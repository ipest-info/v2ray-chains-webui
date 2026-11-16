package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// ---------- 配置生成 ----------

func testDB() *DB {
	return &DB{
		Nodes: []*Node{
			{ID: "gz", Name: "广州", SSHHost: "1.1.1.1", PublicAddr: "gz.example.com", InternalAddr: "10.0.0.1"},
			{ID: "hk", Name: "香港", SSHHost: "2.2.2.2", PublicAddr: "hk.example.com", InternalAddr: "10.0.0.2"},
			{ID: "sg", Name: "新加坡", SSHHost: "3.3.3.3", PublicAddr: "sg.example.com"},
		},
		Chains: []*Chain{{
			ID: "c1", Name: "广州-香港-新加坡", Port: 20001, RelayUUID: "relay-uuid",
			Hops: []Hop{{"gz", "public"}, {"hk", "internal"}, {"sg", "public"}},
		}},
		Users: []*User{
			{ID: "u1", Name: "alice", UUID: "alice-uuid", Enabled: true},
			{ID: "u2", Name: "bob", UUID: "bob-uuid", Enabled: false},
			{ID: "u3", Name: "carol", UUID: "carol-uuid", Enabled: true, ChainIDs: []string{"other"}},
		},
	}
}

func TestBuildConfigChain(t *testing.T) {
	db := testDB()

	// 入口：只包含启用且有权限的用户，出站指向香港内网地址。
	gz, ports := configJSON(db, "gz")
	if len(ports) != 1 || ports[0] != 20001 {
		t.Fatalf("ports = %v", ports)
	}
	if !strings.Contains(gz, "alice-uuid") || strings.Contains(gz, "bob-uuid") || strings.Contains(gz, "carol-uuid") {
		t.Errorf("入口节点的用户列表不正确:\n%s", gz)
	}
	if !strings.Contains(gz, `"address": "10.0.0.2"`) {
		t.Errorf("广州应经内网地址连接香港:\n%s", gz)
	}

	// 中转：只接受线路凭据，出站指向新加坡公网地址。
	hk, _ := configJSON(db, "hk")
	if strings.Contains(hk, "alice-uuid") || !strings.Contains(hk, "relay-uuid") || !strings.Contains(hk, `"address": "sg.example.com"`) {
		t.Errorf("中转节点配置不正确:\n%s", hk)
	}

	// 出口：没有下一跳，直连并屏蔽内网地址。
	sg, _ := configJSON(db, "sg")
	if strings.Contains(sg, "vnext") || !strings.Contains(sg, "geoip:private") {
		t.Errorf("出口节点配置不正确:\n%s", sg)
	}
}

func TestBuildConfigNoUsers(t *testing.T) {
	db := testDB()
	db.Users = nil
	if _, ports := configJSON(db, "gz"); len(ports) != 0 {
		t.Errorf("没有用户时入口不应开放端口: %v", ports)
	}
	if _, ports := configJSON(db, "hk"); len(ports) != 1 {
		t.Errorf("中转节点仍应监听: %v", ports)
	}
}

func TestVmessLink(t *testing.T) {
	db := testDB()
	link := vmessLink(db, db.Users[0], db.Chains[0])
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(link, "vmess://"))
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]string
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v["add"] != "gz.example.com" || v["port"] != "20001" || v["id"] != "alice-uuid" {
		t.Errorf("link = %v", v)
	}
}

// ---------- SSH 直连 / 跳板 ----------

// testSSHServer 是一个仅用于测试的 SSH 服务器：用本机 bash 执行命令，并支持端口转发（作为跳板）。
type testSSHServer struct {
	host     string
	port     int
	forwards atomic.Int32
}

func startSSHServer(t *testing.T, password string) *testSSHServer {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if string(pw) == password {
				return nil, nil
			}
			return nil, fmt.Errorf("bad password")
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &testSSHServer{host: "127.0.0.1", port: ln.Addr().(*net.TCPAddr).Port}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c, cfg)
		}
	}()
	return s
}

func (s *testSSHServer) serve(c net.Conn, cfg *ssh.ServerConfig) {
	conn, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		c.Close()
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		switch nc.ChannelType() {
		case "session":
			ch, creqs, _ := nc.Accept()
			go func() {
				for req := range creqs {
					if req.Type != "exec" {
						req.Reply(false, nil)
						continue
					}
					var p struct{ Cmd string }
					ssh.Unmarshal(req.Payload, &p)
					req.Reply(true, nil)
					cmd := exec.Command("bash", "-c", p.Cmd)
					cmd.Stdin, cmd.Stdout, cmd.Stderr = ch, ch, ch.Stderr()
					code := 0
					if err := cmd.Run(); err != nil {
						code = 1
						if ee, ok := err.(*exec.ExitError); ok {
							code = ee.ExitCode()
						}
					}
					ch.SendRequest("exit-status", false, ssh.Marshal(struct{ C uint32 }{uint32(code)}))
					ch.Close()
				}
			}()
		case "direct-tcpip":
			var p struct {
				Host  string
				Port  uint32
				OHost string
				OPort uint32
			}
			ssh.Unmarshal(nc.ExtraData(), &p)
			up, err := net.Dial("tcp", net.JoinHostPort(p.Host, strconv.Itoa(int(p.Port))))
			if err != nil {
				nc.Reject(ssh.ConnectionFailed, err.Error())
				continue
			}
			s.forwards.Add(1)
			ch, creqs, _ := nc.Accept()
			go ssh.DiscardRequests(creqs)
			go func() { io.Copy(up, ch); up.Close() }()
			go func() { io.Copy(ch, up); ch.Close() }()
		default:
			nc.Reject(ssh.UnknownChannelType, "unsupported")
		}
	}
}

func TestSSHDirectAndJump(t *testing.T) {
	b := startSSHServer(t, "pw-b")
	c := startSSHServer(t, "pw-c")
	db := &DB{Nodes: []*Node{
		{ID: "b", Name: "B", SSHHost: b.host, SSHPort: b.port, SSHUser: "root", SSHPassword: "pw-b"},
		{ID: "c", Name: "C", SSHHost: c.host, SSHPort: c.port, SSHUser: "root", SSHPassword: "pw-c", JumpNodeID: "b"},
	}}

	conn, err := dialNode(db, "c")
	if err != nil {
		t.Fatalf("经跳板连接失败: %v", err)
	}
	defer conn.Close()
	if b.forwards.Load() != 1 {
		t.Errorf("到 C 的连接应当经由 B 转发，forwards = %d", b.forwards.Load())
	}
	if conn.learned["b"] == "" || conn.learned["c"] == "" {
		t.Errorf("应记录两个节点的主机公钥: %v", conn.learned)
	}

	out, err := runOutput(conn.Client, "echo hello-$((1+1))", 10*time.Second)
	if err != nil || strings.TrimSpace(out) != "hello-2" {
		t.Errorf("out = %q, err = %v", out, err)
	}
	var buf bytes.Buffer
	if err := runRootScript(conn.Client, db.node("c"), "echo script-ok\nexit 42\n", &buf, 10*time.Second); exitCode(err) != 42 {
		t.Errorf("退出码应为 42: %v", err)
	}
	if !strings.Contains(buf.String(), "script-ok") {
		t.Errorf("脚本输出 = %q", buf.String())
	}

	// 主机公钥变化后必须拒绝连接。
	db.node("c").HostKey = conn.learned["b"]
	if _, err := dialNode(db, "c"); err == nil || !strings.Contains(err.Error(), "主机公钥") {
		t.Errorf("主机公钥不一致时应报错: %v", err)
	}

	// 密码错误。
	db.node("b").SSHPassword = "wrong"
	if _, err := dialNode(db, "b"); err == nil {
		t.Error("密码错误时应连接失败")
	}
}

func TestJumpLoopRejected(t *testing.T) {
	db := &DB{Nodes: []*Node{
		{ID: "a", Name: "A", SSHHost: "127.0.0.1", SSHPort: 1, SSHUser: "root", SSHPassword: "x", JumpNodeID: "b"},
		{ID: "b", Name: "B", SSHHost: "127.0.0.1", SSHPort: 1, SSHUser: "root", SSHPassword: "x", JumpNodeID: "a"},
	}}
	if _, err := dialNode(db, "a"); err == nil {
		t.Error("循环跳板应报错")
	}
}
