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

// 用户级出口：dave 指定走 socks 出口，alice 跟随线路默认（末端直连）。
func TestPerUserExit(t *testing.T) {
	db := testDB()
	db.Exits = []*Exit{{ID: "e1", Name: "住宅代理", Protocol: "socks", Address: "9.9.9.9", Port: 1080, Username: "u", Password: "p"}}
	db.Users = append(db.Users, &User{ID: "u4", Name: "dave", UUID: "dave-uuid", Enabled: true, ExitID: "e1"})
	exitRelay, exitEmail := relayID(db.Chains[0], "e1")

	rulesOf := func(node string) []any {
		cfg, _ := buildConfig(db, node)
		return cfg["routing"].(obj)["rules"].([]any)
	}
	find := func(rules []any, user string) string {
		for _, r := range rules {
			r := r.(obj)
			us, _ := r["user"].([]string)
			if (user == "" && us == nil && r["ip"] == nil) || (len(us) == 1 && us[0] == user) {
				return r["outboundTag"].(string)
			}
		}
		return ""
	}

	// 入口：dave 走带出口标记的出站，其余用户走默认出站。
	gz := rulesOf("gz")
	if find(gz, "dave") != "out-c1-e1" || find(gz, "") != "out-c1" {
		t.Errorf("入口规则不正确: %v", gz)
	}
	gzJSON, _ := configJSON(db, "gz")
	if !strings.Contains(gzJSON, exitRelay) || !strings.Contains(gzJSON, "relay-uuid") {
		t.Errorf("入口应同时带有两种互联凭据:\n%s", gzJSON)
	}

	// 中转：按互联凭据分流。
	hk := rulesOf("hk")
	if find(hk, exitEmail) != "out-c1-e1" || find(hk, "") != "out-c1" {
		t.Errorf("中转规则不正确: %v", hk)
	}

	// 出口：带标记的走 socks 代理，其余直连。
	sg := rulesOf("sg")
	if find(sg, exitEmail) != "exit-e1" || find(sg, "") != "direct" {
		t.Errorf("出口规则不正确: %v", sg)
	}
	sgJSON, _ := configJSON(db, "sg")
	if !strings.Contains(sgJSON, `"protocol": "socks"`) || !strings.Contains(sgJSON, `"address": "9.9.9.9"`) {
		t.Errorf("出口节点缺少 socks 出站:\n%s", sgJSON)
	}

	// 线路默认出口改为代理、alice 强制直连：两者对调。
	db.Chains[0].ExitID = "e1"
	db.Users[3].ExitID = ""
	db.Users[0].ExitID = exitDirect
	sg = rulesOf("sg")
	if find(sg, "relay@c1") != "direct" || find(sg, "") != "exit-e1" {
		t.Errorf("默认出口为代理时规则不正确: %v", sg)
	}
}

func TestNodeConf(t *testing.T) {
	db := testDB()
	db.node("sg").Conf = NodeConf{
		LogLevel: "info", DNS: []string{"8.8.8.8"}, Sniffing: true, AllowPrivate: true,
		Extra: `{"policy":{"levels":{"0":{"connIdle":120}}},
			"inbounds":[{"tag":"x-in","port":1234,"protocol":"socks"}],
			"routing":{"rules":[{"type":"field","inboundTag":["x-in"],"outboundTag":"direct"}]}}`,
	}
	cfg, _ := buildConfig(db, "sg")
	s, _ := configJSON(db, "sg")
	if cfg["log"].(obj)["loglevel"] != "info" || cfg["dns"] == nil || cfg["policy"] == nil {
		t.Errorf("配置项未生效:\n%s", s)
	}
	if strings.Contains(s, "geoip:private") || !strings.Contains(s, "destOverride") {
		t.Errorf("AllowPrivate / Sniffing 未生效:\n%s", s)
	}
	if n := len(cfg["inbounds"].([]any)); n != 2 {
		t.Errorf("自定义入站应追加在后面，共 %d 个", n)
	}
	rules := cfg["routing"].(obj)["rules"].([]any)
	if tags := rules[0].(obj)["inboundTag"].([]any); tags[0] != "x-in" {
		t.Errorf("自定义路由规则应排在最前: %v", rules)
	}
	if _, err := parseExtra(`{"inbounds":{}}`); err == nil {
		t.Error("inbounds 不是数组时应报错")
	}
	if _, err := parseExtra(`[1]`); err == nil {
		t.Error("不是对象时应报错")
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

func TestParseExitLine(t *testing.T) {
	ok := []struct {
		line, def      string
		proto, addr    string
		port           int
		user, pw, name string
	}{
		{"socks5://u:p@1.2.3.4:1080#美国01", "http", "socks", "1.2.3.4", 1080, "u", "p", "美国01"},
		{"http://proxy.example.com:8080/", "socks", "http", "proxy.example.com", 8080, "", "", "proxy.example.com:8080"},
		{"1.2.3.4:1080:user:pa:ss", "socks", "socks", "1.2.3.4", 1080, "user", "pa:ss", "1.2.3.4:1080"},
		{"user:p@ss@1.2.3.4:3128 日本 02", "http", "http", "1.2.3.4", 3128, "user", "p@ss", "日本 02"},
		{"1.2.3.4:1080", "socks", "socks", "1.2.3.4", 1080, "", "", "1.2.3.4:1080"},
	}
	for _, c := range ok {
		e, err := parseExitLine(c.line, c.def)
		if err != nil {
			t.Errorf("%q: %v", c.line, err)
			continue
		}
		if e.Protocol != c.proto || e.Address != c.addr || e.Port != c.port || e.Username != c.user || e.Password != c.pw || e.Name != c.name {
			t.Errorf("%q => %+v", c.line, e)
		}
	}
	for _, line := range []string{"1.2.3.4", "1.2.3.4:abc", "ss://x@1.2.3.4:1", "1.2.3.4:99999", "bad host:1080:u:p", ":p@1.2.3.4:1080"} {
		if e, err := parseExitLine(line, "socks"); err == nil {
			t.Errorf("%q 应当报错，却得到 %+v", line, e)
		}
	}
}

// 出口代理不转发 UDP 时，末端节点上应有单独的 UDP 规则，且排在该出口的普通规则之前。
func TestExitUDPHandling(t *testing.T) {
	db := testDB()
	db.Exits = []*Exit{{ID: "e1", Name: "x", Protocol: "socks", Address: "9.9.9.9", Port: 1080}}
	db.Chains[0].ExitID = "e1"
	udpRule := func() obj {
		cfg, _ := buildConfig(db, "sg")
		rules := cfg["routing"].(obj)["rules"].([]any)
		for i, r := range rules {
			if r.(obj)["network"] == "udp" {
				if next := rules[i+1].(obj); next["outboundTag"] != "exit-e1" {
					t.Errorf("UDP 规则应紧挨在出口规则之前: %v", rules)
				}
				return r.(obj)
			}
		}
		return nil
	}
	if r := udpRule(); r != nil {
		t.Errorf("SOCKS5 未检测时应经代理转发 UDP，不应有单独规则: %v", r)
	}
	db.Exits[0].UDPStatus = "fail"
	if r := udpRule(); r == nil || r["outboundTag"] != "block" {
		t.Errorf("检测为不支持后应丢弃 UDP: %v", r)
	}
	db.Chains[0].UDPFallback = "direct"
	if r := udpRule(); r == nil || r["outboundTag"] != "direct" {
		t.Errorf("线路设为直连时 UDP 应从末端节点出网: %v", r)
	}
	db.Exits[0].UDP = "proxy"
	if r := udpRule(); r != nil {
		t.Errorf("强制经代理时不应有单独规则: %v", r)
	}
	db.Exits[0].UDP, db.Exits[0].UDPStatus = "off", "ok"
	if r := udpRule(); r == nil {
		t.Error("关闭后应有单独规则")
	}
	db.Exits[0].UDP, db.Exits[0].Protocol = "auto", "http"
	if r := udpRule(); r == nil {
		t.Error("HTTP 代理始终不转发 UDP")
	}
}

func TestBandwidthSampling(t *testing.T) {
	c := parseNetDev([]string{
		"Inter-|   Receive                                                |  Transmit",
		" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed",
		"    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0",
		"  eth0: 5000000 100 0 0 0 0 0 0 2000000 50 0 0 0 0 0 0",
	})
	if c["eth0"] != [2]uint64{5000000, 2000000} || c["lo"] != [2]uint64{1000, 1000} || len(c) != 2 {
		t.Fatalf("parseNetDev = %v", c)
	}

	m := newNodeMon("")
	t0 := time.Unix(1_700_000_000, 0)
	m.add(t0, 100, map[string][2]uint64{"eth0": {0, 0}, "lo": {0, 0}})
	if len(m.tiers[0]) != 0 {
		t.Fatal("第一次采样只应记录基准")
	}
	// 5 秒内收 625000 字节 = 1 Mbit/s，发 62500 字节 = 100 kbit/s
	m.add(t0.Add(5*time.Second), 105, map[string][2]uint64{"eth0": {625000, 62500}, "lo": {999, 999}})
	s := m.tiers[0][0]
	if s.R["eth0"].Rx != 1e6 || s.R["eth0"].Tx != 1e5 {
		t.Errorf("速率 = %+v", s.R["eth0"])
	}
	if total := pick(s, ""); total.Rx != 1e6 {
		t.Errorf("合计不应包含 lo: %+v", total)
	}
	// 计数器回绕（节点重启）时跳过该网卡，不产生负值或尖峰
	m.add(t0.Add(10*time.Second), 110, map[string][2]uint64{"eth0": {10, 10}, "lo": {2000, 2000}})
	if _, ok := m.tiers[0][1].R["eth0"]; ok {
		t.Error("计数器变小时不应计算速率")
	}
	// 跨过一分钟后，1 分钟档应得到上一分钟的平均值
	m.add(t0.Add(65*time.Second), 165, map[string][2]uint64{"eth0": {20, 20}, "lo": {3000, 3000}})
	if len(m.tiers[1]) != 1 || m.tiers[1][0].R["eth0"].Rx != 1e6 {
		t.Errorf("1 分钟聚合 = %+v", m.tiers[1])
	}
}
