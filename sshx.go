package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	sshDialTimeout = 12 * time.Second
	maxJumpDepth   = 5
)

// sshConn 是到目标节点的 SSH 连接，可能经过若干跳板。
type sshConn struct {
	*ssh.Client
	closers []io.Closer
	learned map[string]string // 本次连接中首次见到的主机公钥：节点 ID -> 公钥
}

func (c *sshConn) Close() {
	c.Client.Close()
	for i := len(c.closers) - 1; i >= 0; i-- {
		c.closers[i].Close()
	}
}

func shq(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func sshClientConfig(n *Node, learned map[string]string) (*ssh.ClientConfig, error) {
	var auth []ssh.AuthMethod
	if strings.TrimSpace(n.SSHKey) != "" {
		signer, err := ssh.ParsePrivateKey([]byte(n.SSHKey))
		if err != nil {
			return nil, fmt.Errorf("节点「%s」的 SSH 私钥无法解析: %w", n.Name, err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if n.SSHPassword != "" {
		pw := n.SSHPassword
		auth = append(auth, ssh.Password(pw), ssh.KeyboardInteractive(
			func(_, _ string, questions []string, _ []bool) ([]string, error) {
				ans := make([]string, len(questions))
				for i := range ans {
					ans[i] = pw
				}
				return ans, nil
			}))
	}
	if len(auth) == 0 {
		return nil, fmt.Errorf("节点「%s」未配置 SSH 密码或私钥", n.Name)
	}
	return &ssh.ClientConfig{
		User:    n.SSHUser,
		Auth:    auth,
		Timeout: sshDialTimeout,
		// 首次连接信任并记录主机公钥，之后必须一致（TOFU）。
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			got := base64.StdEncoding.EncodeToString(key.Marshal())
			if n.HostKey == "" {
				learned[n.ID] = got
				return nil
			}
			if n.HostKey != got {
				return fmt.Errorf("节点「%s」的 SSH 主机公钥与首次记录的不一致（若服务器已重装，请在页面上「重置主机公钥」）", n.Name)
			}
			return nil
		},
	}, nil
}

// dialNode 连接到节点；若节点配置了跳板，则先连接跳板再从跳板拨号。
func dialNode(db *DB, nodeID string) (*sshConn, error) {
	conn := &sshConn{learned: map[string]string{}}
	client, err := dialPath(db, nodeID, conn, 0)
	if err != nil {
		for i := len(conn.closers) - 1; i >= 0; i-- {
			conn.closers[i].Close()
		}
		return nil, err
	}
	conn.Client = client
	return conn, nil
}

func dialPath(db *DB, nodeID string, conn *sshConn, depth int) (*ssh.Client, error) {
	n := db.node(nodeID)
	if n == nil {
		return nil, errors.New("节点不存在")
	}
	if depth > maxJumpDepth {
		return nil, errors.New("SSH 跳板层级过深或存在循环")
	}
	cfg, err := sshClientConfig(n, conn.learned)
	if err != nil {
		return nil, err
	}
	port := n.SSHPort
	if port == 0 {
		port = 22
	}
	addr := net.JoinHostPort(n.SSHHost, strconv.Itoa(port))

	var raw net.Conn
	if n.JumpNodeID != "" {
		jn := db.node(n.JumpNodeID)
		if jn == nil {
			return nil, fmt.Errorf("节点「%s」的跳板节点不存在", n.Name)
		}
		jc, err := dialPath(db, n.JumpNodeID, conn, depth+1)
		if err != nil {
			return nil, err
		}
		conn.closers = append(conn.closers, jc)
		raw, err = dialVia(jc, addr)
		if err != nil {
			return nil, fmt.Errorf("经跳板「%s」连接「%s」(%s) 失败: %w", jn.Name, n.Name, addr, err)
		}
	} else {
		raw, err = net.DialTimeout("tcp", addr, sshDialTimeout)
		if err != nil {
			return nil, fmt.Errorf("连接「%s」(%s) 失败: %w", n.Name, addr, err)
		}
	}
	_ = raw.SetDeadline(time.Now().Add(sshDialTimeout + 8*time.Second))
	c, chans, reqs, err := ssh.NewClientConn(raw, addr, cfg)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("「%s」SSH 握手 / 认证失败: %w", n.Name, err)
	}
	_ = raw.SetDeadline(time.Time{})
	return ssh.NewClient(c, chans, reqs), nil
}

// dialVia 通过已有 SSH 连接拨号，带超时。
func dialVia(jc *ssh.Client, addr string) (net.Conn, error) {
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := jc.Dial("tcp", addr)
		ch <- res{c, err}
	}()
	select {
	case r := <-ch:
		return r.c, r.err
	case <-time.After(sshDialTimeout):
		go func() {
			if r := <-ch; r.c != nil {
				r.c.Close()
			}
		}()
		return nil, errors.New("连接超时")
	}
}

// runSession 执行一条命令，超时后强制断开。
func runSession(c *ssh.Client, cmd string, stdin io.Reader, out io.Writer, timeout time.Duration) error {
	sess, err := c.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	sess.Stdin = stdin
	sess.Stdout = out
	sess.Stderr = out
	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		sess.Close()
		return fmt.Errorf("执行超时（%s）", timeout)
	}
}

// runOutput 以登录用户身份执行命令并返回输出。
func runOutput(c *ssh.Client, cmd string, timeout time.Duration) (string, error) {
	var buf bytes.Buffer
	err := runSession(c, cmd, nil, &buf, timeout)
	return buf.String(), err
}

// runRootScript 以 root 身份执行一段 bash 脚本。
// 登录用户不是 root 时通过 sudo 提权（优先免密，否则使用 SSH 密码）。
func runRootScript(c *ssh.Client, n *Node, script string, out io.Writer, timeout time.Duration) error {
	if n.SSHUser == "root" {
		return runSession(c, "bash -s", strings.NewReader(script), out, timeout)
	}
	f := "/tmp/vcw-" + randHex(8) + ".sh"
	if err := runSession(c, "umask 077; cat > "+f, strings.NewReader(script), out, 30*time.Second); err != nil {
		return fmt.Errorf("上传脚本失败: %w", err)
	}
	tail := " bash " + f + "; rc=$?; rm -f " + f + "; exit $rc"
	if n.SSHPassword != "" {
		return runSession(c, "sudo -S -p '' "+tail, strings.NewReader(n.SSHPassword+"\n"), out, timeout)
	}
	return runSession(c, "sudo -n "+tail, nil, out, timeout)
}

func exitCode(err error) int {
	var ee *ssh.ExitError
	if errors.As(err, &ee) {
		return ee.ExitStatus()
	}
	return -1
}
