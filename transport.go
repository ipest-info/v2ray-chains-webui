package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// 线路的传输方式：
//
//	tcp    VMess 直接跑在 TCP 上（默认）
//	ws     VMess over WebSocket
//	wstls  VMess over WebSocket + TLS
//
// wstls 时，面向用户的入口使用入口节点上配置的域名和正式证书；
// 节点之间的互联同样走 WebSocket + TLS，但使用后台为该线路生成的自签证书（不校验证书，
// 身份认证和加密仍由 VMess 负责，这一层 TLS 只用来让流量看起来像普通 HTTPS）。

func (c *Chain) transport() string {
	if c.Transport == "ws" || c.Transport == "wstls" {
		return c.Transport
	}
	return "tcp"
}

func pemLines(p string) []string {
	out := []string{}
	for _, l := range strings.Split(p, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// inboundStream 返回线路在某节点上入站的传输设置。entry 表示这是面向用户的入口。
func inboundStream(c *Chain, node *Node, entry bool) obj {
	switch c.transport() {
	case "ws":
		return obj{"network": "ws", "wsSettings": obj{"path": c.WSPath}}
	case "wstls":
		cert, key := c.RelayCert, c.RelayKey
		if entry {
			cert, key = node.TLSCert, node.TLSKey
		}
		return obj{
			"network": "ws", "security": "tls",
			"wsSettings":  obj{"path": c.WSPath},
			"tlsSettings": obj{"certificates": []any{obj{"certificate": pemLines(cert), "key": pemLines(key)}}},
		}
	}
	return obj{"network": "tcp"}
}

// outboundStream 返回节点连接下一跳时的传输设置。
func outboundStream(c *Chain) obj {
	switch c.transport() {
	case "ws":
		return obj{"network": "ws", "wsSettings": obj{"path": c.WSPath}}
	case "wstls":
		return obj{
			"network": "ws", "security": "tls",
			"wsSettings":  obj{"path": c.WSPath},
			"tlsSettings": obj{"allowInsecure": true, "serverName": "relay-" + c.ID + ".internal"},
		}
	}
	return obj{"network": "tcp"}
}

// selfSignedCert 生成节点互联用的自签证书（ECDSA P-256，有效期 10 年）。
func selfSignedCert(name string) (certPEM, keyPEM string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})), nil
}

// certLeaf 校验证书和私钥是否匹配，返回叶子证书。
func certLeaf(certPEM, keyPEM string) (*x509.Certificate, error) {
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(pair.Certificate[0])
}

// nodeCertOK 返回节点是否有一张覆盖其域名且未过期的证书。
func nodeCertOK(n *Node) bool {
	if n.TLSDomain == "" || n.TLSCert == "" || n.TLSKey == "" {
		return false
	}
	leaf, err := certLeaf(n.TLSCert, n.TLSKey)
	return err == nil && time.Now().Before(leaf.NotAfter) && leaf.VerifyHostname(n.TLSDomain) == nil
}

// wstlsEntryChain 返回把该节点作为 WebSocket + TLS 入口的线路（没有则为 nil）。
func wstlsEntryChain(db *DB, nodeID string) *Chain {
	for _, c := range db.Chains {
		if c.transport() == "wstls" && len(c.Hops) > 0 && c.Hops[0].NodeID == nodeID {
			return c
		}
	}
	return nil
}

// maskSecrets 把配置里的 TLS 私钥替换掉，用于页面预览。
func maskSecrets(cfg obj) {
	ins, _ := cfg["inbounds"].([]any)
	for _, in := range ins {
		m, _ := in.(obj)
		ss, _ := m["streamSettings"].(obj)
		ts, _ := ss["tlsSettings"].(obj)
		certs, _ := ts["certificates"].([]any)
		for _, c := range certs {
			if cm, ok := c.(obj); ok && cm["key"] != nil {
				cm["key"] = []string{"（私钥已隐藏）"}
			}
		}
	}
}

// issueNodeCert 用 acme.sh（DNS 验证）为节点的域名申请证书，保存到节点记录并同步到节点。
// 节点的域名解析到节点自己，后台无法替它完成 HTTP 验证，所以只支持 DNS 验证。
func (a *App) issueNodeCert(t *Task, nodeID string, force bool) error {
	a.acmeMu.Lock()
	var cfg TLSSettings
	var domain string
	a.store.View(func(db *DB) {
		cfg = db.Settings.TLS
		if n := db.node(nodeID); n != nil {
			domain = n.TLSDomain
		}
	})
	err := func() error {
		if domain == "" {
			return errors.New("请先在节点上填写 TLS 域名")
		}
		if cfg.Mode != "dns" || cfg.DNSProvider == "" || len(cfg.DNSEnv) == 0 {
			return errors.New("为节点申请证书需要 DNS 验证：请先在「设置 → 后台域名与 HTTPS 证书」里把验证方式选为 DNS 并填写 DNS API 凭据（域名一栏可以留空）；或者在节点上手动粘贴证书")
		}
		dir := filepath.Join(a.dataDir, "tls", "nodes")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		certFile, keyFile := filepath.Join(dir, nodeID+".crt"), filepath.Join(dir, nodeID+".key")
		if err := a.acmeObtain(t, cfg, domain, force, certFile, keyFile); err != nil {
			return err
		}
		cert, err1 := os.ReadFile(certFile)
		key, err2 := os.ReadFile(keyFile)
		if err := errors.Join(err1, err2); err != nil {
			return err
		}
		leaf, err := certLeaf(string(cert), string(key))
		if err != nil {
			return fmt.Errorf("申请到的证书无法解析: %w", err)
		}
		t.logf("证书已签发，有效期至 %s", leaf.NotAfter.Local().Format("2006-01-02"))
		return a.store.Update(func(db *DB) error {
			n := db.node(nodeID)
			if n == nil || n.TLSDomain != domain {
				return errors.New("申请期间节点或域名已变更，请重试")
			}
			n.TLSCert, n.TLSKey, n.TLSAuto = string(cert), string(key), true
			return nil
		})
	}()
	a.acmeMu.Unlock()
	if err != nil {
		return err
	}
	// 证书写在 v2ray 配置里，已在使用该证书的节点需要同步才会换上新证书。
	if wstlsEntryChain(a.store.Snapshot(), nodeID) != nil {
		return a.applyNode(t, nodeID)
	}
	return nil
}

func (a *App) nodeCert(w http.ResponseWriter, r *http.Request) (any, error) {
	id := r.PathValue("id")
	var name, domain string
	var has bool
	a.store.View(func(db *DB) {
		if n := db.node(id); n != nil {
			name, domain, has = n.Name, n.TLSDomain, nodeCertOK(n)
		}
	})
	if name == "" {
		return nil, errNotFound
	}
	if domain == "" {
		return nil, bad("请先在节点上填写 TLS 域名")
	}
	t := a.tasks.Start("申请节点证书：「"+name+"」"+domain, func(t *Task) error { return a.issueNodeCert(t, id, has) })
	return obj{"task_id": t.ID}, nil
}
