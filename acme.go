package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// TLSSettings 是后台自身 HTTPS 证书（通过 acme.sh 申请）的配置。
type TLSSettings struct {
	Domain      string            `json:"domain"`
	Email       string            `json:"email"`
	CA          string            `json:"ca"`           // letsencrypt / zerossl / letsencrypt_test
	Mode        string            `json:"mode"`         // http（80 端口验证）/ dns（DNS API 验证）
	DNSProvider string            `json:"dns_provider"` // acme.sh 的 dnsapi 名称，例如 dns_ali
	DNSEnv      map[string]string `json:"dns_env"`      // DNS API 凭据（环境变量）
	Redirect    bool              `json:"redirect"`     // 证书可用时把 HTTP 访问跳转到 HTTPS
	AcmeBaseURL string            `json:"acme_base_url"`
}

const defaultAcmeBaseURL = "https://raw.githubusercontent.com/acmesh-official/acme.sh/3.1.1"

var (
	domainRe      = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
	dnsProviderRe = regexp.MustCompile(`^dns_[a-z0-9_]+$`)
	envKeyRe      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	acmeCAs       = map[string]bool{"letsencrypt": true, "zerossl": true, "letsencrypt_test": true}
)

// ---------- 证书加载 ----------

type certInfo struct {
	Loaded   bool      `json:"loaded"`
	Domains  []string  `json:"domains"`
	Issuer   string    `json:"issuer"`
	NotAfter time.Time `json:"not_after"`
	Valid    bool      `json:"valid"`
}

// certManager 从数据目录加载证书，申请 / 续期后热更新，无需重启。
type certManager struct {
	dir  string
	mu   sync.RWMutex
	cert *tls.Certificate
	leaf *x509.Certificate
}

func (m *certManager) certFile() string { return filepath.Join(m.dir, "fullchain.pem") }
func (m *certManager) keyFile() string  { return filepath.Join(m.dir, "key.pem") }

func (m *certManager) load() error {
	cert, err := tls.LoadX509KeyPair(m.certFile(), m.keyFile())
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.cert, m.leaf = &cert, leaf
	m.mu.Unlock()
	return nil
}

func (m *certManager) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cert == nil {
		return nil, errors.New("尚未配置证书")
	}
	return m.cert, nil
}

func (m *certManager) info() certInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.leaf == nil {
		return certInfo{Domains: []string{}}
	}
	return certInfo{
		Loaded: true, Domains: m.leaf.DNSNames, Issuer: m.leaf.Issuer.CommonName,
		NotAfter: m.leaf.NotAfter, Valid: time.Now().Before(m.leaf.NotAfter),
	}
}

// covers 返回当前证书是否有效且包含该域名。
func (m *certManager) covers(domain string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.leaf != nil && time.Now().Before(m.leaf.NotAfter) && m.leaf.VerifyHostname(domain) == nil
}

// ---------- acme.sh ----------

func (a *App) acmeHome() string { return filepath.Join(a.dataDir, "acme") }

func fetchFile(url, dst string, mode os.FileMode) error {
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if !strings.HasPrefix(string(b), "#!") {
		return errors.New("下载到的内容不是脚本")
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	return os.WriteFile(dst, b, mode)
}

// ensureAcme 确保 acme.sh（以及 DNS 模式所需的 dnsapi 脚本）已下载到数据目录。
func (a *App) ensureAcme(t *Task, cfg TLSSettings) (string, error) {
	for _, bin := range []string{"curl", "openssl"} {
		if _, err := exec.LookPath(bin); err != nil {
			return "", fmt.Errorf("后台所在机器缺少 %s，acme.sh 无法运行，请先安装", bin)
		}
	}
	base := strings.TrimRight(cfg.AcmeBaseURL, "/")
	if base == "" {
		base = defaultAcmeBaseURL
	}
	files := []string{"acme.sh"}
	if cfg.Mode == "dns" {
		files = append(files, "dnsapi/"+cfg.DNSProvider+".sh")
	}
	for _, f := range files {
		dst := filepath.Join(a.acmeHome(), f)
		if _, err := os.Stat(dst); err == nil {
			continue
		}
		t.logf("下载 %s/%s", base, f)
		if err := fetchFile(base+"/"+f, dst, 0o700); err != nil {
			return "", fmt.Errorf("下载 %s 失败: %w（可在「acme.sh 下载地址」中更换镜像，或手动放到 %s）", f, err, dst)
		}
	}
	return filepath.Join(a.acmeHome(), "acme.sh"), nil
}

func (a *App) runAcme(t *Task, script string, env map[string]string, args ...string) (int, error) {
	home := a.acmeHome()
	args = append([]string{script, "--home", home, "--config-home", filepath.Join(home, "config"),
		"--cert-home", filepath.Join(home, "certs")}, args...)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", args...)
	cmd.Env = append(os.Environ(), "HOME="+home, "LE_WORKING_DIR="+home)
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Stdout, cmd.Stderr = t, t
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), err
	}
	if err != nil {
		return -1, err
	}
	return 0, nil
}

// issueCert 用 acme.sh 申请（或续期）后台域名的证书，并让 HTTPS 监听立即使用新证书。
func (a *App) issueCert(t *Task, force bool) error {
	a.acmeMu.Lock()
	defer a.acmeMu.Unlock()

	var cfg TLSSettings
	a.store.View(func(db *DB) { cfg = db.Settings.TLS })
	if cfg.Domain == "" {
		return errors.New("请先在「设置」中填写并保存域名")
	}
	script, err := a.ensureAcme(t, cfg)
	if err != nil {
		return err
	}
	ca := cfg.CA
	if ca == "" {
		ca = "letsencrypt"
	}
	args := []string{"--issue", "-d", cfg.Domain, "--server", ca, "--keylength", "ec-256"}
	if cfg.Email != "" {
		args = append(args, "--accountemail", cfg.Email)
	}
	if force {
		args = append(args, "--force")
	}

	var env map[string]string
	if cfg.Mode == "dns" {
		t.logf("使用 DNS 验证（%s）为 %s 申请证书", cfg.DNSProvider, cfg.Domain)
		args = append(args, "--dns", cfg.DNSProvider)
		env = cfg.DNSEnv
	} else {
		// HTTP 验证：临时监听 80 端口，只提供 acme.sh 写入的验证文件。
		webroot := filepath.Join(a.acmeHome(), "webroot")
		if err := os.MkdirAll(filepath.Join(webroot, ".well-known", "acme-challenge"), 0o755); err != nil {
			return err
		}
		ln, err := net.Listen("tcp", ":80")
		if err != nil {
			return fmt.Errorf("HTTP 验证需要临时监听 80 端口，但失败了: %w（端口被占用或被封时请改用 DNS 验证）", err)
		}
		mux := http.NewServeMux()
		mux.Handle("/.well-known/acme-challenge/", http.FileServer(http.Dir(webroot)))
		srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		go srv.Serve(ln)
		defer srv.Close()
		t.logf("使用 HTTP 验证（80 端口）为 %s 申请证书", cfg.Domain)
		args = append(args, "-w", webroot)
	}

	// 退出码 2 表示证书尚未到续期时间，acme.sh 跳过了签发，直接安装已有证书即可。
	if code, err := a.runAcme(t, script, env, args...); err != nil && code != 2 {
		return fmt.Errorf("acme.sh 申请证书失败: %w", err)
	}
	if err := os.MkdirAll(a.certs.dir, 0o700); err != nil {
		return err
	}
	if _, err := a.runAcme(t, script, nil, "--install-cert", "-d", cfg.Domain, "--ecc",
		"--fullchain-file", a.certs.certFile(), "--key-file", a.certs.keyFile()); err != nil {
		return fmt.Errorf("安装证书失败: %w", err)
	}
	_ = os.Chmod(a.certs.keyFile(), 0o600)
	if err := a.certs.load(); err != nil {
		return fmt.Errorf("加载新证书失败: %w", err)
	}
	info := a.certs.info()
	t.logf("证书已生效，有效期至 %s；访问地址 https://%s:%s", info.NotAfter.Local().Format("2006-01-02"), cfg.Domain, a.httpsPort)
	return nil
}

// renewLoop 每 12 小时检查一次，证书剩余不足 30 天时自动续期。
func (a *App) renewLoop() {
	for {
		time.Sleep(12 * time.Hour)
		info := a.certs.info()
		var domain string
		a.store.View(func(db *DB) { domain = db.Settings.TLS.Domain })
		if !info.Loaded || domain == "" || time.Until(info.NotAfter) > 30*24*time.Hour {
			continue
		}
		log.Printf("证书将于 %s 到期，开始自动续期", info.NotAfter.Format("2006-01-02"))
		a.tasks.Start("自动续期证书："+domain, func(t *Task) error { return a.issueCert(t, true) })
	}
}

// redirectHTTPS 包装明文 HTTP 入口：开启跳转且证书可用时，把请求跳到 HTTPS。
func (a *App) redirectHTTPS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var cfg TLSSettings
		a.store.View(func(db *DB) { cfg = db.Settings.TLS })
		if cfg.Redirect && cfg.Domain != "" && a.httpsPort != "" && a.certs.covers(cfg.Domain) {
			http.Redirect(w, r, "https://"+net.JoinHostPort(cfg.Domain, a.httpsPort)+r.URL.RequestURI(), http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---------- 接口 ----------

type tlsView struct {
	TLSSettings
	DNSEnvKeys []string `json:"dns_env_keys"`
	HTTPSPort  string   `json:"https_port"`
	Cert       certInfo `json:"cert"`
}

func (a *App) tlsState(cfg TLSSettings) tlsView {
	keys := []string{}
	for k := range cfg.DNSEnv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	cfg.DNSEnv = nil // 凭据不回传
	if cfg.AcmeBaseURL == "" {
		cfg.AcmeBaseURL = defaultAcmeBaseURL
	}
	return tlsView{TLSSettings: cfg, DNSEnvKeys: keys, HTTPSPort: a.httpsPort, Cert: a.certs.info()}
}

func (a *App) saveTLS(w http.ResponseWriter, r *http.Request) (any, error) {
	var in struct {
		TLSSettings
		DNSEnvText string `json:"dns_env_text"` // 每行 KEY=VALUE；留空表示保持不变
	}
	if err := readJSON(r, &in); err != nil {
		return nil, err
	}
	c := in.TLSSettings
	c.Domain = strings.ToLower(strings.TrimSpace(c.Domain))
	c.Email = strings.TrimSpace(c.Email)
	c.DNSProvider = strings.TrimSpace(c.DNSProvider)
	c.AcmeBaseURL = strings.TrimRight(strings.TrimSpace(c.AcmeBaseURL), "/")
	if c.CA == "" {
		c.CA = "letsencrypt"
	}
	if c.Mode == "" {
		c.Mode = "http"
	}
	switch {
	case c.Domain != "" && !domainRe.MatchString(c.Domain):
		return nil, bad("域名格式不正确")
	case c.Email != "" && (!strings.Contains(c.Email, "@") || strings.ContainsAny(c.Email, " \t\r\n")):
		return nil, bad("邮箱格式不正确")
	case !acmeCAs[c.CA]:
		return nil, bad("证书颁发机构不正确")
	case c.CA == "zerossl" && c.Email == "":
		return nil, bad("使用 ZeroSSL 需要填写邮箱")
	case c.Mode != "http" && c.Mode != "dns":
		return nil, bad("验证方式不正确")
	case c.Mode == "dns" && !dnsProviderRe.MatchString(c.DNSProvider):
		return nil, bad("DNS 服务商应为 acme.sh 的 dnsapi 名称，例如 dns_ali、dns_dp、dns_cf")
	case c.AcmeBaseURL != "" && !strings.HasPrefix(c.AcmeBaseURL, "https://") && !strings.HasPrefix(c.AcmeBaseURL, "http://"):
		return nil, bad("acme.sh 下载地址必须以 http(s):// 开头")
	}
	var env map[string]string
	if strings.TrimSpace(in.DNSEnvText) != "" {
		env = map[string]string{}
		for _, line := range strings.Split(in.DNSEnvText, "\n") {
			line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "export "))
			if line == "" {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			k, v = strings.TrimSpace(k), strings.Trim(strings.TrimSpace(v), `"'`)
			if !ok || !envKeyRe.MatchString(k) {
				return nil, bad("DNS API 凭据每行应为 KEY=VALUE：%s", line)
			}
			env[k] = v
		}
	}
	return nil, a.store.Update(func(db *DB) error {
		if env == nil {
			env = db.Settings.TLS.DNSEnv
		}
		c.DNSEnv = env
		if c.Mode == "dns" && len(c.DNSEnv) == 0 {
			return bad("DNS 验证需要填写 DNS API 凭据")
		}
		db.Settings.TLS = c
		return nil
	})
}

func (a *App) tlsIssue(w http.ResponseWriter, r *http.Request) (any, error) {
	var domain string
	a.store.View(func(db *DB) { domain = db.Settings.TLS.Domain })
	if domain == "" {
		return nil, bad("请先填写并保存域名")
	}
	// 当前证书已覆盖该域名时视为续期，强制重新签发。
	force := a.certs.covers(domain)
	t := a.tasks.Start("申请证书："+domain, func(t *Task) error { return a.issueCert(t, force) })
	return obj{"task_id": t.ID}, nil
}
