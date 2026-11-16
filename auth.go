package main

import (
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	sessionCookie = "vcw_session"
	sessionTTL    = 12 * time.Hour
	maxLoginFails = 5
	loginLockTime = 10 * time.Minute
)

type loginFail struct {
	count int
	until time.Time
	last  time.Time
}

type Auth struct {
	mu       sync.Mutex
	sessions map[string]time.Time
	fails    map[string]*loginFail
}

func newAuth() *Auth {
	return &Auth{sessions: map[string]time.Time{}, fails: map[string]*loginFail{}}
}

func hashPassword(pw string) string {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	return string(h)
}

func checkPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// locked 返回该 IP 是否因多次登录失败被暂时锁定。
func (a *Auth) locked(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	f := a.fails[ip]
	return f != nil && time.Now().Before(f.until)
}

func (a *Auth) recordFail(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	f := a.fails[ip]
	if f == nil || now.Sub(f.last) > loginLockTime {
		f = &loginFail{}
		a.fails[ip] = f
	}
	f.count++
	f.last = now
	if f.count >= maxLoginFails {
		f.until = now.Add(loginLockTime)
		f.count = 0
	}
}

func (a *Auth) clearFail(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.fails, ip)
}

func (a *Auth) newSession() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	for k, exp := range a.sessions {
		if now.After(exp) {
			delete(a.sessions, k)
		}
	}
	tok := randHex(32)
	a.sessions[tok] = now.Add(sessionTTL)
	return tok
}

func (a *Auth) valid(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	exp, ok := a.sessions[c.Value]
	return ok && time.Now().Before(exp)
}

func (a *Auth) drop(r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		a.mu.Lock()
		delete(a.sessions, c.Value)
		a.mu.Unlock()
	}
}

// dropAll 使所有会话失效（修改密码后调用）。
func (a *Auth) dropAll() {
	a.mu.Lock()
	a.sessions = map[string]time.Time{}
	a.mu.Unlock()
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, tok string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: tok, Path: "/", MaxAge: maxAge,
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
	})
}
