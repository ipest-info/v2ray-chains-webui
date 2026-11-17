package main

import (
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"regexp"
	"strings"
	"time"
)

//go:embed web
var webFS embed.FS

type App struct {
	store *Store
	auth  *Auth
	tasks *Tasks
}

type apiError struct {
	code int
	msg  string
}

func (e *apiError) Error() string { return e.msg }

func bad(format string, a ...any) error {
	return &apiError{http.StatusBadRequest, fmt.Sprintf(format, a...)}
}

var errNotFound = &apiError{http.StatusNotFound, "对象不存在"}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	var ae *apiError
	if errors.As(err, &ae) {
		writeJSON(w, ae.code, obj{"error": ae.msg})
		return
	}
	writeJSON(w, http.StatusInternalServerError, obj{"error": err.Error()})
}

func readJSON(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		return bad("请求格式错误")
	}
	return nil
}

type handler func(w http.ResponseWriter, r *http.Request) (any, error)

// api 包装需要登录的接口。
func (a *App) api(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.auth.valid(r) {
			writeJSON(w, http.StatusUnauthorized, obj{"error": "未登录"})
			return
		}
		// 写操作必须是 JSON 请求，配合 SameSite=Strict Cookie 防止跨站请求伪造。
		if r.Method != http.MethodGet && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			writeJSON(w, http.StatusUnsupportedMediaType, obj{"error": "需要 application/json"})
			return
		}
		v, err := h(w, r)
		if err != nil {
			writeErr(w, err)
			return
		}
		if v == nil {
			v = obj{"ok": true}
		}
		writeJSON(w, http.StatusOK, v)
	}
}

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(webFS, "web")
	mux.Handle("GET /", http.FileServer(http.FS(sub)))

	mux.HandleFunc("POST /api/login", a.login)
	mux.HandleFunc("POST /api/logout", a.logout)
	mux.HandleFunc("GET /sub/{token}", a.subscription)

	mux.HandleFunc("GET /api/state", a.api(a.state))
	mux.HandleFunc("POST /api/password", a.api(a.changePassword))
	mux.HandleFunc("PUT /api/settings", a.api(a.saveSettings))

	mux.HandleFunc("POST /api/nodes", a.api(a.saveNode))
	mux.HandleFunc("PUT /api/nodes/{id}", a.api(a.saveNode))
	mux.HandleFunc("DELETE /api/nodes/{id}", a.api(a.deleteNode))
	mux.HandleFunc("POST /api/nodes/{id}/check", a.api(a.nodeCheck))
	mux.HandleFunc("POST /api/nodes/{id}/install", a.api(a.nodeInstall))
	mux.HandleFunc("POST /api/nodes/{id}/apply", a.api(a.nodeApply))
	mux.HandleFunc("POST /api/nodes/{id}/reset-hostkey", a.api(a.nodeResetHostKey))
	mux.HandleFunc("GET /api/nodes/{id}/config", a.api(a.nodeConfig))
	mux.HandleFunc("POST /api/apply-all", a.api(a.applyAll))
	mux.HandleFunc("PUT /api/nodes/{id}/conf", a.api(a.saveNodeConf))
	mux.HandleFunc("GET /api/nodes/{id}/backups", a.api(a.backupList))
	mux.HandleFunc("POST /api/nodes/{id}/backups", a.api(a.backupCreate))
	mux.HandleFunc("GET /api/nodes/{id}/backups/{name}", a.api(a.backupGet))
	mux.HandleFunc("POST /api/nodes/{id}/backups/{name}/restore", a.api(a.backupRestore))

	mux.HandleFunc("POST /api/exits", a.api(a.saveExit))
	mux.HandleFunc("PUT /api/exits/{id}", a.api(a.saveExit))
	mux.HandleFunc("DELETE /api/exits/{id}", a.api(a.deleteExit))

	mux.HandleFunc("POST /api/chains", a.api(a.saveChain))
	mux.HandleFunc("PUT /api/chains/{id}", a.api(a.saveChain))
	mux.HandleFunc("DELETE /api/chains/{id}", a.api(a.deleteChain))
	mux.HandleFunc("POST /api/chains/{id}/test", a.api(a.chainTest))

	mux.HandleFunc("POST /api/users", a.api(a.saveUser))
	mux.HandleFunc("PUT /api/users/{id}", a.api(a.saveUser))
	mux.HandleFunc("DELETE /api/users/{id}", a.api(a.deleteUser))
	mux.HandleFunc("POST /api/users/{id}/reset", a.api(a.resetUser))

	mux.HandleFunc("GET /api/tasks/{id}", a.api(a.taskGet))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		mux.ServeHTTP(w, r)
	})
}

// ---------- 登录 ----------

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if a.auth.locked(ip) {
		writeJSON(w, http.StatusTooManyRequests, obj{"error": "登录失败次数过多，请 10 分钟后再试"})
		return
	}
	var in struct{ Username, Password string }
	if err := readJSON(r, &in); err != nil {
		writeErr(w, err)
		return
	}
	var admin Admin
	a.store.View(func(db *DB) { admin = db.Admin })
	okPw := checkPassword(admin.PasswordHash, in.Password) // 始终校验，避免用户名探测
	if in.Username != admin.Username || !okPw {
		a.auth.recordFail(ip)
		time.Sleep(500 * time.Millisecond)
		writeJSON(w, http.StatusUnauthorized, obj{"error": "用户名或密码错误"})
		return
	}
	a.auth.clearFail(ip)
	setSessionCookie(w, r, a.auth.newSession(), int(sessionTTL.Seconds()))
	writeJSON(w, http.StatusOK, obj{"ok": true})
}

func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	a.auth.drop(r)
	setSessionCookie(w, r, "", -1)
	writeJSON(w, http.StatusOK, obj{"ok": true})
}

func (a *App) changePassword(w http.ResponseWriter, r *http.Request) (any, error) {
	var in struct {
		Old      string `json:"old"`
		Username string `json:"username"`
		New      string `json:"new"`
	}
	if err := readJSON(r, &in); err != nil {
		return nil, err
	}
	in.Username = strings.TrimSpace(in.Username)
	if len(in.New) < 8 {
		return nil, bad("新密码至少 8 位")
	}
	err := a.store.Update(func(db *DB) error {
		if !checkPassword(db.Admin.PasswordHash, in.Old) {
			return bad("当前密码不正确")
		}
		if in.Username != "" {
			db.Admin.Username = in.Username
		}
		db.Admin.PasswordHash = hashPassword(in.New)
		return nil
	})
	if err != nil {
		return nil, err
	}
	a.auth.dropAll()
	return nil, nil
}

func (a *App) saveSettings(w http.ResponseWriter, r *http.Request) (any, error) {
	var in Settings
	if err := readJSON(r, &in); err != nil {
		return nil, err
	}
	in.DownloadURL = strings.TrimSpace(in.DownloadURL)
	if in.DownloadURL == "" {
		in.DownloadURL = defaultDownloadURL
	}
	if !strings.HasPrefix(in.DownloadURL, "https://") && !strings.HasPrefix(in.DownloadURL, "http://") {
		return nil, bad("下载地址必须以 http(s):// 开头")
	}
	return nil, a.store.Update(func(db *DB) error { db.Settings = in; return nil })
}

// ---------- 总览 ----------

type nodeView struct {
	Node
	HasPassword bool `json:"has_password"`
	HasKey      bool `json:"has_key"`
	HasHostKey  bool `json:"has_host_key"`
	Dirty       bool `json:"dirty"`
}

type exitView struct {
	Exit
	HasPassword bool `json:"has_password"`
}

type userView struct {
	User
	Links []obj `json:"links"`
}

func (a *App) state(w http.ResponseWriter, r *http.Request) (any, error) {
	db := a.store.Snapshot()
	nodes := make([]nodeView, 0, len(db.Nodes))
	for _, n := range db.Nodes {
		cfg, ports := configJSON(db, n.ID)
		v := nodeView{Node: *n, HasPassword: n.SSHPassword != "", HasKey: n.SSHKey != "", HasHostKey: n.HostKey != ""}
		v.Dirty = n.AppliedHash != configHash(cfg) && (n.AppliedHash != "" || len(ports) > 0)
		v.SSHPassword, v.SSHKey, v.HostKey = "", "", ""
		nodes = append(nodes, v)
	}
	users := make([]userView, 0, len(db.Users))
	for _, u := range db.Users {
		v := userView{User: *u, Links: []obj{}}
		for _, c := range db.Chains {
			if userAllowed(u, c.ID) {
				exit := "末端节点直连"
				if e := db.exit(userExit(db, u, c)); e != nil {
					exit = e.Name
				}
				v.Links = append(v.Links, obj{"chain_id": c.ID, "name": chainPath(db, c), "exit": exit, "link": vmessLink(db, u, c)})
			}
		}
		users = append(users, v)
	}
	if db.Chains == nil {
		db.Chains = []*Chain{}
	}
	exits := make([]exitView, 0, len(db.Exits))
	for _, e := range db.Exits {
		v := exitView{Exit: *e, HasPassword: e.Password != ""}
		v.Password = ""
		exits = append(exits, v)
	}
	return obj{
		"admin":    db.Admin.Username,
		"settings": db.Settings,
		"nodes":    nodes,
		"chains":   db.Chains,
		"exits":    exits,
		"users":    users,
		"tasks":    a.tasks.List(),
	}, nil
}

// ---------- 节点 ----------

var addrRe = regexp.MustCompile(`^[A-Za-z0-9._:\-]+$`)
var userRe = regexp.MustCompile(`^[A-Za-z0-9._\-]+$`)

type nodeInput struct {
	Name         string `json:"name"`
	SSHHost      string `json:"ssh_host"`
	SSHPort      int    `json:"ssh_port"`
	SSHUser      string `json:"ssh_user"`
	SSHPassword  string `json:"ssh_password"`
	SSHKey       string `json:"ssh_key"`
	ClearKey     bool   `json:"clear_key"`
	JumpNodeID   string `json:"jump_node_id"`
	PublicAddr   string `json:"public_addr"`
	InternalAddr string `json:"internal_addr"`
}

func (a *App) saveNode(w http.ResponseWriter, r *http.Request) (any, error) {
	id := r.PathValue("id")
	var in nodeInput
	if err := readJSON(r, &in); err != nil {
		return nil, err
	}
	in.Name = strings.TrimSpace(in.Name)
	in.SSHHost = strings.TrimSpace(in.SSHHost)
	in.SSHUser = strings.TrimSpace(in.SSHUser)
	in.PublicAddr = strings.TrimSpace(in.PublicAddr)
	in.InternalAddr = strings.TrimSpace(in.InternalAddr)
	if in.SSHUser == "" {
		in.SSHUser = "root"
	}
	if in.SSHPort == 0 {
		in.SSHPort = 22
	}
	switch {
	case in.Name == "":
		return nil, bad("请填写节点名称")
	case !addrRe.MatchString(in.SSHHost):
		return nil, bad("SSH 地址格式不正确")
	case in.SSHPort < 1 || in.SSHPort > 65535:
		return nil, bad("SSH 端口不正确")
	case !userRe.MatchString(in.SSHUser):
		return nil, bad("SSH 用户名格式不正确")
	case in.PublicAddr != "" && !addrRe.MatchString(in.PublicAddr):
		return nil, bad("公网地址格式不正确")
	case in.InternalAddr != "" && !addrRe.MatchString(in.InternalAddr):
		return nil, bad("内网地址格式不正确")
	}

	var out string
	err := a.store.Update(func(db *DB) error {
		var n *Node
		if id == "" {
			if in.SSHPassword == "" && strings.TrimSpace(in.SSHKey) == "" {
				return bad("请填写 SSH 密码或私钥")
			}
			n = &Node{ID: randHex(4), Status: "unknown"}
			db.Nodes = append(db.Nodes, n)
		} else if n = db.node(id); n == nil {
			return errNotFound
		}
		if in.JumpNodeID != "" {
			if db.node(in.JumpNodeID) == nil {
				return bad("跳板节点不存在")
			}
			// 沿跳板链向上检查，不能绕回自己。
			for cur, depth := in.JumpNodeID, 0; cur != ""; depth++ {
				if cur == n.ID || depth > maxJumpDepth {
					return bad("SSH 跳板存在循环或层级过深")
				}
				cur = db.node(cur).JumpNodeID
			}
		}
		if n.SSHHost != in.SSHHost || n.SSHPort != in.SSHPort {
			n.HostKey = "" // 换了服务器，重新记录主机公钥
		}
		n.Name, n.SSHHost, n.SSHPort, n.SSHUser = in.Name, in.SSHHost, in.SSHPort, in.SSHUser
		n.JumpNodeID, n.PublicAddr, n.InternalAddr = in.JumpNodeID, in.PublicAddr, in.InternalAddr
		// 密码 / 私钥留空表示保持不变。
		if in.SSHPassword != "" {
			n.SSHPassword = in.SSHPassword
		}
		if strings.TrimSpace(in.SSHKey) != "" {
			n.SSHKey = strings.TrimSpace(in.SSHKey) + "\n"
		} else if in.ClearKey {
			n.SSHKey = ""
		}
		out = n.ID
		return nil
	})
	if err != nil {
		return nil, err
	}
	return obj{"id": out}, nil
}

func (a *App) deleteNode(w http.ResponseWriter, r *http.Request) (any, error) {
	id := r.PathValue("id")
	return nil, a.store.Update(func(db *DB) error {
		if db.node(id) == nil {
			return errNotFound
		}
		for _, c := range db.Chains {
			for _, h := range c.Hops {
				if h.NodeID == id {
					return bad("线路「%s」正在使用该节点，请先修改或删除线路", c.Name)
				}
			}
		}
		for _, n := range db.Nodes {
			if n.JumpNodeID == id {
				return bad("节点「%s」把该节点作为 SSH 跳板，请先修改", n.Name)
			}
		}
		for i, n := range db.Nodes {
			if n.ID == id {
				db.Nodes = append(db.Nodes[:i], db.Nodes[i+1:]...)
				break
			}
		}
		return nil
	})
}

func (a *App) nodeName(id string) (string, error) {
	var name string
	a.store.View(func(db *DB) {
		if n := db.node(id); n != nil {
			name = n.Name
		}
	})
	if name == "" {
		return "", errNotFound
	}
	return name, nil
}

func (a *App) nodeCheck(w http.ResponseWriter, r *http.Request) (any, error) {
	id := r.PathValue("id")
	if _, err := a.nodeName(id); err != nil {
		return nil, err
	}
	if err := a.checkNode(id); err != nil {
		return obj{"ok": false, "error": err.Error()}, nil
	}
	return nil, nil
}

func (a *App) nodeInstall(w http.ResponseWriter, r *http.Request) (any, error) {
	id := r.PathValue("id")
	name, err := a.nodeName(id)
	if err != nil {
		return nil, err
	}
	t := a.tasks.Start("安装 v2ray：「"+name+"」", func(t *Task) error {
		err := a.installNode(t, id)
		if err != nil {
			_ = a.checkNode(id)
		}
		return err
	})
	return obj{"task_id": t.ID}, nil
}

func (a *App) nodeApply(w http.ResponseWriter, r *http.Request) (any, error) {
	id := r.PathValue("id")
	name, err := a.nodeName(id)
	if err != nil {
		return nil, err
	}
	t := a.tasks.Start("同步配置：「"+name+"」", func(t *Task) error { return a.applyNode(t, id) })
	return obj{"task_id": t.ID}, nil
}

// applyAll 把配置同步到所有已安装 v2ray 或参与线路的节点。
func (a *App) applyAll(w http.ResponseWriter, r *http.Request) (any, error) {
	db := a.store.Snapshot()
	t := a.tasks.Start("同步全部节点配置", func(t *Task) error {
		failed := 0
		for _, n := range db.Nodes {
			_, ports := configJSON(db, n.ID)
			if n.V2rayVersion == "" && len(ports) == 0 {
				continue
			}
			if err := a.applyNode(t, n.ID); err != nil {
				t.logf("「%s」失败: %v", n.Name, err)
				failed++
			}
		}
		if failed > 0 {
			return fmt.Errorf("%d 个节点同步失败", failed)
		}
		return nil
	})
	return obj{"task_id": t.ID}, nil
}

func (a *App) nodeResetHostKey(w http.ResponseWriter, r *http.Request) (any, error) {
	id := r.PathValue("id")
	return nil, a.store.Update(func(db *DB) error {
		n := db.node(id)
		if n == nil {
			return errNotFound
		}
		n.HostKey = ""
		return nil
	})
}

func (a *App) nodeConfig(w http.ResponseWriter, r *http.Request) (any, error) {
	db := a.store.Snapshot()
	if db.node(r.PathValue("id")) == nil {
		return nil, errNotFound
	}
	cfg, _ := configJSON(db, r.PathValue("id"))
	return obj{"config": cfg}, nil
}

// ---------- 节点 v2ray 配置项与备份 ----------

var logLevels = map[string]bool{"debug": true, "info": true, "warning": true, "error": true, "none": true}

func (a *App) saveNodeConf(w http.ResponseWriter, r *http.Request) (any, error) {
	id := r.PathValue("id")
	var in NodeConf
	if err := readJSON(r, &in); err != nil {
		return nil, err
	}
	if in.LogLevel == "" {
		in.LogLevel = "warning"
	}
	if !logLevels[in.LogLevel] {
		return nil, bad("日志级别不正确")
	}
	dns := []string{}
	for _, d := range in.DNS {
		if d = strings.TrimSpace(d); d == "" {
			continue
		}
		if len(d) > 200 || strings.ContainsAny(d, " \t\r\n\"") {
			return nil, bad("DNS 服务器格式不正确: %s", d)
		}
		dns = append(dns, d)
	}
	in.DNS = dns
	in.Extra = strings.TrimSpace(in.Extra)
	if _, err := parseExtra(in.Extra); err != nil {
		return nil, bad("自定义 JSON %v", err)
	}
	return nil, a.store.Update(func(db *DB) error {
		n := db.node(id)
		if n == nil {
			return errNotFound
		}
		n.Conf = in
		return nil
	})
}

func (a *App) backupList(w http.ResponseWriter, r *http.Request) (any, error) {
	id := r.PathValue("id")
	if _, err := a.nodeName(id); err != nil {
		return nil, err
	}
	list, err := a.listBackups(id)
	if err != nil {
		return nil, bad("%v", err)
	}
	return obj{"backups": list}, nil
}

func (a *App) backupGet(w http.ResponseWriter, r *http.Request) (any, error) {
	id, name := r.PathValue("id"), r.PathValue("name")
	if _, err := a.nodeName(id); err != nil {
		return nil, err
	}
	if !backupNameRe.MatchString(name) {
		return nil, bad("备份文件名不正确")
	}
	content, err := a.readBackup(id, name)
	if err != nil {
		return nil, bad("%v", err)
	}
	return obj{"config": content}, nil
}

func (a *App) backupCreate(w http.ResponseWriter, r *http.Request) (any, error) {
	id := r.PathValue("id")
	name, err := a.nodeName(id)
	if err != nil {
		return nil, err
	}
	t := a.tasks.Start("备份配置：「"+name+"」", func(t *Task) error { return a.backupNode(t, id) })
	return obj{"task_id": t.ID}, nil
}

func (a *App) backupRestore(w http.ResponseWriter, r *http.Request) (any, error) {
	id, file := r.PathValue("id"), r.PathValue("name")
	name, err := a.nodeName(id)
	if err != nil {
		return nil, err
	}
	if !backupNameRe.MatchString(file) {
		return nil, bad("备份文件名不正确")
	}
	t := a.tasks.Start("恢复备份：「"+name+"」", func(t *Task) error { return a.restoreNode(t, id, file) })
	return obj{"task_id": t.ID}, nil
}

// ---------- 出口代理 ----------

func (a *App) saveExit(w http.ResponseWriter, r *http.Request) (any, error) {
	id := r.PathValue("id")
	var in Exit
	if err := readJSON(r, &in); err != nil {
		return nil, err
	}
	in.Name, in.Address, in.Username = strings.TrimSpace(in.Name), strings.TrimSpace(in.Address), strings.TrimSpace(in.Username)
	switch {
	case in.Name == "":
		return nil, bad("请填写出口名称")
	case in.Protocol != "socks" && in.Protocol != "http":
		return nil, bad("协议只支持 socks 或 http")
	case !addrRe.MatchString(in.Address):
		return nil, bad("代理地址格式不正确")
	case in.Port < 1 || in.Port > 65535:
		return nil, bad("端口范围 1-65535")
	}
	return nil, a.store.Update(func(db *DB) error {
		var e *Exit
		if id == "" {
			e = &Exit{ID: randHex(4)}
			db.Exits = append(db.Exits, e)
		} else if e = db.exit(id); e == nil {
			return errNotFound
		}
		e.Name, e.Protocol, e.Address, e.Port = in.Name, in.Protocol, in.Address, in.Port
		// 密码留空表示保持不变；用户名清空则一并清除密码。
		if in.Password != "" {
			e.Password = in.Password
		}
		if in.Username == "" {
			e.Password = ""
		}
		e.Username = in.Username
		return nil
	})
}

func (a *App) deleteExit(w http.ResponseWriter, r *http.Request) (any, error) {
	id := r.PathValue("id")
	return nil, a.store.Update(func(db *DB) error {
		for _, c := range db.Chains {
			if c.ExitID == id {
				return bad("线路「%s」正在使用该出口，请先修改", c.Name)
			}
		}
		for _, u := range db.Users {
			if u.ExitID == id {
				return bad("用户「%s」正在使用该出口，请先修改", u.Name)
			}
		}
		for i, e := range db.Exits {
			if e.ID == id {
				db.Exits = append(db.Exits[:i], db.Exits[i+1:]...)
				return nil
			}
		}
		return errNotFound
	})
}

// ---------- 线路 ----------

func (a *App) saveChain(w http.ResponseWriter, r *http.Request) (any, error) {
	id := r.PathValue("id")
	var in struct {
		Name   string `json:"name"`
		Port   int    `json:"port"`
		Hops   []Hop  `json:"hops"`
		ExitID string `json:"exit_id"`
	}
	if err := readJSON(r, &in); err != nil {
		return nil, err
	}
	in.Name = strings.TrimSpace(in.Name)
	switch {
	case in.Name == "":
		return nil, bad("请填写线路名称")
	case in.Port < 1 || in.Port > 65535:
		return nil, bad("端口范围 1-65535")
	case len(in.Hops) == 0:
		return nil, bad("线路至少需要一个节点")
	case len(in.Hops) > 8:
		return nil, bad("线路最多 8 跳")
	}
	return nil, a.store.Update(func(db *DB) error {
		if in.ExitID != "" && db.exit(in.ExitID) == nil {
			return bad("所选出口代理不存在")
		}
		seen := map[string]bool{}
		for i := range in.Hops {
			h := &in.Hops[i]
			n := db.node(h.NodeID)
			if n == nil {
				return bad("第 %d 跳的节点不存在", i+1)
			}
			if seen[h.NodeID] {
				return bad("节点「%s」在线路中重复出现", n.Name)
			}
			seen[h.NodeID] = true
			if i == 0 || h.Addr != "internal" {
				h.Addr = "public"
			}
			if h.Addr == "internal" && n.InternalAddr == "" {
				return bad("节点「%s」未填写内网地址，无法走内网", n.Name)
			}
			if h.Addr == "public" && n.PublicAddr == "" && i > 0 {
				return bad("节点「%s」未填写公网地址", n.Name)
			}
		}
		if entry := db.node(in.Hops[0].NodeID); entry.PublicAddr == "" {
			return bad("入口节点「%s」未填写公网地址，用户无法连接", entry.Name)
		}
		for _, c := range db.Chains {
			if c.ID == id || c.Port != in.Port {
				continue
			}
			for _, h := range c.Hops {
				if seen[h.NodeID] {
					return bad("端口 %d 已被线路「%s」在节点「%s」上占用", in.Port, c.Name, db.node(h.NodeID).Name)
				}
			}
		}
		var c *Chain
		if id == "" {
			c = &Chain{ID: randHex(4), RelayUUID: newUUID()}
			db.Chains = append(db.Chains, c)
		} else if c = db.chain(id); c == nil {
			return errNotFound
		}
		c.Name, c.Port, c.Hops, c.ExitID = in.Name, in.Port, in.Hops, in.ExitID
		return nil
	})
}

func (a *App) deleteChain(w http.ResponseWriter, r *http.Request) (any, error) {
	id := r.PathValue("id")
	return nil, a.store.Update(func(db *DB) error {
		for i, c := range db.Chains {
			if c.ID == id {
				db.Chains = append(db.Chains[:i], db.Chains[i+1:]...)
				for _, u := range db.Users {
					ids := u.ChainIDs[:0]
					for _, cid := range u.ChainIDs {
						if cid != id {
							ids = append(ids, cid)
						}
					}
					// 被删到一条不剩时停用账号，避免「空 = 全部线路」意外扩大权限。
					if len(u.ChainIDs) > 0 && len(ids) == 0 {
						u.Enabled = false
					}
					u.ChainIDs = ids
				}
				return nil
			}
		}
		return errNotFound
	})
}

func (a *App) chainTest(w http.ResponseWriter, r *http.Request) (any, error) {
	id := r.PathValue("id")
	var name string
	a.store.View(func(db *DB) {
		if c := db.chain(id); c != nil {
			name = c.Name
		}
	})
	if name == "" {
		return nil, errNotFound
	}
	t := a.tasks.Start("检测线路：「"+name+"」", func(t *Task) error { return a.testChain(t, id) })
	return obj{"task_id": t.ID}, nil
}

// ---------- 用户 ----------

func (a *App) saveUser(w http.ResponseWriter, r *http.Request) (any, error) {
	id := r.PathValue("id")
	var in struct {
		Name     string   `json:"name"`
		Enabled  bool     `json:"enabled"`
		ChainIDs []string `json:"chain_ids"`
		Remark   string   `json:"remark"`
		ExitID   string   `json:"exit_id"`
	}
	if err := readJSON(r, &in); err != nil {
		return nil, err
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 64 {
		return nil, bad("请填写用户名（最多 64 个字符）")
	}
	return nil, a.store.Update(func(db *DB) error {
		for _, u := range db.Users {
			if u.Name == in.Name && u.ID != id {
				return bad("用户名已存在")
			}
		}
		if in.ExitID != "" && in.ExitID != exitDirect && db.exit(in.ExitID) == nil {
			return bad("所选出口代理不存在")
		}
		for _, cid := range in.ChainIDs {
			if db.chain(cid) == nil {
				return bad("所选线路不存在")
			}
		}
		var u *User
		if id == "" {
			u = &User{ID: randHex(4), UUID: newUUID(), SubToken: randHex(16), CreatedAt: time.Now()}
			db.Users = append(db.Users, u)
		} else if u = db.user(id); u == nil {
			return errNotFound
		}
		if in.ChainIDs == nil {
			in.ChainIDs = []string{}
		}
		u.Name, u.Enabled, u.ChainIDs, u.Remark = in.Name, in.Enabled, in.ChainIDs, strings.TrimSpace(in.Remark)
		u.ExitID = in.ExitID
		return nil
	})
}

func (a *App) deleteUser(w http.ResponseWriter, r *http.Request) (any, error) {
	id := r.PathValue("id")
	return nil, a.store.Update(func(db *DB) error {
		for i, u := range db.Users {
			if u.ID == id {
				db.Users = append(db.Users[:i], db.Users[i+1:]...)
				return nil
			}
		}
		return errNotFound
	})
}

// resetUser 重新生成用户的 UUID 与订阅地址，旧凭据在同步配置后失效。
func (a *App) resetUser(w http.ResponseWriter, r *http.Request) (any, error) {
	id := r.PathValue("id")
	return nil, a.store.Update(func(db *DB) error {
		u := db.user(id)
		if u == nil {
			return errNotFound
		}
		u.UUID, u.SubToken = newUUID(), randHex(16)
		return nil
	})
}

// subscription 是给客户端使用的订阅地址，凭 token 访问，无需登录。
func (a *App) subscription(w http.ResponseWriter, r *http.Request) {
	tok := r.PathValue("token")
	db := a.store.Snapshot()
	for _, u := range db.Users {
		if u.SubToken != tok || tok == "" {
			continue
		}
		var links []string
		for _, c := range db.Chains {
			if userAllowed(u, c.ID) {
				links = append(links, vmessLink(db, u, c))
			}
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprint(w, base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n"))))
		return
	}
	http.NotFound(w, r)
}

func (a *App) taskGet(w http.ResponseWriter, r *http.Request) (any, error) {
	t := a.tasks.Get(r.PathValue("id"))
	if t == nil {
		return nil, errNotFound
	}
	return t.view(true), nil
}
