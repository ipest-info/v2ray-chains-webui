package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------- 后台任务 ----------

type Task struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Status    string    `json:"status"` // running / success / failed
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at"`

	mu  sync.Mutex
	log []byte
}

func (t *Task) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.log) < 512<<10 {
		t.log = append(t.log, p...)
	}
	return len(p), nil
}

func (t *Task) logf(format string, a ...any) {
	fmt.Fprintf(t, "[%s] %s\n", time.Now().Format("15:04:05"), fmt.Sprintf(format, a...))
}

type taskView struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Status    string    `json:"status"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at"`
	Log       string    `json:"log,omitempty"`
}

func (t *Task) view(withLog bool) taskView {
	t.mu.Lock()
	defer t.mu.Unlock()
	v := taskView{ID: t.ID, Title: t.Title, Status: t.Status, StartedAt: t.StartedAt, EndedAt: t.EndedAt}
	if withLog {
		v.Log = string(t.log)
	}
	return v
}

type Tasks struct {
	mu    sync.Mutex
	list  []*Task
	locks sync.Map // 节点 ID -> *sync.Mutex，同一节点的操作串行执行
}

func (ts *Tasks) nodeLock(id string) *sync.Mutex {
	m, _ := ts.locks.LoadOrStore(id, &sync.Mutex{})
	return m.(*sync.Mutex)
}

// Start 在后台运行 fn 并返回任务。
func (ts *Tasks) Start(title string, fn func(t *Task) error) *Task {
	t := &Task{ID: randHex(6), Title: title, Status: "running", StartedAt: time.Now()}
	ts.mu.Lock()
	ts.list = append(ts.list, t)
	if len(ts.list) > 100 {
		ts.list = ts.list[len(ts.list)-100:]
	}
	ts.mu.Unlock()
	go func() {
		var err error
		func() {
			defer func() {
				if r := recover(); r != nil {
					err = fmt.Errorf("内部错误: %v", r)
				}
			}()
			err = fn(t)
		}()
		if err != nil {
			t.logf("失败: %v", err)
		} else {
			t.logf("完成")
		}
		t.mu.Lock()
		t.EndedAt = time.Now()
		if err != nil {
			t.Status = "failed"
		} else {
			t.Status = "success"
		}
		t.mu.Unlock()
	}()
	return t
}

func (ts *Tasks) Get(id string) *Task {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	for _, t := range ts.list {
		if t.ID == id {
			return t
		}
	}
	return nil
}

func (ts *Tasks) List() []taskView {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	out := make([]taskView, 0, len(ts.list))
	for i := len(ts.list) - 1; i >= 0; i-- {
		out = append(out, ts.list[i].view(false))
	}
	return out
}

// ---------- 节点操作 ----------

// connect 连接节点，并把首次见到的主机公钥写回存储。
func (a *App) connect(nodeID string) (*sshConn, *DB, error) {
	db := a.store.Snapshot()
	conn, err := dialNode(db, nodeID)
	if err != nil {
		return nil, db, err
	}
	if len(conn.learned) > 0 {
		_ = a.store.Update(func(d *DB) error {
			for id, key := range conn.learned {
				if n := d.node(id); n != nil && n.HostKey == "" {
					n.HostKey = key
				}
			}
			return nil
		})
	}
	return conn, db, nil
}

const probeCmd = `echo "VER=$(/usr/local/bin/v2ray version 2>/dev/null | head -n1)"; echo "ACTIVE=$(systemctl is-active v2ray 2>/dev/null)"`

func probe(conn *sshConn) (version string, active bool) {
	out, _ := runOutput(conn.Client, probeCmd, 20*time.Second)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "VER="); ok {
			if f := strings.Fields(v); len(f) >= 2 {
				version = f[1]
			} else {
				version = v
			}
		}
		if v, ok := strings.CutPrefix(line, "ACTIVE="); ok {
			active = v == "active"
		}
	}
	return
}

// checkNode 测试 SSH 连通性并刷新节点状态。
func (a *App) checkNode(nodeID string) error {
	conn, _, err := a.connect(nodeID)
	var ver string
	var active bool
	if err == nil {
		ver, active = probe(conn)
		conn.Close()
	}
	_ = a.store.Update(func(d *DB) error {
		n := d.node(nodeID)
		if n == nil {
			return nil
		}
		n.CheckedAt = time.Now()
		if err != nil {
			n.Status, n.StatusMsg = "offline", err.Error()
			return nil
		}
		n.Status, n.StatusMsg = "online", ""
		n.V2rayVersion, n.ServiceActive = ver, active
		return nil
	})
	return err
}

const depsScript = `
export DEBIAN_FRONTEND=noninteractive
need() { command -v "$1" >/dev/null 2>&1; }
if ! need curl || ! need unzip; then
  echo ">> 安装依赖 curl / unzip"
  if need apt-get; then apt-get update -y >/dev/null && apt-get install -y curl unzip
  elif need dnf; then dnf install -y curl unzip
  elif need yum; then yum install -y curl unzip
  elif need apk; then apk add --no-cache curl unzip
  else echo "无法自动安装 curl / unzip，请手动安装后重试"; exit 1; fi
fi
need systemctl || { echo "该系统没有 systemd，暂不支持"; exit 1; }
`

const installScript = `
set -e
TMP=$(mktemp -d)
trap 'rm -rf "$TMP" "$ZIP"' EXIT
unzip -tq "$ZIP" >/dev/null
unzip -oq "$ZIP" -d "$TMP"
systemctl stop v2ray 2>/dev/null || true
install -m 755 "$TMP/v2ray" /usr/local/bin/v2ray
mkdir -p /usr/local/share/v2ray /usr/local/etc/v2ray
install -m 644 "$TMP/geoip.dat" "$TMP/geosite.dat" /usr/local/share/v2ray/
if [ ! -f /usr/local/etc/v2ray/config.json ]; then
  echo '{"outbounds":[{"protocol":"freedom"}]}' > /usr/local/etc/v2ray/config.json
  chmod 600 /usr/local/etc/v2ray/config.json
fi
cat > /etc/systemd/system/v2ray.service <<'VCW_UNIT_EOF'
[Unit]
Description=V2Ray Service (managed by v2ray-chains-webui)
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
Environment=V2RAY_LOCATION_ASSET=/usr/local/share/v2ray
ExecStart=/usr/local/bin/v2ray run -config /usr/local/etc/v2ray/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
VCW_UNIT_EOF
systemctl daemon-reload
systemctl enable v2ray >/dev/null 2>&1
# VMess 要求各节点时间误差在 90 秒内
timedatectl set-ntp true 2>/dev/null || true
echo ">> 已安装: $(/usr/local/bin/v2ray version | head -n1)"
`

const errDownload = 42

// installNode 在节点上安装 v2ray 并同步配置。
// 目标节点自己下载失败时（例如境内节点访问 GitHub 不通），自动改由其它节点下载后经面板中转。
func (a *App) installNode(t *Task, nodeID string) error {
	l := a.tasks.nodeLock(nodeID)
	l.Lock()
	defer l.Unlock()

	conn, db, err := a.connect(nodeID)
	if err != nil {
		return err
	}
	defer conn.Close()
	n := db.node(nodeID)
	t.logf("已连接节点「%s」", n.Name)

	m, err := runOutput(conn.Client, "uname -m", 20*time.Second)
	if err != nil {
		return fmt.Errorf("获取系统架构失败: %w", err)
	}
	var arch string
	switch strings.TrimSpace(m) {
	case "x86_64", "amd64":
		arch = "64"
	case "aarch64", "arm64":
		arch = "arm64-v8a"
	default:
		return fmt.Errorf("暂不支持的系统架构: %s", strings.TrimSpace(m))
	}
	url := strings.ReplaceAll(db.Settings.DownloadURL, "{arch}", arch)
	zip := "/tmp/vcw-" + randHex(8) + ".zip"

	if err := runRootScript(conn.Client, n, depsScript, t, 10*time.Minute); err != nil {
		return fmt.Errorf("准备依赖失败: %w", err)
	}

	t.logf("下载 %s", url)
	dl := fmt.Sprintf("curl -fsSL --connect-timeout 15 --max-time 900 -o %s %s && unzip -tq %s >/dev/null || { rm -f %s; exit %d; }",
		zip, shq(url), zip, zip, errDownload)
	if err := runSession(conn.Client, dl, nil, t, 16*time.Minute); err != nil {
		if exitCode(err) != errDownload {
			return fmt.Errorf("下载失败: %w", err)
		}
		t.logf("节点自身下载失败，尝试由其它节点代为下载")
		if err := a.relayDownload(t, db, n, conn, url, zip); err != nil {
			return err
		}
	}

	t.logf("安装 v2ray")
	if err := runRootScript(conn.Client, n, "ZIP="+zip+"\n"+installScript, t, 5*time.Minute); err != nil {
		return fmt.Errorf("安装失败: %w", err)
	}
	return a.applyOn(t, conn, nodeID)
}

// relayDownload 依次尝试让其它节点下载安装包，并通过 SSH 流式转存到目标节点。
func (a *App) relayDownload(t *Task, db *DB, target *Node, tc *sshConn, url, zip string) error {
	// 优先使用目标节点的跳板，其次是其它节点。
	var order []*Node
	if j := db.node(target.JumpNodeID); j != nil {
		order = append(order, j)
	}
	for _, o := range db.Nodes {
		if o.ID != target.ID && o.ID != target.JumpNodeID {
			order = append(order, o)
		}
	}
	for _, src := range order {
		t.logf("尝试经节点「%s」下载", src.Name)
		sc, err := dialNode(db, src.ID)
		if err != nil {
			t.logf("  跳过: %v", err)
			continue
		}
		err = pipeDownload(sc, tc, url, zip)
		sc.Close()
		if err != nil {
			t.logf("  失败: %v", err)
			continue
		}
		if _, err := runOutput(tc.Client, "unzip -tq "+zip, time.Minute); err != nil {
			t.logf("  安装包校验失败")
			continue
		}
		t.logf("  下载成功")
		return nil
	}
	_, _ = runOutput(tc.Client, "rm -f "+zip, 20*time.Second)
	return errors.New("所有节点都无法下载安装包，请在「设置」中更换下载地址（镜像）后重试")
}

func pipeDownload(src, dst *sshConn, url, zip string) error {
	ss, err := src.NewSession()
	if err != nil {
		return err
	}
	defer ss.Close()
	ds, err := dst.NewSession()
	if err != nil {
		return err
	}
	defer ds.Close()
	rd, err := ss.StdoutPipe()
	if err != nil {
		return err
	}
	wr, err := ds.StdinPipe()
	if err != nil {
		return err
	}
	if err := ds.Start("umask 077; cat > " + zip); err != nil {
		return err
	}
	if err := ss.Start("curl -fsSL --connect-timeout 15 --max-time 900 " + shq(url)); err != nil {
		return err
	}
	timer := time.AfterFunc(16*time.Minute, func() { ss.Close(); ds.Close() })
	defer timer.Stop()
	_, cerr := io.Copy(wr, rd)
	wr.Close()
	serr := ss.Wait()
	derr := ds.Wait()
	return errors.Join(serr, cerr, derr)
}

// scriptHead 是同步 / 备份 / 恢复脚本的公共部分。备份保存在节点上，最多保留 30 份。
const scriptHead = `
set -e
export V2RAY_LOCATION_ASSET=/usr/local/share/v2ray
[ -x /usr/local/bin/v2ray ] || { echo "该节点尚未安装 v2ray，请先执行「安装」"; exit 1; }
D=/usr/local/etc/v2ray
B=$D/backups
mkdir -p "$D"
umask 077
backup_config() {
  mkdir -p "$B"
  name="config-$(date +%Y%m%d-%H%M%S).json"
  cp -p "$D/config.json" "$B/$name"
  ls -1 "$B" | grep -E '^config-[0-9]{8}-[0-9]{6}\.json$' | sort -r | tail -n +31 | while read -r f; do rm -f "$B/$f"; done
  echo ">> 已备份当前配置: $name"
}
restart_v2ray() {
  systemctl restart v2ray
  sleep 1
  systemctl is-active --quiet v2ray || { echo "v2ray 启动失败:"; journalctl -u v2ray -n 20 --no-pager 2>/dev/null; exit 1; }
}
`

const applyScript = scriptHead + `
cat > "$D/config.new.json" <<'VCW_CONFIG_EOF'
@CONFIG@
VCW_CONFIG_EOF
/usr/local/bin/v2ray test -c "$D/config.new.json" >/dev/null || { echo "配置校验未通过，已保留原配置"; exit 1; }
# 覆盖前先备份当前配置（内容没有变化时不重复备份）
if [ -f "$D/config.json" ] && ! cmp -s "$D/config.json" "$D/config.new.json"; then
  backup_config
fi
mv -f "$D/config.new.json" "$D/config.json"
for p in @PORTS@; do
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then ufw allow "$p/tcp" >/dev/null; fi
  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd -q --permanent --add-port="$p/tcp" && firewall-cmd -q --add-port="$p/tcp"
  fi
done
restart_v2ray
echo ">> 配置已生效"
`

const backupNowScript = scriptHead + `
[ -f "$D/config.json" ] || { echo "节点上还没有配置文件"; exit 1; }
backup_config
`

// 恢复前同样先备份当前配置；备份文件校验不通过则不动现有配置。
const restoreScript = scriptHead + `
F="$B/@NAME@"
[ -f "$F" ] || { echo "备份文件不存在"; exit 1; }
cp -p "$F" "$D/config.new.json"
/usr/local/bin/v2ray test -c "$D/config.new.json" >/dev/null || { rm -f "$D/config.new.json"; echo "备份文件校验未通过，已保留当前配置"; exit 1; }
if [ -f "$D/config.json" ] && ! cmp -s "$D/config.json" "$D/config.new.json"; then
  backup_config
fi
mv -f "$D/config.new.json" "$D/config.json"
restart_v2ray
echo ">> 已恢复备份并重启 v2ray"
`

const listBackupsScript = `
B=/usr/local/etc/v2ray/backups
[ -d "$B" ] || exit 0
cd "$B"
for f in config-*.json; do [ -f "$f" ] && echo "VCW_BACKUP $f $(stat -c %s "$f")"; done
exit 0
`

var backupNameRe = regexp.MustCompile(`^config-(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})\.json$`)

type backupInfo struct {
	Name string `json:"name"`
	Time string `json:"time"` // 节点本地时间
	Size int    `json:"size"`
}

// listBackups 列出节点上的配置备份，最新的在前。
func (a *App) listBackups(nodeID string) ([]backupInfo, error) {
	conn, db, err := a.connect(nodeID)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	var buf bytes.Buffer
	if err := runRootScript(conn.Client, db.node(nodeID), listBackupsScript, &buf, 30*time.Second); err != nil {
		return nil, fmt.Errorf("读取备份列表失败: %w: %s", err, strings.TrimSpace(buf.String()))
	}
	out := []backupInfo{}
	for _, line := range strings.Split(buf.String(), "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || f[0] != "VCW_BACKUP" {
			continue
		}
		m := backupNameRe.FindStringSubmatch(f[1])
		if m == nil {
			continue
		}
		size, _ := strconv.Atoi(f[2])
		out = append(out, backupInfo{Name: f[1], Size: size,
			Time: fmt.Sprintf("%s-%s-%s %s:%s:%s", m[1], m[2], m[3], m[4], m[5], m[6])})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	return out, nil
}

// readBackup 读取一份备份的内容。
func (a *App) readBackup(nodeID, name string) (string, error) {
	conn, db, err := a.connect(nodeID)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	var buf bytes.Buffer
	script := "cat /usr/local/etc/v2ray/backups/" + name + "\n"
	if err := runRootScript(conn.Client, db.node(nodeID), script, &buf, 30*time.Second); err != nil {
		return "", fmt.Errorf("读取备份失败: %w: %s", err, strings.TrimSpace(buf.String()))
	}
	return buf.String(), nil
}

// backupNode 立即备份节点上的当前配置。
func (a *App) backupNode(t *Task, nodeID string) error {
	l := a.tasks.nodeLock(nodeID)
	l.Lock()
	defer l.Unlock()
	conn, db, err := a.connect(nodeID)
	if err != nil {
		return err
	}
	defer conn.Close()
	return runRootScript(conn.Client, db.node(nodeID), backupNowScript, t, time.Minute)
}

// restoreNode 把节点配置恢复为指定备份并重启 v2ray。
func (a *App) restoreNode(t *Task, nodeID, name string) error {
	l := a.tasks.nodeLock(nodeID)
	l.Lock()
	defer l.Unlock()
	conn, db, err := a.connect(nodeID)
	if err != nil {
		a.markOffline(nodeID, err)
		return err
	}
	defer conn.Close()
	t.logf("恢复备份 %s", name)
	if err := runRootScript(conn.Client, db.node(nodeID), strings.ReplaceAll(restoreScript, "@NAME@", name), t, 2*time.Minute); err != nil {
		return fmt.Errorf("恢复失败: %w", err)
	}
	t.logf("注意：节点现在运行的是备份中的配置，与后台当前数据可能不一致；再次「同步配置」会用后台数据覆盖它")
	ver, active := probe(conn)
	return a.store.Update(func(d *DB) error {
		if n := d.node(nodeID); n != nil {
			// 记为与后台生成的配置不同，页面上显示「配置待同步」。
			n.AppliedHash, n.AppliedAt = "restored:"+name, time.Now()
			n.Status, n.StatusMsg, n.CheckedAt = "online", "", time.Now()
			n.V2rayVersion, n.ServiceActive = ver, active
		}
		return nil
	})
}

// applyNode 把当前配置同步到节点并重启 v2ray。
func (a *App) applyNode(t *Task, nodeID string) error {
	l := a.tasks.nodeLock(nodeID)
	l.Lock()
	defer l.Unlock()
	conn, _, err := a.connect(nodeID)
	if err != nil {
		a.markOffline(nodeID, err)
		return err
	}
	defer conn.Close()
	return a.applyOn(t, conn, nodeID)
}

func (a *App) markOffline(nodeID string, err error) {
	_ = a.store.Update(func(d *DB) error {
		if n := d.node(nodeID); n != nil {
			n.Status, n.StatusMsg, n.CheckedAt = "offline", err.Error(), time.Now()
		}
		return nil
	})
}

func (a *App) applyOn(t *Task, conn *sshConn, nodeID string) error {
	db := a.store.Snapshot() // 取最新数据生成配置
	n := db.node(nodeID)
	if n == nil {
		return errors.New("节点不存在")
	}
	cfg, ports := configJSON(db, nodeID)
	ps := make([]string, len(ports))
	for i, p := range ports {
		ps[i] = strconv.Itoa(p)
	}
	t.logf("同步配置到「%s」（监听端口: %s）", n.Name, strings.Join(ps, " "))
	if err := runRootScript(conn.Client, n, strings.NewReplacer("@CONFIG@", cfg, "@PORTS@", strings.Join(ps, " ")).Replace(applyScript), t, 2*time.Minute); err != nil {
		return fmt.Errorf("同步配置失败: %w", err)
	}
	ver, active := probe(conn)
	return a.store.Update(func(d *DB) error {
		if n := d.node(nodeID); n != nil {
			n.AppliedHash, n.AppliedAt = configHash(cfg), time.Now()
			n.Status, n.StatusMsg, n.CheckedAt = "online", "", time.Now()
			n.V2rayVersion, n.ServiceActive = ver, active
		}
		return nil
	})
}

// testChain 逐跳检查「上一跳能否连到下一跳的线路端口」。
func (a *App) testChain(t *Task, chainID string) error {
	db := a.store.Snapshot()
	c := db.chain(chainID)
	if c == nil {
		return errors.New("线路不存在")
	}
	failed := 0
	for i := 0; i+1 < len(c.Hops); i++ {
		from, to := db.node(c.Hops[i].NodeID), db.node(c.Hops[i+1].NodeID)
		if from == nil || to == nil {
			return errors.New("线路中的节点不存在")
		}
		addr := hopAddr(to, c.Hops[i+1].Addr)
		t.logf("「%s」→「%s」(%s:%d)", from.Name, to.Name, addr, c.Port)
		conn, _, err := a.connect(from.ID)
		if err != nil {
			t.logf("  无法 SSH 到「%s」: %v", from.Name, err)
			failed++
			continue
		}
		cmd := fmt.Sprintf("timeout 6 bash -c %s", shq(fmt.Sprintf("exec 3<>/dev/tcp/%s/%d", addr, c.Port)))
		_, err = runOutput(conn.Client, cmd, 15*time.Second)
		conn.Close()
		if err != nil {
			t.logf("  不通（请确认下一跳已同步配置，且防火墙 / 安全组已放行 TCP %d）", c.Port)
			failed++
		} else {
			t.logf("  连通")
		}
	}
	if len(c.Hops) < 2 {
		t.logf("单节点线路，无需检测节点间连通性")
	}
	if failed > 0 {
		return fmt.Errorf("%d 段不通", failed)
	}
	return nil
}
