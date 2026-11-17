package main

import (
	"bufio"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 带宽监控：每个节点保持一条常驻 SSH 连接，节点每 5 秒输出一次 /proc/net/dev 的网卡累计字节数，
// 后台据此算出各网卡的上下行速率。数据只保存在内存里，后台重启后重新开始累积。

const (
	monInterval = 5 // 秒
	monScript   = `while :; do echo "VCW_T $(cut -d' ' -f1 /proc/uptime)"; cat /proc/net/dev; echo VCW_END; sleep 5; done`
)

// 三档精度：5 秒 × 1 小时、1 分钟 × 24 小时、10 分钟 × 7 天。
var monTiers = []struct {
	name   string
	step   int64 // 秒
	points int
}{
	{"1h", monInterval, 720},
	{"24h", 60, 1440},
	{"7d", 600, 1008},
}

// 虚拟网卡不计入「合计」，避免容器 / 隧道流量被重复统计。
var virtualIfacePrefixes = []string{"lo", "veth", "docker", "br-", "virbr", "cni", "flannel", "cali", "kube", "dummy", "tunl", "sit", "ip6tnl", "ifb"}

func isVirtualIface(name string) bool {
	for _, p := range virtualIfacePrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

type rate struct{ Rx, Tx float64 } // bit/s

type monSample struct {
	T int64 // Unix 秒
	R map[string]rate
}

// monBucket 把细粒度采样聚合成一个粗粒度点（取平均）。
type monBucket struct {
	start int64
	sum   map[string]rate
	n     int
}

type nodeMon struct {
	mu        sync.Mutex
	tiers     [][]monSample
	buckets   []monBucket // 与 tiers[1:] 对应
	lastBytes map[string][2]uint64
	lastUp    float64
	connected bool
	errMsg    string
	updated   time.Time

	sig  string // 连接参数的摘要，变化后重连
	stop chan struct{}
}

func newNodeMon(sig string) *nodeMon {
	return &nodeMon{
		tiers: make([][]monSample, len(monTiers)), buckets: make([]monBucket, len(monTiers)-1),
		sig: sig, stop: make(chan struct{}),
	}
}

// add 记录一次采样：counters 为各网卡的累计收 / 发字节数，up 为节点的开机秒数（单调时钟）。
func (m *nodeMon) add(now time.Time, up float64, counters map[string][2]uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	prev, prevUp := m.lastBytes, m.lastUp
	m.lastBytes, m.lastUp, m.updated = counters, up, now
	dt := up - prevUp
	if prev == nil || dt <= 0 || dt > 60 {
		return // 第一次采样、节点重启或中断过久：只记基准，不算速率
	}
	s := monSample{T: now.Unix(), R: map[string]rate{}}
	for name, c := range counters {
		p, ok := prev[name]
		if !ok || c[0] < p[0] || c[1] < p[1] {
			continue // 新网卡或计数器回绕
		}
		s.R[name] = rate{float64(c[0]-p[0]) * 8 / dt, float64(c[1]-p[1]) * 8 / dt}
	}
	m.push(0, s)
	for i := range m.buckets {
		b := &m.buckets[i]
		step := monTiers[i+1].step
		start := s.T - s.T%step
		if b.n > 0 && start != b.start {
			avg := monSample{T: b.start, R: map[string]rate{}}
			for name, v := range b.sum {
				avg.R[name] = rate{v.Rx / float64(b.n), v.Tx / float64(b.n)}
			}
			m.push(i+1, avg)
			b.n = 0
		}
		if b.n == 0 {
			b.start, b.sum = start, map[string]rate{}
		}
		for name, v := range s.R {
			cur := b.sum[name]
			b.sum[name] = rate{cur.Rx + v.Rx, cur.Tx + v.Tx}
		}
		b.n++
	}
}

func (m *nodeMon) push(tier int, s monSample) {
	t := append(m.tiers[tier], s)
	if max := monTiers[tier].points; len(t) > max {
		t = t[len(t)-max:]
	}
	m.tiers[tier] = t
}

func (m *nodeMon) setState(connected bool, msg string) {
	m.mu.Lock()
	m.connected, m.errMsg = connected, msg
	if !connected {
		m.lastBytes = nil // 重连后重新取基准
	}
	m.mu.Unlock()
}

// parseNetDev 解析一段 /proc/net/dev 输出。
func parseNetDev(lines []string) map[string][2]uint64 {
	out := map[string][2]uint64{}
	for _, line := range lines {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 9 {
			continue
		}
		rx, err1 := strconv.ParseUint(f[0], 10, 64)
		tx, err2 := strconv.ParseUint(f[8], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		out[strings.TrimSpace(name)] = [2]uint64{rx, tx}
	}
	return out
}

type Monitor struct {
	app   *App
	mu    sync.Mutex
	nodes map[string]*nodeMon
}

func nodeSig(n *Node) string {
	return fmt.Sprintf("%s|%d|%s|%s|%s", n.SSHHost, n.SSHPort, n.SSHUser, n.JumpNodeID, configHash(n.SSHPassword+n.SSHKey))
}

// run 定期对照节点列表：为新节点启动采集，停止已删除或连接参数已变更的节点的采集。
func (mo *Monitor) run() {
	for {
		db := mo.app.store.Snapshot()
		mo.mu.Lock()
		alive := map[string]bool{}
		for _, n := range db.Nodes {
			alive[n.ID] = true
			sig := nodeSig(n)
			if cur := mo.nodes[n.ID]; cur != nil && cur.sig == sig {
				continue
			} else if cur != nil {
				close(cur.stop)
			}
			m := newNodeMon(sig)
			mo.nodes[n.ID] = m
			go mo.collect(n.ID, m)
		}
		for id, m := range mo.nodes {
			if !alive[id] {
				close(m.stop)
				delete(mo.nodes, id)
			}
		}
		mo.mu.Unlock()
		time.Sleep(15 * time.Second)
	}
}

// collect 维持到节点的监控连接，断开后退避重连。
func (mo *Monitor) collect(nodeID string, m *nodeMon) {
	backoff := 5 * time.Second
	for {
		started := time.Now()
		err := mo.stream(nodeID, m)
		select {
		case <-m.stop:
			return
		default:
		}
		msg := "监控连接已断开"
		if err != nil {
			msg = err.Error()
		}
		m.setState(false, msg)
		if time.Since(started) > time.Minute {
			backoff = 5 * time.Second
		} else if backoff < 5*time.Minute {
			backoff *= 2
		}
		select {
		case <-m.stop:
			return
		case <-time.After(backoff):
		}
	}
}

func (mo *Monitor) stream(nodeID string, m *nodeMon) error {
	conn, _, err := mo.app.connect(nodeID)
	if err != nil {
		return err
	}
	defer conn.Close()
	done := make(chan struct{})
	defer close(done)
	go func() { // 停止采集或连接卡死（3 个周期没有数据）时断开
		tick := time.NewTicker(time.Duration(monInterval) * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-m.stop:
				conn.Close()
				return
			case <-done:
				return
			case <-tick.C:
				m.mu.Lock()
				stale := m.connected && time.Since(m.updated) > 4*monInterval*time.Second
				m.mu.Unlock()
				if stale {
					conn.Close()
					return
				}
			}
		}
	}()
	sess, err := conn.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return err
	}
	if err := sess.Start(monScript); err != nil {
		return err
	}
	m.mu.Lock()
	m.connected, m.errMsg, m.updated = true, "", time.Now()
	m.mu.Unlock()

	sc := bufio.NewScanner(stdout)
	var up float64
	var lines []string
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "VCW_T "):
			up, _ = strconv.ParseFloat(strings.TrimSpace(line[6:]), 64)
			lines = lines[:0]
		case line == "VCW_END":
			m.add(time.Now(), up, parseNetDev(lines))
		default:
			lines = append(lines, line)
		}
	}
	return sc.Err()
}

// ---------- 接口 ----------

type ifaceView struct {
	Name    string  `json:"name"`
	Virtual bool    `json:"virtual"`
	Rx      float64 `json:"rx"` // 当前速率 bit/s
	Tx      float64 `json:"tx"`
}

type bandwidthNode struct {
	ID        string      `json:"id"`
	Name      string      `json:"name"`
	Connected bool        `json:"connected"`
	Error     string      `json:"error"`
	Ifaces    []ifaceView `json:"ifaces"`
	Iface     string      `json:"iface"`  // 本次返回的曲线对应的网卡，空表示合计
	Points    [][3]int64  `json:"points"` // [时间, 下行 bit/s, 上行 bit/s]
	RxBytes   float64     `json:"rx_bytes"`
	TxBytes   float64     `json:"tx_bytes"`
}

func pick(s monSample, iface string) rate {
	if iface != "" {
		return s.R[iface]
	}
	var total rate
	for name, v := range s.R {
		if !isVirtualIface(name) {
			total.Rx += v.Rx
			total.Tx += v.Tx
		}
	}
	return total
}

// bandwidth 返回各节点在所选时间范围内的速率曲线。?range=1h|24h|7d，?iface.<节点ID>=网卡名 选择单个网卡。
func (a *App) bandwidth(w http.ResponseWriter, r *http.Request) (any, error) {
	tier := 0
	for i, t := range monTiers {
		if t.name == r.URL.Query().Get("range") {
			tier = i
		}
	}
	db := a.store.Snapshot()
	out := []bandwidthNode{}
	a.monitor.mu.Lock()
	mons := map[string]*nodeMon{}
	for id, m := range a.monitor.nodes {
		mons[id] = m
	}
	a.monitor.mu.Unlock()

	for _, n := range db.Nodes {
		v := bandwidthNode{ID: n.ID, Name: n.Name, Ifaces: []ifaceView{}, Points: [][3]int64{}, Error: "正在连接…"}
		m := mons[n.ID]
		if m == nil {
			out = append(out, v)
			continue
		}
		m.mu.Lock()
		v.Connected, v.Error = m.connected, m.errMsg
		if fine := m.tiers[0]; len(fine) > 0 && m.connected {
			last := fine[len(fine)-1]
			for name, rt := range last.R {
				v.Ifaces = append(v.Ifaces, ifaceView{Name: name, Virtual: isVirtualIface(name), Rx: rt.Rx, Tx: rt.Tx})
			}
			sort.Slice(v.Ifaces, func(i, j int) bool {
				if v.Ifaces[i].Virtual != v.Ifaces[j].Virtual {
					return !v.Ifaces[i].Virtual
				}
				return v.Ifaces[i].Name < v.Ifaces[j].Name
			})
		}
		iface := r.URL.Query().Get("iface." + n.ID)
		v.Iface = iface
		step := float64(monTiers[tier].step)
		for _, s := range m.tiers[tier] {
			rt := pick(s, iface)
			v.Points = append(v.Points, [3]int64{s.T, int64(rt.Rx), int64(rt.Tx)})
			v.RxBytes += rt.Rx / 8 * step
			v.TxBytes += rt.Tx / 8 * step
		}
		m.mu.Unlock()
		out = append(out, v)
	}
	return obj{"range": monTiers[tier].name, "step": monTiers[tier].step, "nodes": out}, nil
}
