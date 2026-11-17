package main

import (
	"bytes"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// 节点排查：一次 SSH 收集服务状态、端口监听、配置校验、时间偏差和最近的 v2ray 日志，
// 再对照常见错误给出可能的原因。

const diagnoseScript = `
export V2RAY_LOCATION_ASSET=/usr/local/share/v2ray
echo "VCW_NOW=$(date +%s)"
echo "VCW_INSTALLED=$([ -x /usr/local/bin/v2ray ] && echo yes || echo no)"
echo "VCW_ACTIVE=$(systemctl is-active v2ray 2>/dev/null)"
echo "VCW_SINCE=$(systemctl show v2ray -p ActiveEnterTimestamp --value 2>/dev/null)"
echo "VCW_RESTARTS=$(systemctl show v2ray -p NRestarts --value 2>/dev/null)"
echo VCW_PORTS_BEGIN
(ss -lntp 2>/dev/null || netstat -lntp 2>/dev/null) | grep -i v2ray
echo VCW_PORTS_END
if [ -x /usr/local/bin/v2ray ] && [ -f /usr/local/etc/v2ray/config.json ]; then
  echo VCW_TEST_BEGIN
  /usr/local/bin/v2ray test -c /usr/local/etc/v2ray/config.json 2>&1 | tail -n 6
  echo "VCW_TEST_RC=${PIPESTATUS[0]}"
fi
echo VCW_LOG_BEGIN
journalctl -u v2ray -n @LINES@ --no-pager -o short-iso 2>&1
echo VCW_LOG_END
`

type diagCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"` // ok / bad / warn
	Detail string `json:"detail"`
}

type diagHint struct {
	Title  string `json:"title"`
	Advice string `json:"advice"`
	Count  int    `json:"count"`
	Sample string `json:"sample"`
}

// 常见日志错误及其可能原因。按顺序匹配，每行日志只归入第一条命中的规则。
var logPatterns = []struct {
	re            *regexp.Regexp
	title, advice string
}{
	{regexp.MustCompile(`(?i)address already in use`), "端口被占用",
		"线路端口已被其它程序占用，v2ray 无法监听。换一个线路端口，或在节点上停掉占用该端口的程序。"},
	{regexp.MustCompile(`(?i)invalid user|not found user|failed to (validate|read) request|invalid auth`), "VMess 认证失败",
		"连进来的凭据本节点不认识。常见原因：上下游节点或客户端的配置不是同一版（对所有节点「同步全部配置」，客户端更新订阅）；用户已停用或重置过凭据；节点之间时间相差超过 90 秒；也可能只是公网上的端口扫描。"},
	{regexp.MustCompile(`(?i)failed to (parse|load|build)|invalid config|unknown (protocol|config)|unmarshal|malformed`), "配置解析失败",
		"节点上的配置文件有问题。检查该节点「配置项」里的自定义 JSON；也可以在「备份 / 恢复」里恢复到上一份能用的配置。"},
	{regexp.MustCompile(`(?i)connection refused`), "对端拒绝连接",
		"下一跳（或出口代理）的端口没有在监听。确认下一跳节点已安装并同步配置、v2ray 在运行；如果目标是出口代理，确认代理地址和端口正确。"},
	{regexp.MustCompile(`(?i)i/o timeout|deadline exceeded|no route to host|network is unreachable|connection timed out`), "连接超时 / 不可达",
		"本节点连不上下一跳或目标地址。检查下一跳的安全组 / 防火墙是否放行线路端口、线路里该跳选的内网 / 公网地址是否正确；用线路页的「检测连通性」逐跳确认。"},
	{regexp.MustCompile(`(?i)socks|http.*proxy.*(fail|error)|proxy.*(auth|denied)`), "出口代理异常",
		"经出口代理转发失败。检查代理的地址、端口、用户名密码，以及代理服务是否可用；UDP 相关的报错可在「出口代理」页「检测 UDP」确认代理是否支持 UDP。"},
	{regexp.MustCompile(`(?i)no such host|failed to (lookup|resolve)|dns`), "域名解析失败",
		"节点解析域名失败。检查节点的 DNS 设置，或在节点「配置项」里指定 DNS 服务器。"},
	{regexp.MustCompile(`(?i)too many open files`), "文件句柄耗尽",
		"并发连接数超过系统限制。重新「安装」一次会写入更高的 LimitNOFILE，或检查是否有异常的大量连接。"},
	{regexp.MustCompile(`(?i)permission denied`), "权限不足",
		"v2ray 没有权限读取文件或监听端口。重新「安装」一次以恢复服务文件和权限。"},
	{regexp.MustCompile(`(?i)connection reset|broken pipe|closed pipe|EOF`), "连接被中断",
		"连接中途断开。少量出现属于正常（用户关闭连接、目标网站断开）；大量出现时检查线路质量，或是否被中间网络干扰。"},
}

var problemLineRe = regexp.MustCompile(`(?i)\[(warning|error)\]|fail|error|panic|denied|refused|timeout|invalid`)
var listenPortRe = regexp.MustCompile(`[:\]](\d+)\s`)

// diagnoseNode 收集并分析节点的运行状况。
func (a *App) diagnoseNode(nodeID string, lines int) (obj, error) {
	db := a.store.Snapshot()
	n := db.node(nodeID)
	if n == nil {
		return nil, errNotFound
	}
	checks := []diagCheck{}
	add := func(name, status, detail string) { checks = append(checks, diagCheck{name, status, detail}) }
	result := func(logs []string, hints []diagHint) obj {
		return obj{"checks": checks, "hints": hints, "logs": logs, "time": time.Now()}
	}

	conn, _, err := a.connect(nodeID)
	if err != nil {
		a.markOffline(nodeID, err)
		add("SSH 连接", "bad", err.Error())
		advice := "后台连不上这个节点。检查 SSH 地址、端口、账号密码，以及节点的安全组是否放行 SSH。"
		if n.JumpNodeID == "" && len(db.Nodes) > 1 {
			advice += "如果后台所在机器本来就无法直连它，编辑节点并在「SSH 跳板」里选择一个能连到它的节点。"
		}
		return result([]string{}, []diagHint{{Title: "无法通过 SSH 连接节点", Advice: advice, Count: 1}}), nil
	}
	defer conn.Close()
	add("SSH 连接", "ok", "")

	var buf bytes.Buffer
	script := strings.ReplaceAll(diagnoseScript, "@LINES@", strconv.Itoa(lines))
	if err := runRootScript(conn.Client, n, script, &buf, 40*time.Second); err != nil {
		add("收集诊断信息", "bad", err.Error())
		return result([]string{}, []diagHint{}), nil
	}
	now := time.Now()

	kv := map[string]string{}
	section := ""
	var ports, test, logs []string
	for _, line := range strings.Split(buf.String(), "\n") {
		line = strings.TrimRight(line, "\r")
		switch line {
		case "VCW_PORTS_BEGIN", "VCW_TEST_BEGIN", "VCW_LOG_BEGIN":
			section = line
			continue
		case "VCW_PORTS_END", "VCW_LOG_END":
			section = ""
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok && strings.HasPrefix(k, "VCW_") && section != "VCW_LOG_BEGIN" {
			kv[k] = v
			if k == "VCW_TEST_RC" {
				section = ""
			}
			continue
		}
		switch section {
		case "VCW_PORTS_BEGIN":
			ports = append(ports, line)
		case "VCW_TEST_BEGIN":
			test = append(test, line)
		case "VCW_LOG_BEGIN":
			if strings.TrimSpace(line) != "" {
				logs = append(logs, line)
			}
		}
	}
	if logs == nil {
		logs = []string{}
	}
	hints := []diagHint{}

	// v2ray 是否安装、是否在运行
	if kv["VCW_INSTALLED"] != "yes" {
		add("v2ray 已安装", "bad", "节点上没有 /usr/local/bin/v2ray")
		hints = append(hints, diagHint{Title: "节点尚未安装 v2ray", Advice: "在节点列表点「安装」。", Count: 1})
		return result(logs, hints), nil
	}
	add("v2ray 已安装", "ok", "")
	active := kv["VCW_ACTIVE"] == "active"
	if active {
		detail := ""
		if kv["VCW_SINCE"] != "" {
			detail = "启动于 " + kv["VCW_SINCE"]
		}
		if r, _ := strconv.Atoi(kv["VCW_RESTARTS"]); r > 0 {
			detail += fmt.Sprintf("，已自动重启 %d 次", r)
			add("v2ray 服务运行中", "warn", detail)
			hints = append(hints, diagHint{Title: "v2ray 发生过异常重启",
				Advice: "服务崩溃后被 systemd 自动拉起。查看下面日志里重启前的报错。", Count: r})
		} else {
			add("v2ray 服务运行中", "ok", detail)
		}
	} else {
		add("v2ray 服务运行中", "bad", "当前状态: "+kv["VCW_ACTIVE"])
		hints = append(hints, diagHint{Title: "v2ray 没有在运行",
			Advice: "查看下面的日志找到启动失败的原因；修正后点「同步配置」会重新启动服务。", Count: 1})
	}

	// 配置文件校验
	if rc, ok := kv["VCW_TEST_RC"]; ok {
		if rc == "0" {
			add("配置文件校验", "ok", "")
		} else {
			add("配置文件校验", "bad", strings.TrimSpace(strings.Join(test, "\n")))
			hints = append(hints, diagHint{Title: "节点上的配置文件无法通过校验",
				Advice: "检查该节点「配置项」里的自定义 JSON 后重新同步，或在「备份 / 恢复」里恢复到之前的配置。", Count: 1})
		}
	}

	// 端口监听：对照后台为该节点生成的配置
	cfg, want := configJSON(db, nodeID)
	listening := map[int]bool{}
	for _, l := range ports {
		for _, m := range listenPortRe.FindAllStringSubmatch(l+" ", -1) {
			p, _ := strconv.Atoi(m[1])
			listening[p] = true
		}
	}
	var missing []string
	for _, p := range want {
		if !listening[p] {
			missing = append(missing, strconv.Itoa(p))
		}
	}
	switch {
	case len(want) == 0:
		add("线路端口监听", "ok", "该节点目前不需要监听任何线路端口")
	case len(missing) == 0:
		add("线路端口监听", "ok", fmt.Sprintf("%v", want))
	default:
		add("线路端口监听", "bad", "未监听: "+strings.Join(missing, " "))
		if active {
			hints = append(hints, diagHint{Title: "线路端口没有在监听",
				Advice: "v2ray 在运行但没有监听应有的端口，通常是配置还没同步到节点，点「同步配置」。", Count: len(missing)})
		}
	}

	// 配置是否与后台一致
	if n.AppliedHash == configHash(cfg) {
		add("配置已同步", "ok", "")
	} else {
		add("配置已同步", "warn", "节点上的配置与后台当前数据不一致")
		hints = append(hints, diagHint{Title: "配置待同步",
			Advice: "后台里的线路 / 用户 / 出口有改动还没下发到这个节点，点「同步配置」。", Count: 1})
	}

	// 时间偏差：VMess 要求两端时间相差不超过 90 秒
	if ts, err := strconv.ParseInt(kv["VCW_NOW"], 10, 64); err == nil {
		off := ts - now.Unix()
		if off < 0 {
			off = -off
		}
		switch {
		case off <= 30:
			add("系统时间", "ok", fmt.Sprintf("与后台相差 %d 秒", off))
		case off <= 90:
			add("系统时间", "warn", fmt.Sprintf("与后台相差 %d 秒，接近 VMess 的 90 秒上限", off))
		default:
			add("系统时间", "bad", fmt.Sprintf("与后台相差 %d 秒", off))
			hints = append(hints, diagHint{Title: "节点时间不准",
				Advice: "VMess 要求各节点和客户端的时间相差不超过 90 秒。在节点上开启时间同步（timedatectl set-ntp true，或安装 chrony）。", Count: 1})
		}
	}

	// 日志里的常见错误
	found := map[int]*diagHint{}
	for _, l := range logs {
		for i, p := range logPatterns {
			if p.re.MatchString(l) {
				h := found[i]
				if h == nil {
					h = &diagHint{Title: p.title, Advice: p.advice}
					found[i] = h
				}
				h.Count++
				h.Sample = l // 保留最近的一条
				break
			}
		}
	}
	idx := make([]int, 0, len(found))
	for i := range found {
		idx = append(idx, i)
	}
	sort.Slice(idx, func(x, y int) bool { return found[idx[x]].Count > found[idx[y]].Count })
	for _, i := range idx {
		hints = append(hints, *found[i])
	}
	return result(logs, hints), nil
}

func (a *App) nodeDiagnose(w http.ResponseWriter, r *http.Request) (any, error) {
	lines, _ := strconv.Atoi(r.URL.Query().Get("lines"))
	if lines < 50 || lines > 2000 {
		lines = 200
	}
	return a.diagnoseNode(r.PathValue("id"), lines)
}
