package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// UDP 检测的做法：在线路末端节点（实际去连代理的那台机器）上临时起一个 v2ray，
// 把本机的几个端口经该 SOCKS5 代理转发到公共 DNS，然后分别用 TCP 和 UDP 各发一次 DNS 查询。
// TCP 通而 UDP 不通 = 代理不支持 UDP；TCP 也不通 = 代理本身连不上，无法判断。
// 这与正式配置里使用的是同一个 v2ray、同一种出站，结果与实际转发行为一致。
const udpTestScript = `
V=/usr/local/bin/v2ray
[ -x "$V" ] || { echo "VCW_ERR=noinstall"; exit 0; }
export V2RAY_LOCATION_ASSET=/usr/local/share/v2ray
umask 077
D=$(mktemp -d)
cat > "$D/c.json" <<'VCW_CONFIG_EOF'
@CONFIG@
VCW_CONFIG_EOF
"$V" run -c "$D/c.json" > "$D/log" 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null; rm -rf "$D"' EXIT
sleep 2
kill -0 $PID 2>/dev/null || { echo "VCW_ERR=v2ray"; tail -n 5 "$D/log"; exit 0; }
# DNS 查询 example.com A，事务 ID 0x1234
Q='\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
tcp() { ( exec 3<>/dev/tcp/127.0.0.1/$1 || exit 1; printf '\x00\x1d'"$Q" >&3
  r=$(timeout 8 dd bs=1 count=4 <&3 2>/dev/null | od -An -tx1 | tr -d ' \n'); [ "$r" != "${r%1234}" ] ) 2>/dev/null; }
udp() { ( exec 3<>/dev/udp/127.0.0.1/$1 || exit 1; printf "$Q" >&3
  r=$(timeout 5 dd bs=512 count=1 <&3 2>/dev/null | od -An -tx1 | tr -d ' \n' | cut -c1-4); [ "$r" = 1234 ] ) 2>/dev/null; }
T=fail; U=fail
if tcp @P1@ || tcp @P2@; then T=ok; fi
if [ $T = ok ]; then if udp @P1@ || udp @P2@; then U=ok; fi; fi
echo "VCW_TCP=$T"
echo "VCW_UDP=$U"
`

func udpTestConfig(e *Exit, p1, p2 int) string {
	in := func(port int, dns string) obj {
		return obj{"listen": "127.0.0.1", "port": port, "protocol": "dokodemo-door",
			"settings": obj{"address": dns, "port": 53, "network": "tcp,udp"}}
	}
	out := exitOutbound(e)
	b, _ := json.MarshalIndent(obj{
		"log":       obj{"loglevel": "none"},
		"inbounds":  []any{in(p1, "8.8.8.8"), in(p2, "1.1.1.1")},
		"outbounds": []any{out},
	}, "", "  ")
	return string(b)
}

// udpTestOn 在一个已连接的节点上检测出口代理，返回 ok / fail / error 及说明。
func udpTestOn(conn *sshConn, n *Node, e *Exit) (status, msg string) {
	r, _ := rand.Int(rand.Reader, big.NewInt(20000))
	p1 := 30000 + int(r.Int64())
	script := strings.NewReplacer(
		"@CONFIG@", udpTestConfig(e, p1, p1+1),
		"@P1@", fmt.Sprint(p1), "@P2@", fmt.Sprint(p1+1),
	).Replace(udpTestScript)
	var buf bytes.Buffer
	if err := runRootScript(conn.Client, n, script, &buf, time.Minute); err != nil {
		return "error", "检测脚本执行失败: " + err.Error()
	}
	out := buf.String()
	switch {
	case strings.Contains(out, "VCW_ERR=noinstall"):
		return "error", "节点尚未安装 v2ray"
	case strings.Contains(out, "VCW_ERR=v2ray"):
		return "error", "临时 v2ray 启动失败"
	case !strings.Contains(out, "VCW_TCP=ok"):
		return "error", "经代理的 TCP 也不通（代理地址 / 账号有误，或节点连不上代理），无法判断 UDP"
	case strings.Contains(out, "VCW_UDP=ok"):
		return "ok", "支持 UDP"
	}
	return "fail", "TCP 正常但 UDP 不通，代理不支持 UDP"
}

// udpTest 检测若干出口代理的 UDP 支持情况。nodeIDs 为空时使用所有线路的末端节点。
func (a *App) udpTest(t *Task, exitIDs []string) error {
	db := a.store.Snapshot()
	var nodeIDs []string
	seen := map[string]bool{}
	for _, c := range db.Chains {
		if len(c.Hops) == 0 {
			continue
		}
		if id := c.Hops[len(c.Hops)-1].NodeID; !seen[id] {
			seen[id] = true
			nodeIDs = append(nodeIDs, id)
		}
	}
	if len(nodeIDs) == 0 {
		return errors.New("还没有线路。检测需要在线路的末端节点上进行，请先创建线路")
	}

	type result struct{ status, msg string }
	results := map[string][]result{} // 出口 ID -> 各节点的结果
	for _, nid := range nodeIDs {
		n := db.node(nid)
		t.logf("在末端节点「%s」上检测", n.Name)
		conn, _, err := a.connect(nid)
		if err != nil {
			t.logf("  无法连接节点: %v", err)
			for _, eid := range exitIDs {
				results[eid] = append(results[eid], result{"error", "「" + n.Name + "」SSH 连接失败"})
			}
			continue
		}
		for _, eid := range exitIDs {
			e := db.exit(eid)
			status, msg := udpTestOn(conn, n, e)
			t.logf("  %s (%s:%d)：%s", e.Name, e.Address, e.Port, msg)
			results[eid] = append(results[eid], result{status, "「" + n.Name + "」" + msg})
		}
		conn.Close()
	}

	// 汇总：任一节点明确测出不支持即判为不支持；全部支持才算支持；其余为无法判断。
	failed := 0
	err := a.store.Update(func(d *DB) error {
		for eid, rs := range results {
			e := d.exit(eid)
			if e == nil {
				continue
			}
			status, msgs := "ok", []string{}
			for _, r := range rs {
				msgs = append(msgs, r.msg)
				if r.status == "fail" {
					status = "fail"
				} else if r.status == "error" && status != "fail" {
					status = "error"
				}
			}
			if status != "ok" {
				failed++
			}
			e.UDPStatus, e.UDPMsg, e.UDPCheckedAt = status, strings.Join(msgs, "；"), time.Now()
		}
		return nil
	})
	if err != nil {
		return err
	}
	t.logf("共检测 %d 个出口代理，%d 个不支持 UDP 或无法判断", len(exitIDs), failed)
	t.logf("检测结果会影响「自动」模式下的 UDP 处理方式，请「同步全部配置」使其生效")
	return nil
}

// exitUDPTest 检测单个（带 id）或全部 SOCKS5 出口代理。
func (a *App) exitUDPTest(w http.ResponseWriter, r *http.Request) (any, error) {
	id := r.PathValue("id")
	var ids []string
	title := "检测全部出口代理的 UDP 支持"
	var err error
	a.store.View(func(db *DB) {
		if id != "" {
			e := db.exit(id)
			switch {
			case e == nil:
				err = errNotFound
			case e.Protocol != "socks":
				err = bad("HTTP 代理无法转发 UDP，不需要检测")
			default:
				ids, title = []string{id}, "检测 UDP 支持：「"+e.Name+"」"
			}
			return
		}
		for _, e := range db.Exits {
			if e.Protocol == "socks" {
				ids = append(ids, e.ID)
			}
		}
	})
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, bad("没有 SOCKS5 出口代理可检测")
	}
	t := a.tasks.Start(title, func(t *Task) error { return a.udpTest(t, ids) })
	return obj{"task_id": t.ID}, nil
}
