package main

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// 按用户限速。
//
// v2ray 本身不能按用户限速，这里在入口节点上用 Linux 的 tc 来做：
// 被限速的用户在每条线路上分配一个专属端口（入口节点上单独一个入站），
// tc 按端口匹配该用户的流量并用 police 动作限制速率。
// 同一用户的多个端口共用一个限速器，所以限速值是该用户在这个入口节点上的总速率。

const (
	limitPortBase = 30000 // 专属端口从这里开始分配
	limitPortMax  = 39999
)

func (u *User) limited() bool { return u.LimitDown > 0 || u.LimitUp > 0 }

// userPort 返回用户在某条线路入口上应使用的端口：限速用户用专属端口，其余用线路端口。
func userPort(u *User, c *Chain) int {
	if u.limited() {
		if p := u.Ports[c.ID]; p != 0 {
			return p
		}
	}
	return c.Port
}

// ensureLimitPorts 为限速用户在其可用的每条线路上分配专属端口。
// 端口一经分配就固定下来（取消限速后再次开启仍是原端口），线路删除后回收。
func ensureLimitPorts(db *DB) {
	used := map[int]bool{}
	for _, c := range db.Chains {
		used[c.Port] = true
	}
	for _, u := range db.Users {
		for cid, p := range u.Ports {
			if db.chain(cid) == nil {
				delete(u.Ports, cid)
			} else {
				used[p] = true
			}
		}
	}
	next := limitPortBase
	for _, u := range db.Users {
		if !u.limited() {
			continue
		}
		for _, c := range db.Chains {
			if u.Ports[c.ID] != 0 || (len(u.ChainIDs) > 0 && !contains(u.ChainIDs, c.ID)) {
				continue
			}
			for used[next] && next <= limitPortMax {
				next++
			}
			if next > limitPortMax {
				return
			}
			if u.Ports == nil {
				u.Ports = map[string]int{}
			}
			u.Ports[c.ID] = next
			used[next] = true
		}
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

type limitRule struct {
	Port     int
	DownKbit int // 0 = 不限
	UpKbit   int
	Index    int // 该用户限速器的编号（下行用 Index，上行用 Index+1）
}

// nodeLimits 返回需要在该节点（作为入口）上生效的限速规则。
func nodeLimits(db *DB, nodeID string) []limitRule {
	var rules []limitRule
	for ui, u := range db.Users {
		if !u.limited() {
			continue
		}
		for _, c := range db.Chains {
			if len(c.Hops) == 0 || c.Hops[0].NodeID != nodeID || !userAllowed(u, c.ID) || u.Ports[c.ID] == 0 {
				continue
			}
			rules = append(rules, limitRule{
				Port:     u.Ports[c.ID],
				DownKbit: int(math.Round(u.LimitDown * 1000)),
				UpKbit:   int(math.Round(u.LimitUp * 1000)),
				Index:    20000 + ui*2,
			})
		}
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].Port < rules[j].Port })
	return rules
}

// limitsScript 生成节点上的限速脚本。脚本每次先清掉自己加过的规则再重建；
// 以 `clear` 参数运行时只清除。只动自己使用的过滤器编号，不影响节点上已有的其它 tc 规则。
func limitsScript(rules []limitRule) string {
	var list []string
	for _, r := range rules {
		list = append(list, fmt.Sprintf("%d:%d:%d:%d", r.Port, r.DownKbit, r.UpKbit, r.Index))
	}
	return strings.ReplaceAll(limitsScriptTmpl, "@RULES@", strings.Join(list, " "))
}

const limitsScriptTmpl = `#!/bin/bash
# 由 v2ray-chains-webui 生成，请勿手工修改：每次同步配置都会覆盖。
# 规则格式：端口:下行kbit:上行kbit:限速器编号
RULES="@RULES@"
PREFS="20001 20002 20003"

ifaces() {
  for d in /sys/class/net/*; do
    n=${d##*/}
    case "$n" in lo|veth*|docker*|br-*|virbr*|cni*|flannel*|cali*|kube*|dummy*|tunl*|sit*|ip6tnl*|ifb*) continue;; esac
    echo "$n"
  done
}

command -v tc >/dev/null 2>&1 || {
  [ -z "$RULES" ] && exit 0
  echo "节点上没有 tc 命令（请安装 iproute2 / iproute-tc），无法限速"; exit 1
}

for dev in $(ifaces); do
  for p in $PREFS; do
    tc filter del dev "$dev" egress pref "$p" 2>/dev/null
    tc filter del dev "$dev" ingress pref "$p" 2>/dev/null
  done
done
[ "$1" = clear ] && { echo ">> 已清除限速规则"; exit 0; }
[ -z "$RULES" ] && exit 0

# add 网卡 方向(egress|ingress) 端口 速率kbit 限速器编号
# 下行（节点发给用户）匹配源端口，上行（用户发给节点）匹配目的端口。
add() {
  local dev=$1 dir=$2 port=$3 kbit=$4 idx=$5 key=src u32key=sport
  [ "$dir" = ingress ] && { key=dst; u32key=dport; }
  # 突发量取 0.25 秒的流量，且不小于 128KB；mtu 放大到 64KB，否则合并后的大包会被直接丢弃。
  local burst=$(( kbit * 1000 / 8 / 4 ))
  [ "$burst" -lt 131072 ] && burst=131072
  local act="action police index $idx rate ${kbit}kbit burst ${burst}b mtu 64kb conform-exceed drop"
  tc filter add dev "$dev" "$dir" pref 20001 protocol ip flower ip_proto tcp ${key}_port "$port" $act 2>/dev/null \
    || tc filter add dev "$dev" "$dir" pref 20003 protocol ip u32 match ip protocol 6 0xff match ip $u32key "$port" 0xffff $act \
    || return 1
  tc filter add dev "$dev" "$dir" pref 20002 protocol ipv6 flower ip_proto tcp ${key}_port "$port" $act 2>/dev/null
  return 0
}

fail=0
count=0
for dev in $(ifaces); do
  tc qdisc add dev "$dev" clsact 2>/dev/null   # 已存在时会报错，忽略
  for r in $RULES; do
    IFS=: read -r port down up idx <<< "$r"
    if [ "$down" -gt 0 ]; then add "$dev" egress "$port" "$down" "$idx" || fail=1; fi
    if [ "$up" -gt 0 ]; then add "$dev" ingress "$port" "$up" "$((idx + 1))" || fail=1; fi
    count=$((count + 1))
  done
done
if [ "$fail" != 0 ]; then
  echo "部分限速规则添加失败（内核可能缺少 cls_flower / cls_u32 / act_police 模块）"
  exit 1
fi
echo ">> 限速规则已生效：$(echo $RULES | wc -w) 个端口，网卡: $(ifaces | tr '\n' ' ')"
`

// nodeHash 是节点「已同步状态」的指纹：v2ray 配置 + 限速规则。
func nodeHash(db *DB, nodeID string) string {
	cfg, _ := configJSON(db, nodeID)
	return configHash(cfg + "\n" + limitsScript(nodeLimits(db, nodeID)))
}
