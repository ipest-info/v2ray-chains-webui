package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type obj = map[string]any

// statsAPIPort 是入口节点上 v2ray 统计接口监听的本机端口。
const statsAPIPort = 10085

// logDir 是节点上 v2ray 日志文件所在目录。
const logDir = "/var/log/v2ray"

// hopAddr 返回「上一跳访问该节点」时使用的地址。
func hopAddr(n *Node, kind string) string {
	if kind == "internal" && n.InternalAddr != "" {
		return n.InternalAddr
	}
	if n.PublicAddr != "" {
		return n.PublicAddr
	}
	return n.SSHHost
}

func userAllowed(u *User, chainID string) bool {
	if !u.Enabled {
		return false
	}
	if len(u.ChainIDs) == 0 {
		return true
	}
	for _, id := range u.ChainIDs {
		if id == chainID {
			return true
		}
	}
	return false
}

// userExit 返回用户在某条线路上实际使用的出口代理 ID，空串表示从末端节点直接出网。
func userExit(db *DB, u *User, c *Chain) string {
	e := u.ExitID
	if e == "" {
		e = c.ExitID
	}
	if e == exitDirect || db.exit(e) == nil {
		return ""
	}
	return e
}

func chainDefaultExit(db *DB, c *Chain) string {
	if db.exit(c.ExitID) == nil {
		return ""
	}
	return c.ExitID
}

// chainVariants 返回线路上正在使用的全部出口（默认出口排在最前），以及各出口对应的用户。
func chainVariants(db *DB, c *Chain) ([]string, map[string][]*User) {
	def := chainDefaultExit(db, c)
	users := map[string][]*User{}
	for _, u := range db.Users {
		if userAllowed(u, c.ID) {
			e := userExit(db, u, c)
			users[e] = append(users[e], u)
		}
	}
	var rest []string
	for e := range users {
		if e != def {
			rest = append(rest, e)
		}
	}
	sort.Strings(rest)
	return append([]string{def}, rest...), users
}

// relayID 返回线路上某个出口对应的节点互联凭据。
// 中转 / 出口节点看不到最初的用户，只能靠「上一跳用哪个凭据连进来」区分该走哪个出口。
func relayID(c *Chain, exitID string) (uuid, email string) {
	if exitID == "" {
		return c.RelayUUID, "relay@" + c.ID
	}
	h := sha256.Sum256([]byte(c.RelayUUID + "/" + exitID))
	b := h[:16]
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), "relay-" + exitID + "@" + c.ID
}

func exitOutbound(e *Exit) obj {
	server := obj{"address": e.Address, "port": e.Port}
	if e.Username != "" {
		server["users"] = []any{obj{"user": e.Username, "pass": e.Password}}
	}
	return obj{"tag": "exit-" + e.ID, "protocol": e.Protocol, "settings": obj{"servers": []any{server}}}
}

// buildConfig 生成某个节点的完整 v2ray 配置，并返回需要放行的端口。
//
// 每条线路在入口节点上是一个面向用户的 VMess 入站（每个用户一个 UUID），
// 在中转 / 出口节点上是一个只接受上一跳的 VMess 入站。线路上每个在用的出口
// 对应一个互联凭据：入口按用户选择凭据，后续节点按凭据选择下一跳或最终出口。
func buildConfig(db *DB, nodeID string) (obj, []int) {
	node := db.node(nodeID)
	if node == nil {
		node = &Node{}
	}
	conf := node.Conf
	inbounds := []any{}
	outbounds := []any{
		obj{"tag": "direct", "protocol": "freedom", "settings": obj{}},
		obj{"tag": "block", "protocol": "blackhole", "settings": obj{}},
	}
	rules := []any{}
	exitTags := []string{}
	ports := []int{}
	addedExit := map[string]bool{}

	for _, c := range db.Chains {
		idx := -1
		for i, h := range c.Hops {
			if h.NodeID == nodeID {
				idx = i
				break
			}
		}
		if idx < 0 {
			continue
		}
		inTag := "in-" + c.ID
		last := idx == len(c.Hops)-1
		variants, vusers := chainVariants(db, c)

		clients := []any{}
		var dedicated []*User // 限速用户：各自使用专属端口上的独立入站
		if idx == 0 {
			for _, v := range variants {
				for _, u := range vusers[v] {
					if userPort(u, c) != c.Port {
						dedicated = append(dedicated, u)
						continue
					}
					clients = append(clients, obj{"id": u.UUID, "alterId": 0, "email": u.Name})
				}
			}
			if len(clients) == 0 && len(dedicated) == 0 {
				continue // 没有可用用户时不开放入口
			}
		} else {
			for _, v := range variants {
				id, email := relayID(c, v)
				clients = append(clients, obj{"id": id, "alterId": 0, "email": email})
			}
		}
		inTags := []string{}
		addInbound := func(tag string, port int, clients []any) {
			in := obj{
				"tag":            tag,
				"listen":         "0.0.0.0",
				"port":           port,
				"protocol":       "vmess",
				"settings":       obj{"clients": clients},
				"streamSettings": inboundStream(c, node, idx == 0),
			}
			if conf.Sniffing {
				in["sniffing"] = obj{"enabled": true, "destOverride": []string{"http", "tls"}}
			}
			inbounds = append(inbounds, in)
			ports = append(ports, port)
			inTags = append(inTags, tag)
		}
		if len(clients) > 0 {
			addInbound(inTag, c.Port, clients)
		}
		for _, u := range dedicated {
			addInbound(inTag+"-"+u.ID, userPort(u, c), []any{obj{"id": u.UUID, "alterId": 0, "email": u.Name}})
		}
		if last {
			exitTags = append(exitTags, inTags...)
		}

		var nn *Node
		if !last {
			if nn = db.node(c.Hops[idx+1].NodeID); nn == nil {
				continue
			}
		}
		// 默认出口（variants[0]）作为兜底规则放在最后，其余出口按用户 / 凭据匹配。
		for i := len(variants) - 1; i >= 0; i-- {
			v := variants[i]
			var outTag, udpTag string
			if last {
				outTag = "direct"
				if e := db.exit(v); e != nil {
					outTag = "exit-" + e.ID
					// 代理不转发 UDP 时，UDP 单独处理：丢弃，或改从本节点直接出网。
					if !e.udpViaProxy() {
						udpTag = "block"
						if c.UDPFallback == "direct" {
							udpTag = "direct"
						}
					}
					if !addedExit[e.ID] {
						addedExit[e.ID] = true
						outbounds = append(outbounds, exitOutbound(e))
					}
				}
			} else {
				outTag = "out-" + c.ID
				if v != "" {
					outTag += "-" + v
				}
				id, _ := relayID(c, v)
				outbounds = append(outbounds, obj{
					"tag":      outTag,
					"protocol": "vmess",
					"settings": obj{"vnext": []any{obj{
						"address": hopAddr(nn, c.Hops[idx+1].Addr),
						"port":    c.Port,
						"users":   []any{obj{"id": id, "alterId": 0, "security": "auto"}},
					}}},
					"streamSettings": outboundStream(c),
				})
			}
			rule := obj{"type": "field", "inboundTag": inTags, "outboundTag": outTag}
			if i > 0 {
				emails := []string{}
				if idx == 0 {
					for _, u := range vusers[v] {
						emails = append(emails, u.Name)
					}
				} else {
					_, email := relayID(c, v)
					emails = append(emails, email)
				}
				rule["user"] = emails
			}
			if udpTag != "" {
				udpRule := obj{"type": "field", "inboundTag": inTags, "network": "udp", "outboundTag": udpTag}
				if us, ok := rule["user"]; ok {
					udpRule["user"] = us
				}
				rules = append(rules, udpRule)
			}
			rules = append(rules, rule)
		}
	}

	// 出口节点默认禁止用户访问节点本机及其内网。
	if len(exitTags) > 0 && !conf.AllowPrivate {
		rules = append([]any{obj{
			"type": "field", "inboundTag": exitTags, "ip": []string{"geoip:private"}, "outboundTag": "block",
		}}, rules...)
	}

	sort.Ints(ports)
	// 入口节点开启按用户的流量统计，供带宽监控读取（只监听本机回环地址）。
	stats := false
	for _, c := range db.Chains {
		if len(c.Hops) > 0 && c.Hops[0].NodeID == nodeID && len(inbounds) > 0 {
			stats = true
		}
	}
	if stats {
		inbounds = append(inbounds, obj{
			"tag": "api", "listen": "127.0.0.1", "port": statsAPIPort, "protocol": "dokodemo-door",
			"settings": obj{"address": "127.0.0.1"},
		})
		rules = append([]any{obj{"type": "field", "inboundTag": []string{"api"}, "outboundTag": "api"}}, rules...)
	}
	// 日志写到节点本地文件。访问日志每个连接一条，可在节点配置项里关闭。
	accessLog := logDir + "/access.log"
	if conf.NoAccessLog {
		accessLog = "none"
	}
	level := conf.LogLevel
	if level == "" {
		level = "warning"
	}
	cfg := obj{
		"log":       obj{"loglevel": level, "error": logDir + "/error.log", "access": accessLog},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"routing":   obj{"domainStrategy": "IPIfNonMatch", "rules": rules},
	}
	if stats {
		cfg["stats"] = obj{}
		cfg["api"] = obj{"tag": "api", "services": []string{"StatsService"}}
		cfg["policy"] = obj{"levels": obj{"0": obj{"statsUserUplink": true, "statsUserDownlink": true}}}
	}
	if len(conf.DNS) > 0 {
		cfg["dns"] = obj{"servers": conf.DNS}
	}
	mergeExtra(cfg, conf.Extra)
	return cfg, ports
}

// parseExtra 校验节点的自定义 JSON。
func parseExtra(extra string) (obj, error) {
	if strings.TrimSpace(extra) == "" {
		return nil, nil
	}
	var x obj
	if err := json.Unmarshal([]byte(extra), &x); err != nil {
		return nil, fmt.Errorf("不是合法的 JSON 对象: %w", err)
	}
	for _, k := range []string{"inbounds", "outbounds"} {
		if v, ok := x[k]; ok {
			if _, ok := v.([]any); !ok {
				return nil, fmt.Errorf("%s 必须是数组", k)
			}
		}
	}
	if v, ok := x["routing"]; ok {
		r, ok := v.(obj)
		if !ok {
			return nil, fmt.Errorf("routing 必须是对象")
		}
		if rs, ok := r["rules"]; ok {
			if _, ok := rs.([]any); !ok {
				return nil, fmt.Errorf("routing.rules 必须是数组")
			}
		}
	}
	return x, nil
}

// mergeExtra 把自定义 JSON 合并进生成的配置：
// inbounds / outbounds 追加在后面，routing.rules 插在最前面（优先匹配），其余顶层字段直接覆盖。
func mergeExtra(cfg obj, extra string) {
	x, err := parseExtra(extra)
	if err != nil || x == nil {
		return
	}
	for k, v := range x {
		switch k {
		case "inbounds", "outbounds":
			cfg[k] = append(cfg[k].([]any), v.([]any)...)
		case "routing":
			routing := cfg["routing"].(obj)
			for rk, rv := range v.(obj) {
				if rk == "rules" {
					routing["rules"] = append(append([]any{}, rv.([]any)...), routing["rules"].([]any)...)
				} else {
					routing[rk] = rv
				}
			}
		default:
			cfg[k] = v
		}
	}
}

func configJSON(db *DB, nodeID string) (string, []int) {
	cfg, ports := buildConfig(db, nodeID)
	b, _ := json.MarshalIndent(cfg, "", "  ")
	return string(b), ports
}

func configHash(cfg string) string {
	h := sha256.Sum256([]byte(cfg))
	return hex.EncodeToString(h[:8])
}

// vmessLink 生成用户在某条线路上的 vmess:// 分享链接。
func vmessLink(db *DB, u *User, c *Chain) string {
	if len(c.Hops) == 0 {
		return ""
	}
	entry := db.node(c.Hops[0].NodeID)
	if entry == nil {
		return ""
	}
	link := obj{
		"v": "2", "ps": c.Name, "add": hopAddr(entry, "public"), "port": strconv.Itoa(userPort(u, c)),
		"id": u.UUID, "aid": "0", "scy": "auto", "net": "tcp", "type": "none", "host": "", "path": "", "tls": "",
	}
	switch c.transport() {
	case "ws":
		link["net"], link["path"] = "ws", c.WSPath
	case "wstls":
		// 客户端必须用域名连接，证书才能通过校验。
		link["net"], link["path"], link["tls"] = "ws", c.WSPath, "tls"
		link["add"], link["host"], link["sni"] = entry.TLSDomain, entry.TLSDomain, entry.TLSDomain
	}
	b, _ := json.Marshal(link)
	return "vmess://" + base64.StdEncoding.EncodeToString(b)
}

func chainPath(db *DB, c *Chain) string {
	s := ""
	for i, h := range c.Hops {
		name := "?"
		if n := db.node(h.NodeID); n != nil {
			name = n.Name
		}
		if i > 0 {
			s += " → "
		}
		s += name
	}
	if e := db.exit(c.ExitID); e != nil {
		s += " → " + e.Name
	}
	return fmt.Sprintf("%s (%s)", c.Name, s)
}
