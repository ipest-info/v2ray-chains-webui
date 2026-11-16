package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
)

type obj = map[string]any

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

// buildConfig 生成某个节点的完整 v2ray 配置，并返回需要放行的端口。
//
// 每条线路在入口节点上是一个面向用户的 VMess 入站（每个用户一个 UUID），
// 在中转 / 出口节点上是一个只接受上一跳的 VMess 入站（线路专用 UUID）；
// 非出口节点把该入站的流量路由到指向下一跳的 VMess 出站，出口节点直接放行。
func buildConfig(db *DB, nodeID string) (obj, []int) {
	inbounds := []any{}
	outbounds := []any{
		obj{"tag": "direct", "protocol": "freedom", "settings": obj{}},
		obj{"tag": "block", "protocol": "blackhole", "settings": obj{}},
	}
	rules := []any{}
	exitTags := []string{}
	ports := []int{}

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
		outTag := "out-" + c.ID

		clients := []any{}
		if idx == 0 {
			for _, u := range db.Users {
				if userAllowed(u, c.ID) {
					clients = append(clients, obj{"id": u.UUID, "alterId": 0, "email": u.Name})
				}
			}
			if len(clients) == 0 {
				continue // 没有可用用户时不开放入口
			}
		} else {
			clients = append(clients, obj{"id": c.RelayUUID, "alterId": 0, "email": "relay@" + c.ID})
		}
		inbounds = append(inbounds, obj{
			"tag":            inTag,
			"listen":         "0.0.0.0",
			"port":           c.Port,
			"protocol":       "vmess",
			"settings":       obj{"clients": clients},
			"streamSettings": obj{"network": "tcp"},
		})
		ports = append(ports, c.Port)

		if idx == len(c.Hops)-1 {
			exitTags = append(exitTags, inTag)
			rules = append(rules, obj{"type": "field", "inboundTag": []string{inTag}, "outboundTag": "direct"})
			continue
		}
		next := c.Hops[idx+1]
		nn := db.node(next.NodeID)
		if nn == nil {
			continue
		}
		outbounds = append(outbounds, obj{
			"tag":      outTag,
			"protocol": "vmess",
			"settings": obj{"vnext": []any{obj{
				"address": hopAddr(nn, next.Addr),
				"port":    c.Port,
				"users":   []any{obj{"id": c.RelayUUID, "alterId": 0, "security": "auto"}},
			}}},
			"streamSettings": obj{"network": "tcp"},
		})
		rules = append(rules, obj{"type": "field", "inboundTag": []string{inTag}, "outboundTag": outTag})
	}

	// 出口节点禁止用户访问节点本机及其内网。
	if len(exitTags) > 0 {
		rules = append([]any{obj{
			"type": "field", "inboundTag": exitTags, "ip": []string{"geoip:private"}, "outboundTag": "block",
		}}, rules...)
	}

	sort.Ints(ports)
	return obj{
		"log":       obj{"loglevel": "warning"},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"routing":   obj{"domainStrategy": "IPIfNonMatch", "rules": rules},
	}, ports
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
	b, _ := json.Marshal(obj{
		"v": "2", "ps": c.Name, "add": hopAddr(entry, "public"), "port": strconv.Itoa(c.Port),
		"id": u.UUID, "aid": "0", "scy": "auto", "net": "tcp", "type": "none", "host": "", "path": "", "tls": "",
	})
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
	return fmt.Sprintf("%s (%s)", c.Name, s)
}
