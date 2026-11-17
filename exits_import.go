package main

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// parseExitLine 解析批量导入中的一行，支持：
//
//	socks5://user:pass@host:port#名称   （协议可为 socks / socks5 / socks5h / http / https）
//	user:pass@host:port
//	host:port:user:pass
//	host:port
//
// 行尾可以用 # 或空白分隔一个名称；没有写协议的行使用 defProto。
func parseExitLine(line, defProto string) (*Exit, error) {
	e := &Exit{Protocol: defProto}
	// 名称：#后面的内容，或空白之后的内容。
	if i := strings.Index(line, "#"); i >= 0 {
		e.Name = strings.TrimSpace(line[i+1:])
		line = strings.TrimSpace(line[:i])
	} else if f := strings.Fields(line); len(f) > 1 {
		e.Name = strings.Join(f[1:], " ")
		line = f[0]
	}
	if scheme, rest, ok := strings.Cut(line, "://"); ok {
		switch strings.ToLower(scheme) {
		case "socks", "socks5", "socks5h":
			e.Protocol = "socks"
		case "http", "https":
			e.Protocol = "http"
		default:
			return nil, fmt.Errorf("不支持的协议 %s", scheme)
		}
		line = strings.TrimRight(rest, "/")
	}
	var hostport string
	if i := strings.LastIndex(line, "@"); i >= 0 {
		// user:pass@host:port（密码里可以有 @ 和 :）
		e.Username, e.Password, _ = strings.Cut(line[:i], ":")
		hostport = line[i+1:]
	} else {
		// host:port 或 host:port:user:pass（密码里可以有 :）
		p := strings.SplitN(line, ":", 4)
		if len(p) < 2 {
			return nil, fmt.Errorf("缺少端口")
		}
		hostport = p[0] + ":" + p[1]
		if len(p) > 2 {
			e.Username = p[2]
		}
		if len(p) > 3 {
			e.Password = p[3]
		}
	}
	host, port, ok := strings.Cut(hostport, ":")
	if !ok {
		return nil, fmt.Errorf("缺少端口")
	}
	e.Address = host
	e.Port, _ = strconv.Atoi(port)
	switch {
	case !addrRe.MatchString(e.Address) || strings.Contains(e.Address, ":"):
		return nil, fmt.Errorf("地址格式不正确")
	case e.Port < 1 || e.Port > 65535:
		return nil, fmt.Errorf("端口不正确")
	case e.Username == "" && e.Password != "":
		return nil, fmt.Errorf("有密码但没有用户名")
	}
	if e.Name == "" {
		e.Name = hostport
	}
	return e, nil
}

func exitKey(e *Exit) string {
	return fmt.Sprintf("%s|%s|%d|%s", e.Protocol, strings.ToLower(e.Address), e.Port, e.Username)
}

// importExits 批量导入出口代理：格式正确的行全部导入，已存在的跳过，有问题的行逐条报告。
func (a *App) importExits(w http.ResponseWriter, r *http.Request) (any, error) {
	var in struct {
		Text     string `json:"text"`
		Protocol string `json:"protocol"`
	}
	if err := readJSON(r, &in); err != nil {
		return nil, err
	}
	if in.Protocol != "socks" && in.Protocol != "http" {
		return nil, bad("默认协议只支持 socks 或 http")
	}
	var parsed []*Exit
	errs := []string{}
	for i, line := range strings.Split(in.Text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		e, err := parseExitLine(line, in.Protocol)
		if err != nil {
			errs = append(errs, fmt.Sprintf("第 %d 行：%v", i+1, err))
			continue
		}
		parsed = append(parsed, e)
	}
	if len(parsed) == 0 && len(errs) == 0 {
		return nil, bad("没有可导入的内容")
	}
	if len(parsed) > 2000 {
		return nil, bad("一次最多导入 2000 条")
	}
	added, skipped := 0, 0
	err := a.store.Update(func(db *DB) error {
		seen := map[string]bool{}
		for _, e := range db.Exits {
			seen[exitKey(e)] = true
		}
		for _, e := range parsed {
			if k := exitKey(e); seen[k] {
				skipped++
				continue
			} else {
				seen[k] = true
			}
			e.ID = randHex(4)
			db.Exits = append(db.Exits, e)
			added++
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return obj{"added": added, "skipped": skipped, "errors": errs}, nil
}
