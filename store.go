package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Node 是一台被管理的服务器。
type Node struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	SSHHost      string `json:"ssh_host"`
	SSHPort      int    `json:"ssh_port"`
	SSHUser      string `json:"ssh_user"`
	SSHPassword  string `json:"ssh_password,omitempty"`
	SSHKey       string `json:"ssh_key,omitempty"`
	JumpNodeID   string `json:"jump_node_id,omitempty"` // 经由哪个节点 SSH 跳转
	PublicAddr   string `json:"public_addr"`            // 公网地址（客户端 / 公网跳转使用）
	InternalAddr string `json:"internal_addr"`          // 内网地址（专线跳转使用）
	HostKey      string `json:"host_key,omitempty"`     // 首次连接时记录的 SSH 主机公钥

	Status        string    `json:"status"` // unknown / online / offline
	StatusMsg     string    `json:"status_msg"`
	V2rayVersion  string    `json:"v2ray_version"`
	ServiceActive bool      `json:"service_active"`
	CheckedAt     time.Time `json:"checked_at"`
	AppliedHash   string    `json:"applied_hash"`
	AppliedAt     time.Time `json:"applied_at"`

	Conf NodeConf `json:"conf"`
}

// NodeConf 是单个节点的 v2ray 配置项。
type NodeConf struct {
	LogLevel     string   `json:"log_level"`     // debug / info / warning / error / none，默认 warning
	DNS          []string `json:"dns"`           // 自定义 DNS 服务器，为空使用系统 DNS
	Sniffing     bool     `json:"sniffing"`      // 入站流量嗅探（http / tls）
	AllowPrivate bool     `json:"allow_private"` // 作为出口时允许访问私有地址段
	NoAccessLog  bool     `json:"no_access_log"` // 不写访问日志（默认每个连接记一条）
	Extra        string   `json:"extra"`         // 追加 / 覆盖的自定义 JSON
}

// Exit 是最终出口代理：线路最后一个节点把流量再转交给它（socks / http）。
type Exit struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"` // socks / http
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password,omitempty"`

	// UDP 处理方式：auto（默认，SOCKS5 且未检测出不支持时经代理转发）/ proxy（强制经代理）/ off（不经代理）。
	UDP          string    `json:"udp"`
	UDPStatus    string    `json:"udp_status"` // 最近一次检测结果：ok / fail / error / 空（未检测）
	UDPMsg       string    `json:"udp_msg"`
	UDPCheckedAt time.Time `json:"udp_checked_at"`
}

// udpViaProxy 返回该出口的 UDP 流量是否交给代理转发。HTTP 代理无法承载 UDP。
func (e *Exit) udpViaProxy() bool {
	if e.Protocol != "socks" {
		return false
	}
	switch e.UDP {
	case "proxy":
		return true
	case "off":
		return false
	}
	return e.UDPStatus != "fail"
}

// exitDirect 用在 User.ExitID 上，表示强制从线路末端节点直接出网。
const exitDirect = "direct"

// Hop 是线路中的一跳。Addr 表示「上一跳如何访问本跳」：public 或 internal。
type Hop struct {
	NodeID string `json:"node_id"`
	Addr   string `json:"addr"`
}

// Chain 是一条多跳线路：用户 -> Hops[0] -> Hops[1] -> ... -> 出口。
type Chain struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Port      int    `json:"port"` // 线路在每个节点上使用的端口
	Hops      []Hop  `json:"hops"`
	RelayUUID string `json:"relay_uuid"` // 节点之间互联使用的凭据
	ExitID    string `json:"exit_id"`    // 默认出口代理，为空表示从末端节点直接出网
	// 出口代理不转发 UDP 时，本线路上 UDP 的处理：block（默认，丢弃）/ direct（从末端节点直接出网）。
	UDPFallback string `json:"udp_fallback"`
}

// User 是一个代理账号。
type User struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	UUID     string   `json:"uuid"`
	SubToken string   `json:"sub_token"`
	Enabled  bool     `json:"enabled"`
	ChainIDs []string `json:"chain_ids"` // 为空表示可使用全部线路
	ExitID   string   `json:"exit_id"`   // 为空跟随线路；direct 表示末端节点直连；否则为指定出口代理

	// 限速（Mbit/s，0 表示不限）。限速用户在每条线路上使用专属端口：线路 ID -> 端口。
	LimitDown float64        `json:"limit_down"`
	LimitUp   float64        `json:"limit_up"`
	Ports     map[string]int `json:"ports,omitempty"`
	Remark    string         `json:"remark"`
	CreatedAt time.Time      `json:"created_at"`
}

type Admin struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
}

type Settings struct {
	DownloadURL string      `json:"download_url"`
	TLS         TLSSettings `json:"tls"`
}

const defaultDownloadURL = "https://github.com/v2fly/v2ray-core/releases/latest/download/v2ray-linux-{arch}.zip"

type DB struct {
	Admin    Admin    `json:"admin"`
	Settings Settings `json:"settings"`
	Nodes    []*Node  `json:"nodes"`
	Chains   []*Chain `json:"chains"`
	Exits    []*Exit  `json:"exits"`
	Users    []*User  `json:"users"`
}

// Store 把全部数据保存在一个 JSON 文件中（权限 0600）。
type Store struct {
	mu   sync.Mutex
	path string
	db   DB
}

func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dir, "data.json")}
	b, err := os.ReadFile(s.path)
	if err == nil {
		if err := json.Unmarshal(b, &s.db); err != nil {
			return nil, fmt.Errorf("解析 %s 失败: %w", s.path, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if s.db.Settings.DownloadURL == "" {
		s.db.Settings.DownloadURL = defaultDownloadURL
	}
	return s, nil
}

func (s *Store) saveLocked() error {
	b, err := json.MarshalIndent(&s.db, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Update 在持锁状态下修改数据并落盘；fn 返回错误时不保存。
func (s *Store) Update(fn func(db *DB) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fn(&s.db); err != nil {
		return err
	}
	ensureLimitPorts(&s.db)
	return s.saveLocked()
}

// View 在持锁状态下只读访问数据。
func (s *Store) View(fn func(db *DB)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.db)
}

// Snapshot 返回数据的深拷贝，供耗时操作在锁外使用。
func (s *Store) Snapshot() *DB {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _ := json.Marshal(&s.db)
	var out DB
	_ = json.Unmarshal(b, &out)
	return &out
}

func (db *DB) node(id string) *Node {
	for _, n := range db.Nodes {
		if n.ID == id {
			return n
		}
	}
	return nil
}

func (db *DB) chain(id string) *Chain {
	for _, c := range db.Chains {
		if c.ID == id {
			return c
		}
	}
	return nil
}

func (db *DB) exit(id string) *Exit {
	for _, e := range db.Exits {
		if e.ID == id {
			return e
		}
	}
	return nil
}

func (db *DB) user(id string) *User {
	for _, u := range db.Users {
		if u.ID == id {
			return u
		}
	}
	return nil
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func newUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
