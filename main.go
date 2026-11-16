// v2ray-chains-webui：通过 SSH 管理多台服务器上的 v2ray 及多跳线路的 Web 后台。
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	listen := flag.String("listen", ":8080", "监听地址")
	dataDir := flag.String("data", "./data", "数据目录")
	tlsCert := flag.String("tls-cert", "", "TLS 证书文件（可选）")
	tlsKey := flag.String("tls-key", "", "TLS 私钥文件（可选）")
	resetAdmin := flag.Bool("reset-admin", false, "重置管理员账号密码后退出（读取 ADMIN_USER / ADMIN_PASSWORD，未设置密码则随机生成）")
	flag.Parse()

	store, err := OpenStore(*dataDir)
	if err != nil {
		log.Fatalf("打开数据目录失败: %v", err)
	}

	// 首次启动（或 -reset-admin）时初始化管理员账号。
	var need bool
	store.View(func(db *DB) { need = db.Admin.PasswordHash == "" })
	if need || *resetAdmin {
		user, pw := os.Getenv("ADMIN_USER"), os.Getenv("ADMIN_PASSWORD")
		if user == "" {
			user = "admin"
		}
		generated := pw == ""
		if generated {
			pw = randHex(8)
		} else if len(pw) < 8 {
			log.Fatal("ADMIN_PASSWORD 至少 8 位")
		}
		if err := store.Update(func(db *DB) error {
			db.Admin = Admin{Username: user, PasswordHash: hashPassword(pw)}
			return nil
		}); err != nil {
			log.Fatalf("保存管理员账号失败: %v", err)
		}
		if generated {
			fmt.Printf("\n==== 管理员账号已初始化 ====\n  用户名: %s\n  密  码: %s\n  （仅显示这一次，请登录后在「设置」中修改）\n\n", user, pw)
		} else {
			log.Printf("管理员账号已设置为 %q", user)
		}
		if *resetAdmin {
			return
		}
	}

	app := &App{store: store, auth: newAuth(), tasks: &Tasks{}}
	srv := &http.Server{
		Addr:              *listen,
		Handler:           app.routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	if *tlsCert != "" {
		log.Printf("管理后台已启动: https://%s", *listen)
		log.Fatal(srv.ListenAndServeTLS(*tlsCert, *tlsKey))
	}
	log.Printf("管理后台已启动: http://%s （未启用 TLS，建议使用 -tls-cert/-tls-key 或置于 HTTPS 反向代理之后）", *listen)
	log.Fatal(srv.ListenAndServe())
}
