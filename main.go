// v2ray-chains-webui：通过 SSH 管理多台服务器上的 v2ray 及多跳线路的 Web 后台。
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func main() {
	listen := flag.String("listen", ":8080", "监听地址")
	dataDir := flag.String("data", "./data", "数据目录")
	httpsListen := flag.String("https-listen", ":8443", "HTTPS 监听地址，使用后台里通过 acme.sh 申请的证书；留空则不启用")
	tlsCert := flag.String("tls-cert", "", "手动指定 TLS 证书文件（可选，指定后 -listen 直接提供 HTTPS，且不启用 -https-listen）")
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

	app := &App{
		store: store, auth: newAuth(), tasks: &Tasks{},
		dataDir: *dataDir, certs: &certManager{dir: filepath.Join(*dataDir, "tls")},
	}
	handler := app.routes()
	srv := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	if *tlsCert != "" {
		log.Printf("管理后台已启动: https://%s", *listen)
		log.Fatal(srv.ListenAndServeTLS(*tlsCert, *tlsKey))
	}

	// HTTPS 入口：证书由后台通过 acme.sh 申请，申请成功后立即生效，无需重启。
	if *httpsListen != "" {
		_, port, err := net.SplitHostPort(*httpsListen)
		if err != nil {
			log.Fatalf("-https-listen 格式不正确: %v", err)
		}
		app.httpsPort = port
		if err := app.certs.load(); err == nil {
			log.Printf("已加载证书: %v", app.certs.info().Domains)
		} else if !os.IsNotExist(err) {
			log.Printf("加载证书失败: %v", err)
		}
		ln, err := tls.Listen("tcp", *httpsListen, &tls.Config{
			GetCertificate: app.certs.getCertificate, MinVersion: tls.VersionTLS12,
		})
		if err != nil {
			log.Fatalf("监听 %s 失败: %v", *httpsListen, err)
		}
		httpsSrv := &http.Server{
			Handler: handler, ReadHeaderTimeout: 10 * time.Second,
			ErrorLog: log.New(io.Discard, "", 0), // 没有证书时的握手失败不刷日志
		}
		go func() { log.Fatal(httpsSrv.Serve(ln)) }()
		go app.renewLoop()
		log.Printf("HTTPS 入口: https://<域名>:%s （在「设置」中配置域名并申请证书后可用）", port)
		srv.Handler = app.redirectHTTPS(handler)
	}
	log.Printf("管理后台已启动: http://%s", *listen)
	log.Fatal(srv.ListenAndServe())
}
