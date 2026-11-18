#!/usr/bin/env bash
# v2ray-chains-webui 一键安装 / 升级 / 卸载脚本
#
#   安装或升级到最新版：  bash install.sh
#   安装指定版本：        VERSION=v0.1.0 bash install.sh
#   卸载（保留数据）：    bash install.sh uninstall
#
# 可用的环境变量：
#   VERSION         要安装的版本，默认最新发布版
#   ADMIN_USER      首次安装时的管理员用户名，默认 admin
#   ADMIN_PASSWORD  首次安装时的管理员密码（至少 8 位），不设置则随机生成并显示一次
#   LISTEN          HTTP 监听地址，默认 :8080
#   HTTPS_LISTEN    HTTPS 监听地址，默认 :8443
#   INSTALL_DIR     安装目录，默认 /opt/v2ray-chains-webui
#   PKG             使用本地已下载的安装包（.tar.gz），不联网下载
#   GITHUB_PROXY    下载加速前缀，例如 https://ghproxy.example.com/ （访问 GitHub 困难时使用）
#   GITHUB_TOKEN    仓库为私有时用于下载的访问令牌
set -euo pipefail

REPO="ipest-info/v2ray-chains-webui"
NAME="v2ray-chains-webui"
INSTALL_DIR="${INSTALL_DIR:-/opt/$NAME}"
UNIT="/etc/systemd/system/$NAME.service"
LISTEN="${LISTEN:-:8080}"
HTTPS_LISTEN="${HTTPS_LISTEN:-:8443}"

info() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m错误：\033[0m%s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "请用 root 运行（或在命令前加 sudo）"
command -v systemctl >/dev/null 2>&1 || die "该系统没有 systemd，暂不支持"

if [ "${1:-}" = uninstall ]; then
  systemctl disable --now "$NAME" >/dev/null 2>&1 || true
  rm -f "$UNIT" "$INSTALL_DIR/$NAME"
  systemctl daemon-reload
  info "已卸载。数据仍保留在 $INSTALL_DIR/data（其中有各节点的 SSH 凭据），不再需要时请手动删除。"
  exit 0
fi

if [ -n "${ADMIN_PASSWORD:-}" ] && [ "${#ADMIN_PASSWORD}" -lt 8 ]; then
  die "ADMIN_PASSWORD 至少 8 位"
fi

case "$(uname -m)" in
  x86_64 | amd64) ARCH=amd64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  *) die "暂不支持的系统架构：$(uname -m)" ;;
esac
ASSET="${NAME}_linux_${ARCH}.tar.gz"

# 依赖：下载需要 curl / tar；后台申请证书（acme.sh）需要 curl / openssl
need() { command -v "$1" >/dev/null 2>&1; }
MISSING=""
for b in curl tar openssl; do need "$b" || MISSING="$MISSING $b"; done
if [ -n "$MISSING" ]; then
  info "安装依赖：$MISSING"
  if need apt-get; then apt-get update -y >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y $MISSING >/dev/null
  elif need dnf; then dnf install -y $MISSING >/dev/null
  elif need yum; then yum install -y $MISSING >/dev/null
  elif need apk; then apk add --no-cache $MISSING >/dev/null
  else die "无法自动安装$MISSING，请手动安装后重试"; fi
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# fetch <发布文件名> <保存路径>
fetch() {
  local file=$1 out=$2
  if [ -n "${GITHUB_TOKEN:-}" ]; then
    # 私有仓库：通过 API 找到文件再下载
    local rel="releases/latest"
    [ -n "${VERSION:-}" ] && rel="releases/tags/$VERSION"
    local id
    id=$(curl -fsSL -H "Authorization: Bearer $GITHUB_TOKEN" -H "Accept: application/vnd.github+json" \
      "https://api.github.com/repos/$REPO/$rel" | tr -d '\n' | sed 's/"uploader"/\n/g' |
      grep -o "\"id\": *[0-9]*, *\"node_id\": *\"[^\"]*\", *\"name\": *\"$file\"" | grep -o '"id": *[0-9]*' | grep -o '[0-9]*' | head -n1) || true
    [ -n "$id" ] || return 1
    curl -fsSL -H "Authorization: Bearer $GITHUB_TOKEN" -H "Accept: application/octet-stream" \
      -o "$out" "https://api.github.com/repos/$REPO/releases/assets/$id"
  else
    local url="https://github.com/$REPO/releases/latest/download/$file"
    [ -n "${VERSION:-}" ] && url="https://github.com/$REPO/releases/download/$VERSION/$file"
    curl -fsSL --connect-timeout 15 --retry 2 -o "$out" "${GITHUB_PROXY:-}$url"
  fi
}

if [ -n "${PKG:-}" ]; then
  [ -f "$PKG" ] || die "找不到安装包：$PKG"
  info "使用本地安装包 $PKG"
  cp "$PKG" "$TMP/$ASSET"
else
  info "下载 $ASSET（${VERSION:-最新版}）"
  fetch "$ASSET" "$TMP/$ASSET" || die "下载失败。访问 GitHub 困难时可设置 GITHUB_PROXY，或在别处下载安装包后用 PKG=/path/to/$ASSET 安装；仓库为私有时需要设置 GITHUB_TOKEN。"
  # 校验下载的文件与发布页公布的 SHA-256 一致
  fetch sha256sums.txt "$TMP/sha256sums.txt" || die "下载校验文件失败"
  WANT=$(awk -v f="$ASSET" '$2 == f || $2 == "*" f {print $1}' "$TMP/sha256sums.txt")
  GOT=$(sha256sum "$TMP/$ASSET" | awk '{print $1}')
  [ -n "$WANT" ] && [ "$WANT" = "$GOT" ] || die "安装包校验失败（SHA-256 不一致），已中止"
fi

tar -xzf "$TMP/$ASSET" -C "$TMP"
[ -f "$TMP/$NAME" ] || die "安装包内容不正确"
NEW_VERSION=$("$TMP/$NAME" -version 2>/dev/null || echo unknown)

UPGRADE=0
[ -f "$INSTALL_DIR/data/data.json" ] && UPGRADE=1

mkdir -p "$INSTALL_DIR/data"
chmod 700 "$INSTALL_DIR/data"
systemctl stop "$NAME" >/dev/null 2>&1 || true
install -m 755 "$TMP/$NAME" "$INSTALL_DIR/$NAME"

# 首次安装：初始化管理员账号。密码只在这里用一次，不写进服务文件。
if [ "$UPGRADE" = 0 ]; then
  ADMIN_USER="${ADMIN_USER:-admin}"
  GENERATED=0
  if [ -z "${ADMIN_PASSWORD:-}" ]; then
    ADMIN_PASSWORD=$(openssl rand -hex 8)
    GENERATED=1
  fi
  [ "${#ADMIN_PASSWORD}" -ge 8 ] || die "ADMIN_PASSWORD 至少 8 位"
  ADMIN_USER="$ADMIN_USER" ADMIN_PASSWORD="$ADMIN_PASSWORD" \
    "$INSTALL_DIR/$NAME" -data "$INSTALL_DIR/data" -reset-admin >/dev/null 2>&1 || die "初始化管理员账号失败"
fi

cat > "$UNIT" <<UNIT_EOF
[Unit]
Description=v2ray-chains-webui
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/$NAME -listen $LISTEN -https-listen $HTTPS_LISTEN -data $INSTALL_DIR/data
Restart=on-failure
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT_EOF
systemctl daemon-reload
systemctl enable "$NAME" >/dev/null 2>&1
systemctl restart "$NAME"
sleep 1
systemctl is-active --quiet "$NAME" || { journalctl -u "$NAME" -n 20 --no-pager 2>/dev/null || true; die "服务启动失败，请查看上面的日志"; }

PORT="${LISTEN##*:}"
echo
if [ "$UPGRADE" = 1 ]; then
  info "已升级到 $NEW_VERSION，数据和管理员账号保持不变。"
else
  info "安装完成（$NEW_VERSION）"
  echo "    访问地址：http://<本机公网 IP>:$PORT"
  echo "    管理员账号：$ADMIN_USER"
  if [ "$GENERATED" = 1 ]; then
    echo "    管理员密码：$ADMIN_PASSWORD   （随机生成，只显示这一次，请登录后在「设置」中修改）"
  else
    echo "    管理员密码：你通过 ADMIN_PASSWORD 设置的密码"
  fi
  echo
  echo "    请在安全组 / 防火墙中放行 $PORT 和 ${HTTPS_LISTEN##*:} 端口，并尽量只对固定 IP 开放。"
  echo "    登录后建议先在「设置」中配置域名和 HTTPS 证书。"
fi
echo "    服务管理：systemctl status|restart|stop $NAME"
echo "    数据目录：$INSTALL_DIR/data"
