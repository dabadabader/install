set -euo pipefail

VERSION='Proxy Installer v1.0'
# Github 反代加速代理，第一个为空相当于直连
GITHUB_PROXY=('' 'https://v6.gh-proxy.org/' 'https://gh-proxy.com/' 'https://hub.glowp.xyz/' 'https://proxy.vvvv.ee/' 'https://ghproxy.lvedong.eu.org/')
GH_PROXY=''
TEMP_DIR='/tmp/proxyinstaller'
WORK_DIR='/etc/sing-box'
LOG_DIR="${WORK_DIR}/logs"
CONF_DIR="${WORK_DIR}/conf"
DEFAULT_PORT_REALITY=443
DEFAULT_PORT_WS=2080
DEFAULT_PORT_SS=8388
TLS_SERVER_DEFAULT='addons.mozilla.org'
DEFAULT_NEWEST_VERSION='1.13.0-rc.4'
export DEBIAN_FRONTEND=noninteractive

trap 'rm -rf "$TEMP_DIR" >/dev/null 2>&1 || true' EXIT
mkdir -p "$TEMP_DIR" "$WORK_DIR" "$CONF_DIR" "$LOG_DIR"

# ---------- 彩色输出 ----------
ok()     { echo -e "\033[32m\033[01m$*\033[0m"; }
warn()   { echo -e "\033[33m\033[01m$*\033[0m"; }
err()    { echo -e "\033[31m\033[01m$*\033[0m" >&2; }

# ---------- 颜色变量 ----------
ESC=$(printf '\033')
YELLOW="${ESC}[33m"
GREEN="${ESC}[32m"
RED="${ESC}[31m"
RESET="${ESC}[0m"
die()    { err "$*"; exit 1; }

# ---------- 基础检测 ----------
need_root() { [ "$(id -u)" -eq 0 ] || die "请使用 root 运行。"; }

detect_arch() {
  case "$(uname -m)" in
    aarch64|arm64)  SB_ARCH=arm64 ;;
    x86_64|amd64)   SB_ARCH=amd64 ;;
    armv7l)         SB_ARCH=armv7 ;;
    *) die "不支持的架构: $(uname -m)" ;;
  esac
}

detect_os() {
  local pretty=""
  [ -s /etc/os-release ] && pretty="$(. /etc/os-release; echo "$PRETTY_NAME")"
  case "$pretty" in
    *Debian*|*Ubuntu*)  OS_FAMILY="Debian"; PKG_INSTALL="apt -y install";;
    *CentOS*|*Rocky*|*Alma*|*Red\ Hat*) OS_FAMILY="CentOS"; PKG_INSTALL="yum -y install";;
    *Fedora*)           OS_FAMILY="Fedora"; PKG_INSTALL="dnf -y install";;
    *Alpine*)           OS_FAMILY="Alpine"; PKG_INSTALL="apk add --no-cache";;
    *Arch*)             OS_FAMILY="Arch";   PKG_INSTALL="pacman -S --noconfirm";;
    *) die "不支持的系统: $pretty" ;;
  esac
}

install_deps() {
  local deps=(wget curl jq tar openssl)
  for d in "${deps[@]}"; do
    if ! command -v "$d" >/dev/null 2>&1; then
      ok "安装依赖: $d"
      $PKG_INSTALL "$d" || die "安装 $d 失败"
    fi
  done
}

# 检测是否需要启用 Github CDN，如能直接连通，则不使用
check_cdn() {
  for PROXY_URL in "${GITHUB_PROXY[@]}"; do
    local PROXY_STATUS_CODE
    PROXY_STATUS_CODE=$(wget --server-response --spider --quiet --timeout=3 --tries=1 ${PROXY_URL}https://api.github.com/repos/SagerNet/sing-box/releases 2>&1 | awk '/HTTP\//{last_field = $2} END {print last_field}')
    [ "$PROXY_STATUS_CODE" = "200" ] && GH_PROXY="$PROXY_URL" && break
  done
}

# ---------- Github 版本 ----------
get_latest_version() {
  check_cdn
  # FORCE_VERSION 用于在 sing-box 某个主程序出现 bug 时，强制为指定版本，以防止运行出错
  local FORCE_VERSION
  FORCE_VERSION=$(wget --no-check-certificate --tries=2 --timeout=3 -qO- ${GH_PROXY}https://raw.githubusercontent.com/fscarmen/sing-box/refs/heads/main/force_version | sed 's/^[vV]//g; s/\r//g')
  if grep -q '.' <<< "$FORCE_VERSION"; then
    local RESULT_VERSION="$FORCE_VERSION"
  else
    # 先判断 github api 返回 http 状态码是否为 200，有时候 IP 会被限制，导致获取不到最新版本
    local API_RESPONSE
    API_RESPONSE=$(wget --no-check-certificate --server-response --tries=2 --timeout=3 -qO- "${GH_PROXY}https://api.github.com/repos/SagerNet/sing-box/releases" 2>&1 | grep -E '^[ ]+HTTP/|tag_name')
    if grep -q 'HTTP.* 200' <<< "$API_RESPONSE"; then
      local VERSION_LATEST
      VERSION_LATEST=$(awk -F '["v-]' '/tag_name/{print $5}' <<< "$API_RESPONSE" | sort -Vr | sed -n '1p')
      local RESULT_VERSION
      RESULT_VERSION=$(wget --no-check-certificate --tries=2 --timeout=3 -qO- ${GH_PROXY}https://api.github.com/repos/SagerNet/sing-box/releases | awk -F '["v]' -v var="tag_name.*$VERSION_LATEST" '$0 ~ var {print $5; exit}')
    else
      local RESULT_VERSION="$DEFAULT_NEWEST_VERSION"
    fi
  fi
  echo "$RESULT_VERSION"
}





ensure_singbox() {
  if [ -x "${WORK_DIR}/sing-box" ]; then
    # ok "sing-box 已存在。"
    return
  fi
  check_cdn
  local ver; ver=$(get_latest_version)
  ok "下载 sing-box v${ver} (${SB_ARCH}) ..."
  
  local official_url="https://github.com/SagerNet/sing-box/releases/download/v${ver}/sing-box-${ver}-linux-${SB_ARCH}.tar.gz"
  local tarball="${TEMP_DIR}/sing-box.tar.gz"
  
  # Try with proxy first, then direct from official
  if [ -n "$GH_PROXY" ]; then
    ok "尝试通过代理下载..."
    wget -q --timeout=30 --tries=2 -O "$tarball" "${GH_PROXY}${official_url}" || {
      warn "代理下载失败，尝试直接下载..."
      wget -q --timeout=30 --tries=2 -O "$tarball" "$official_url" || die "下载 sing-box 失败"
    }
  else
    wget -q --timeout=30 --tries=2 -O "$tarball" "$official_url" || die "下载 sing-box 失败"
  fi
  
  # Verify the file is not empty
  [ -s "$tarball" ] || die "下载的文件为空"
  
  # Extract
  tar xzf "$tarball" -C "$TEMP_DIR" || die "解压 sing-box 失败"
  mv "$TEMP_DIR/sing-box-${ver}-linux-${SB_ARCH}/sing-box" "$WORK_DIR/" || die "移动 sing-box 失败"
  chmod +x "${WORK_DIR}/sing-box"
  rm -f "$tarball"
}

ensure_qrencode() {
  command -v qrencode >/dev/null 2>&1 && return
  ok "正在安装二维码生成工具..."
  if command -v apt >/dev/null 2>&1; then
    apt update -y >/dev/null 2>&1
    apt install -y qrencode >/dev/null 2>&1 || warn "qrencode 安装失败，跳过二维码功能。"
  elif command -v yum >/dev/null 2>&1; then
    yum install -y qrencode >/dev/null 2>&1 || warn "qrencode 安装失败，跳过二维码功能。"
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache qrencode >/dev/null 2>&1 || warn "qrencode 安装失败，跳过二维码功能。"
  else
    warn "未识别的包管理器，请手动安装 qrencode。"
  fi
}



# ---------- systemd ----------
ensure_systemd_service() {
  if [ -f /etc/init.d/sing-box ] && ! command -v systemctl >/dev/null 2>&1; then
    # OpenRC 模式（Alpine）
    cat > /etc/init.d/sing-box <<'EOF'
#!/sbin/openrc-run
name="sing-box"
command="/etc/sing-box/sing-box"
command_args="run -c /etc/sing-box/config.json"
command_background="yes"
pidfile="/var/run/${RC_SVCNAME}.pid"
output_log="/etc/sing-box/logs/sing-box.log"
error_log="/etc/sing-box/logs/sing-box.log"
depend() { need net; after net; }
start_pre() { mkdir -p /etc/sing-box/logs /var/run; rm -f "$pidfile"; }
EOF
    chmod +x /etc/init.d/sing-box
    rc-update add sing-box default >/dev/null 2>&1 || true
  else
    # systemd
    cat > /etc/systemd/system/sing-box.service <<'EOF'
[Unit]
Description=Sing-box Service
After=network.target

[Service]
User=root
Type=simple
WorkingDirectory=/etc/sing-box
ExecStart=/etc/sing-box/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable sing-box >/dev/null 2>&1 || true
  fi
}

svc_restart() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl restart sing-box

    # 等待 systemctl 状态稳定
    sleep 1
    if ! systemctl is-active --quiet sing-box; then
        sleep 2
    fi

    systemctl is-active --quiet sing-box \
        && ok "服务已启动。" \
        || die "服务启动失败，查看日志：tail -n 200 ${LOG_DIR}/sing-box.log"

  else
    rc-service sing-box restart
  fi
}

auto_cleanup_old_configs() {
  # 保留的文件列表
  local keep=(
    "00_base.json"
    "10_vless_tcp_reality.json"
    "12_ss.json"
    "13_vmess_ws.json"
  )

  for f in "$CONF_DIR"/*.json; do
    base=$(basename "$f")
    skip=false
    for k in "${keep[@]}"; do
      [ "$base" = "$k" ] && skip=true
    done

    if [ "$skip" = false ]; then
      echo "清理旧文件: $base"
      rm -f "$f"
    fi
  done
}


merge_config() {
  local files=("$CONF_DIR"/*.json)

  # 生成基础配置文件（防止缺失）
  if [ ! -e "${files[0]}" ]; then
    cat > "${CONF_DIR}/00_base.json" <<EOF
{
  "log": {
    "disabled": false,
    "level": "info",
    "output": "${LOG_DIR}/sing-box.log",
    "timestamp": true
  },
  "dns": {
    "servers": [ { "type": "local" } ],
    "strategy": "prefer_ipv4"
  },
  "outbounds": [ { "type": "direct", "tag": "direct" } ]
}
EOF
  fi

  # --- Safe merge for jq 1.6 ---
  jq -s '
    def pickone(k): (map(select(type=="object" and has(k)) | .[k]) | last) // null;
    def catarr(k): (map(select(type=="object" and has(k)) | .[k]) | add) // [];
    {
      log: pickone("log"),
      dns: pickone("dns"),
      ntp: pickone("ntp"),
      outbounds: catarr("outbounds"),
      inbounds:  catarr("inbounds")
    }
  ' "$CONF_DIR"/*.json > "$WORK_DIR/config.json" || {
    echo "⚠️ jq merge failed, falling back to last good config"
  }

  # 校验 JSON 是否有效
  jq . "$WORK_DIR/config.json" >/dev/null 2>&1 || {
    echo "❌ merged config invalid; keeping last valid copy"
  }
}


# ---------- 公共输入 ----------
read_ip_default() {
  # Auto-detect public IP without asking user
  SERVER_IP=$(
  curl -s https://api.ipify.org ||
  curl -s https://ifconfig.me ||
  curl -s https://icanhazip.com ||
  echo "127.0.0.1"
)
  ok "检测到公网 IP: ${SERVER_IP}"
}

read_uuid() {
  # Auto-generate UUID silently
  UUID=$(cat /proc/sys/kernel/random/uuid)
  ok "已生成 UUID: ${UUID}"
}

read_port() {
  local hint="$1" def="$2"
  read -rp "$hint [按回车默认: $def]： " PORT
  PORT="${PORT:-$def}"
  [[ "$PORT" =~ ^[0-9]+$ ]] || die "端口必须为数字。"
  (( PORT>=100 && PORT<=65535 )) || die "端口必须在 100~65535。"
}

# ---------- 1) 安装 VLESS + TCP + Reality ----------
install_vless_tcp_reality() {
  rm -f "${CONF_DIR}/10_vless_tcp_reality.json" 

  ensure_singbox
  ensure_systemd_service
  merge_config
  

  ok "开始安装 VLESS + TCP + Reality 协议"
  read_ip_default
  read_uuid
  read -rp "Reality 域名（sni/握手域名）[按回车默认: ${TLS_SERVER_DEFAULT}]： " TLS_DOMAIN
  TLS_DOMAIN="${TLS_DOMAIN:-$TLS_SERVER_DEFAULT}"
  read_port "监听端口" "$DEFAULT_PORT_REALITY"
  enable_bbr

  # 生成密钥对
  local kp priv pub
  kp="$("${WORK_DIR}/sing-box" generate reality-keypair)"
  priv="$(awk '/PrivateKey/{print $NF}' <<<"$kp")"
  pub="$(awk '/PublicKey/{print $NF}' <<<"$kp")"
  echo "$priv" > "${CONF_DIR}/reality_private.key"
  echo "$pub"  > "${CONF_DIR}/reality_public.key"

  cat > "${CONF_DIR}/10_vless_tcp_reality.json" <<EOF
{
  "inbounds": [{
    "type": "vless",
    "tag": "vless-reality",
    "listen": "::",
    "listen_port": ${PORT},
    "users": [{ "uuid": "${UUID}" }],
    "tls": {
      "enabled": true,
      "server_name": "${TLS_DOMAIN}",
      "reality": {
        "enabled": true,
        "handshake": { "server": "${TLS_DOMAIN}", "server_port": 443 },
        "private_key": "${priv}",
        "short_id": [""]
      }
    }
  }]
}
EOF

  merge_config
  svc_restart

  ok "✅ VLESS + TCP + Reality 安装完成"


  ensure_qrencode
  link="vless://${UUID}@${SERVER_IP}:${PORT}?encryption=none&security=reality&sni=${TLS_DOMAIN}&fp=chrome&pbk=${pub}&type=tcp#VLESS-REALITY"
  clean_link=$(echo -n "$link" | tr -d '\r\n')
  echo "导入链接："
  echo "$clean_link"
  echo
  if command -v qrencode >/dev/null 2>&1; then
    qrencode -t ANSIUTF8 -m 1 -s 1 "$clean_link"
    echo
     echo -e "\033[32m\033[01m如果需要重新打开安装菜单，请输入：\033[0m\033[33mmenu\033[0m"
  echo
  else
    warn "未检测到 qrencode，无法生成二维码。"
  fi
}



# ---------- 2) 安装 VMESS + WS ----------
find_free_port() {
  local port="$1"
  while ss -tuln | grep -q ":$port "; do
    port=$((port+1))
  done
  echo "$port"
}


install_vmess_ws() {
  ok "开始安装 VMESS + WS协议"

  rm -f "${CONF_DIR}/13_vmess_ws.json"


  ensure_singbox
  ensure_systemd_service
  merge_config

  read_ip_default
  read_uuid
  read_port "监听端口" "$DEFAULT_PORT_WS"
  PORT=$(find_free_port "$PORT")  
  enable_bbr

  local path="/${UUID}-vmess"

  cat > "${CONF_DIR}/13_vmess_ws.json" <<EOF
{
  "inbounds": [
    {
       "type": "vmess",
      "tag": "vmess-ws",
      "listen": "::",
      "listen_port": ${PORT},
      "users": [
        { "uuid": "${UUID}" }
      ],
      "transport": {
        "type": "ws",
        "path": "${path}"
      }
    }
  ]
}
EOF

  merge_config
  svc_restart

  ok "✅ VMESS + WS 已安装完成"

  ensure_qrencode
  json=$(printf '{"v":"2","ps":"VMESS-WS","add":"%s","port":"%s","id":"%s","aid":"0","net":"ws","type":"none","host":"","path":"%s","tls":""}' \
        "$SERVER_IP" "$PORT" "$UUID" "$path")
  b64=$(echo -n "$json" | base64 -w0)

  link="vmess://${b64}"
  clean_link=$(echo -n "$link" | tr -d '\r\n')

  echo "导入链接："
  echo "$clean_link"

  echo
  if command -v qrencode >/dev/null 2>&1; then
    qrencode -t ANSIUTF8 -m 1 -s 1 "$clean_link"
    echo
     echo -e "\033[32m\033[01m如果需要重新打开安装菜单，请输入：\033[0m\033[33mmenu\033[0m"
  echo
  else
    warn "未检测到 qrencode，无法生成二维码。"
  fi
}


# ---------- 3) 安装 Shadowsocks（中转） ----------
install_shadowsocks() {
   rm -f "${CONF_DIR}/12_ss.json"  

  ensure_singbox
  ensure_systemd_service
  merge_config

  ok "开始安装 Shadowsocks"
  read_ip_default
   SS_PASS=$(cat /proc/sys/kernel/random/uuid)
  ok "已生成 Shadowsocks 密码: ${SS_PASS}"

  read_port "监听端口" "$DEFAULT_PORT_SS"
  enable_bbr
  local method="aes-128-gcm"

  cat > "${CONF_DIR}/12_ss.json" <<EOF
{
  "inbounds": [{
    "type": "shadowsocks",
    "tag": "shadowsocks",
    "listen": "::",
    "listen_port": ${PORT},
    "method": "${method}",
    "password": "${SS_PASS}"
  }]
}
EOF
  merge_config
  svc_restart
  ok "✅ Shadowsocks 已安装完成"

  ensure_qrencode
  local b64
  b64="$(printf '%s' "${method}:${SS_PASS}@${SERVER_IP}:${PORT}" | base64 | tr -d '\n')"
  link="ss://${b64}#Shadowsocks"
  clean_link=$(echo -n "$link" | tr -d '\r\n')

  echo "导入链接："
  echo "$clean_link"

  echo
  if command -v qrencode >/dev/null 2>&1; then
    qrencode -t ANSIUTF8 -m 1 -s 1 "$clean_link"
    echo
     echo -e "\033[32m\033[01m如果需要重新打开安装菜单，请输入：\033[0m\033[33mmenu\033[0m"
    echo
  else
    warn "未检测到 qrencode，无法生成二维码。"
  fi
}

# ---------- 5) 启用 BBR ----------
enable_bbr() {
  ok "启用 BBR..."
  modprobe tcp_bbr 2>/dev/null || true
  grep -q '^net.core.default_qdisc=fq' /etc/sysctl.conf || echo 'net.core.default_qdisc=fq' >> /etc/sysctl.conf
  grep -q '^net.ipv4.tcp_congestion_control=bbr' /etc/sysctl.conf || echo 'net.ipv4.tcp_congestion_control=bbr' >> /etc/sysctl.conf
  sysctl -p >/dev/null 2>&1 || true
  sysctl net.ipv4.tcp_congestion_control
  ok "BBR 处理完成。"
  echo
   echo -e "\033[32m\033[01m如果需要重新打开安装菜单，请输入：\033[0m\033[33mmenu\033[0m"
  echo
}

# （已取消交互）BBR 在安装步骤中自动启用

# ---------- 6) 修改端口 ----------
change_port() {
  echo "选择要修改端口的协议："
  echo "1) VLESS Reality"
  echo "2) VMESS WS"
  echo "3) Shadowsocks"
  read -rp "输入 1/2/3：" which
  case "$which" in
    1) file="${CONF_DIR}/10_vless_tcp_reality.json" ;;
    2) file="${CONF_DIR}/13_vmess_ws.json" ;;
    3) file="${CONF_DIR}/12_ss.json" ;;
    *) die "无效选择" ;;
  esac

  [ -f "$file" ] || die "未检测到对应协议配置，请先安装该协议。"

  read_port "新端口" "8081"

  jq --argjson p "$PORT" '(.. | objects | select(has("listen_port"))).listen_port = $p' \
    "$file" > "${file}.tmp"

  mv "${file}.tmp" "$file"
  merge_config
  svc_restart

  ok "端口已修改。"
  echo
  echo -e "\033[32m\033[01m如果需要重新打开安装菜单，请输入：\033[0m\033[33mmenu\033[0m"
  echo
}


# ---------- 7) 修改用户名/密码 ----------
change_user_cred() {
  echo "选择要修改凭据的协议："
  echo "1) VLESS（Reality + WS 会同时修改 UUID）"
  echo "2) Shadowsocks 密码"
  read -rp "输入 1/2：" which
  case "$which" in
    1)
      local f1="${CONF_DIR}/10_vless_tcp_reality.json"
      local f2="${CONF_DIR}/13_vmess_ws.json"
      read_uuid
      for f in "$f1" "$f2"; do
        [ -f "$f" ] || continue
        jq --arg u "$UUID" '(.. | objects | select(has("users")) | .users[]? | select(has("uuid"))).uuid = $u' "$f" > "${f}.tmp" && mv "${f}.tmp" "$f"
      done
      merge_config
      svc_restart
      ok "VLESS UUID 已修改。"
      echo
       echo -e "\033[32m\033[01m如果需要重新打开安装菜单，请输入：\033[0m\033[33mmenu\033[0m"
      echo
      ;;
    2)
      local f="${CONF_DIR}/12_ss.json"
      [ -f "$f" ] || die "未检测到 Shadowsocks 配置。"
      read -rp "新的 SS 密码：" newpass
      [ -n "$newpass" ] || die "密码不可为空。"
      jq --arg p "$newpass" '(.. | objects | select(has("password"))).password = $p' "$f" > "${f}.tmp" && mv "${f}.tmp" "$f"
      merge_config
      svc_restart
      ok "Shadowsocks 密码已修改。"
      echo
      echo -e "\033[32m\033[01m如果需要重新打开安装菜单，请输入：\033[0m\033[33mmenu\033[0m"
      echo
      ;;
    *) die "无效选择" ;;
  esac
}

# ---------- 8) 卸载 ----------
uninstall_all() {
  warn "即将卸载 sing-box 及其所有配置与服务文件。"
  read -rp "确认卸载？(y/N): " y
  [[ "${y,,}" == "y" ]] || { echo "已取消。"; return; }
  if command -v systemctl >/dev/null 2>&1; then
    systemctl stop sing-box 2>/dev/null || true
    systemctl disable sing-box 2>/dev/null || true
    rm -f /etc/systemd/system/sing-box.service
    systemctl daemon-reload || true
  else
    rc-service sing-box stop 2>/dev/null || true
    rc-update del sing-box default 2>/dev/null || true
    rm -f /etc/init.d/sing-box
  fi
  rm -rf "${WORK_DIR}"
  ok "已卸载完成。"
  
}

# ---------- 9) 查看已生成的链接 ----------
show_generated_links() {
  echo
  echo "=============================="
  echo " 已生成的链接与二维码"
  echo "=============================="
  echo
  ensure_qrencode
  local found_any=false

  # --- VLESS Reality ---
  local f1="${CONF_DIR}/10_vless_tcp_reality.json"
  if [ -f "$f1" ]; then
    found_any=true
    local uuid port sni pub server_ip
    uuid=$(jq -r '..|objects|select(has("users"))|.users[]?.uuid' "$f1" | head -n1)
    port=$(jq -r '..|objects|select(has("listen_port"))|.listen_port' "$f1" | head -n1)
    sni=$(jq -r '..|objects|select(has("server_name"))|.server_name' "$f1" | head -n1)
    pub=$(cat "${CONF_DIR}/reality_public.key" 2>/dev/null || echo "")
    server_ip=$(curl -s https://api.ip.sb/ip || echo "YOUR_IP")
    link="vless://${uuid}@${server_ip}:${port}?encryption=none&security=reality&sni=${sni}&fp=chrome&pbk=${pub}&type=tcp#VLESS-REALITY"

    echo "🔹 VLESS Reality"
    echo -e "${YELLOW}${link}${RESET}"
    echo
    if command -v qrencode >/dev/null 2>&1; then
      qrencode -t ANSIUTF8 -m 1 -s 1 "$link"
      echo
      echo -e "\033[32m\033[01m如果需要重新打开安装菜单，请输入：\033[0m\033[33mmenu\033[0m"
      echo
    else
      warn "未检测到 qrencode，无法生成二维码。"
    fi
  fi

  # --- VMESS WS ---
  local f2="${CONF_DIR}/13_vmess_ws.json"
  if [ -f "$f2" ]; then
    found_any=true
    local uuid port path server_ip
    uuid=$(jq -r '..|objects|select(has("users"))|.users[]?.uuid' "$f2" | head -n1)
    port=$(jq -r '..|objects|select(has("listen_port"))|.listen_port' "$f2" | head -n1)
    path=$(jq -r '..|objects|select(has("transport"))|.transport.path' "$f2" | head -n1)
    server_ip=$(curl -s https://api.ip.sb/ip || echo "YOUR_IP")
    
    # Generate VMESS link (not VLESS)
    local json b64
    json=$(printf '{"v":"2","ps":"VMESS-WS","add":"%s","port":"%s","id":"%s","aid":"0","net":"ws","type":"none","host":"","path":"%s","tls":""}' \
          "$server_ip" "$port" "$uuid" "$path")
    b64=$(echo -n "$json" | base64 -w0)
    link="vmess://${b64}"

    echo "🔹 VMESS WS"
    echo -e "${YELLOW}${link}${RESET}"
    echo
    if command -v qrencode >/dev/null 2>&1; then
      qrencode -t ANSIUTF8 -m 1 -s 1 "$link"
      echo
      echo -e "\033[32m\033[01m如果需要重新打开安装菜单，请输入：\033[0m\033[33mmenu\033[0m"
      echo
    else
      warn "未检测到 qrencode，无法生成二维码。"
    fi
  fi

  # --- Shadowsocks ---
  local f3="${CONF_DIR}/12_ss.json"
  if [ -f "$f3" ]; then
    found_any=true
    local pass port method server_ip b64
    pass=$(jq -r '..|objects|select(has("password"))|.password' "$f3" | head -n1)
    port=$(jq -r '..|objects|select(has("listen_port"))|.listen_port' "$f3" | head -n1)
    method=$(jq -r '..|objects|select(has("method"))|.method' "$f3" | head -n1)
    server_ip=$(curl -s https://api.ip.sb/ip || echo "YOUR_IP")
    b64=$(printf '%s' "${method}:${pass}@${server_ip}:${port}" | base64 | tr -d '\n')
    link="ss://${b64}#Shadowsocks"

    echo "🔹 Shadowsocks"
    echo -e "${YELLOW}${link}${RESET}"
    echo
    if command -v qrencode >/dev/null 2>&1; then
      qrencode -t ANSIUTF8 -m 1 -s 1 "$link"
      echo
      echo -e "\033[32m\033[01m如果需要重新打开安装菜单，请输入：\033[0m\033[33mmenu\033[0m"
      echo  
    else
      warn "未检测到 qrencode，无法生成二维码。"
    fi
  fi

  if [ "$found_any" = false ]; then
    warn "未检测到任何已安装的协议配置。"
  fi
}


# ---------- 快捷命令 ----------
install_shortcut() {
  local cmd_path="/usr/local/bin/menu11"

  # Create shortcut script
  cat > "$cmd_path" <<'EOF'
#!/usr/bin/env bash
bash <(curl -Ls https://raw.githubusercontent.com/dabadabader/install/testing/installer.sh)
EOF

  chmod +x "$cmd_path"

  # Show message clearly to user
  echo -e "\033[32m\033[01m❔重新打开测试安装菜单请输入：\033[0m\033[33mmenu11\033[0m"
}



# ---------- 主菜单 ----------
main_menu() {
  clear

  LINK="${ESC}]8;;https://wepc.au${ESC}\\${YELLOW}wepc.au${RESET}${ESC}]8;;${ESC}\\"
LINK_PINGIP="${ESC}]8;;https://pingip.cn${ESC}\\${YELLOW}pingip.cn${RESET}${ESC}]8;;${ESC}\\"


  echo -e "${YELLOW}┌─────────────────────────────────┐${RESET}"
  echo -e "${YELLOW}│${RESET}   ${LINK} | ${LINK} | ${LINK}   ${YELLOW}│"
  echo -e "${YELLOW}│${RESET}     ${GREEN}覆盖全球的TikTok服务商${RESET}      ${YELLOW}│"
  echo -e "${YELLOW}│${RESET}       ${GREEN}提供各国原生家宽IP${RESET}        ${YELLOW}│"
  echo -e "${YELLOW}└─────────────────────────────────┘${RESET}"        
echo -e "==================================="
echo -e "    ${GREEN}查询IP可以使用:${RESET}  ${LINK_PINGIP}"
echo -e "==================================="
echo
 echo -e "\033[1m\033[31m*******************************\033[0m"
  echo -e "\033[1m\033[31m          测试版            \033[0m"
  echo -e "\033[1m\033[31m*******************************\033[0m"
  echo
    echo "1) 安装 VLESS + TCP + Reality (直连选这里)"
  echo "2) 安装 VMESS + WS (软路由选这里)"
  echo "3) 安装 Shadowsocks (明文协议, IP容易被墙, 不建议使用)"
  echo "4) 启用 BBR 加速 (已自动启用)"
  echo "5) 修改端口"
  echo "6) 修改用户名/密码"
  echo "7) 卸载脚本"
  echo "8) 查看已生成的链接"
  echo "9) 退出"
  echo
  read -rp "请选择 [1-9]: " opt
  case "$opt" in
    1) install_vless_tcp_reality ;;
    2) install_vmess_ws ;;
    3) install_shadowsocks ;;
    4) enable_bbr ;;
    5) change_port ;;
    6) change_user_cred ;;
    7) uninstall_all ;;
    8) show_generated_links ;;
    9) exit 0 ;;
    *) echo "无效选择";;
  esac

}


# ---------- 引导 ----------
need_root
detect_arch
detect_os
install_deps
install_shortcut
auto_cleanup_old_configs
merge_config
main_menu


