#!/bin/bash
# ==============================================================
# Project: Xray-Auto Installer
# Author: ISFZY
# Repository: https://github.com/ISFZY/Xray-Auto
# Version: v0.3.1
# ==============================================================

# --- UI 样式定义 ---
# 基础色
C_RESET="\033[0m"
C_RED="\033[31m"; C_GREEN="\033[32m"; C_YELLOW="\033[33m"
C_BLUE="\033[34m"; C_CYAN="\033[36m"; C_GRAY="\033[90m"
C_WHITE="\033[37m"; C_BOLD="\033[1m"
# 状态图标
ICON_OK="${C_GREEN}✔${C_RESET}"
ICON_ERR="${C_RED}✖${C_RESET}"
ICON_WARN="${C_YELLOW}⚠${C_RESET}"
ICON_INFO="${C_CYAN}ℹ${C_RESET}"
ICON_GEAR="${C_CYAN}⚙${C_RESET}"
ICON_ROCKET="${C_GREEN}🚀${C_RESET}"

# --- 核心 UI 函数 ---

# 打印带边框的标题
print_title() {
    echo -e "\n${C_CYAN}╭── ${C_BOLD}$1 ${C_CYAN}────────────────────────────────────────${C_RESET}"
}

# 打印步骤信息
msg_info() { echo -e "${C_CYAN}│${C_RESET} ${ICON_INFO} $1"; }
msg_ok()   { echo -e "${C_CYAN}│${C_RESET} ${ICON_OK} $1"; }
msg_warn() { echo -e "${C_CYAN}│${C_RESET} ${ICON_WARN} $1"; }
msg_err()  { echo -e "${C_CYAN}│${C_RESET} ${ICON_ERR} $1"; }

# 静默执行命令 (隐藏杂乱日志，只在报错时显示)
# 用法: run_silent "显示的文字" "要执行的命令"
run_silent() {
    local text="$1"
    local cmd="$2"
    echo -ne "${C_CYAN}│${C_RESET} ${ICON_GEAR} ${text}..."
    
    # 创建临时日志文件
    local log_file=$(mktemp)
    
    if eval "$cmd" > "$log_file" 2>&1; then
        echo -e "\r${C_CYAN}│${C_RESET} ${ICON_OK} ${text}       "
        rm -f "$log_file"
        return 0
    else
        echo -e "\r${C_CYAN}│${C_RESET} ${ICON_ERR} ${text} ${C_RED}(Failed)${C_RESET}"
        echo -e "${C_RED}━━━━━━━━━━━━━━━━ ERROR LOG ━━━━━━━━━━━━━━━━${C_RESET}"
        cat "$log_file"
        echo -e "${C_RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
        rm -f "$log_file"
        exit 1
    fi
}

# 优化的倒计时组件
wait_input() {
    local prompt="$1"
    local default="$2"
    local seconds=10
    
    # 清空输入缓冲
    read -t 0.1 -n 10000 discard 2>/dev/null
    
    echo -ne "${C_CYAN}│${C_RESET}    👉 ${prompt} [默认: ${C_YELLOW}${default}${C_RESET}] "
    
    for ((i=seconds; i>0; i--)); do
        echo -ne "\r${C_CYAN}│${C_RESET}    👉 ${prompt} [默认: ${C_YELLOW}${default}${C_RESET}] (${i}s) "
        if read -t 1 -n 1 -s key; then
            # 如果按下了键 (不仅仅是回车，这里逻辑微调为按任意键暂停倒计时进入编辑，或按回车确认)
            # 简化逻辑：有输入就进入编辑模式，回车就默认
            if [[ -z "$key" ]]; then
                echo -e "\r${C_CYAN}│${C_RESET}    👉 ${prompt} [默认: ${C_YELLOW}${default}${C_RESET}] (已确认)  "
                return 0
            else
                echo -e "\r${C_CYAN}│${C_RESET}    ✏️  请输入新值: \c"
                return 1
            fi
        fi
    done
    echo -e "\r${C_CYAN}│${C_RESET}    👉 ${prompt} [默认: ${C_YELLOW}${default}${C_RESET}] (自动确认)"
    return 0
}

# --- 系统环境检查 ---
if [ ! -f /etc/debian_version ]; then
    echo -e "${C_RED}Error: 本脚本仅支持 Debian/Ubuntu 系统。${C_RESET}"
    exit 1
fi
if [[ $EUID -ne 0 ]]; then echo -e "${C_RED}Error: 请使用 root 权限运行。${C_RESET}"; exit 1; fi

clear
echo -e "${C_CYAN}╭────────────────────────────────────────────────────────────╮${C_RESET}"
echo -e "${C_CYAN}│${C_RESET}          ${ICON_ROCKET} ${C_BOLD}Xray-Auto Installer${C_RESET} ${C_GRAY}v0.4 (Zen Mode)${C_RESET}          ${C_CYAN}│${C_RESET}"
echo -e "${C_CYAN}╰────────────────────────────────────────────────────────────╯${C_RESET}"

# ==============================================================
# 1. 端口配置 (交互区)
# ==============================================================
print_title "Configuration Setup"

# 获取 SSH 默认值
SSH_Current=$(ss -tlnp | grep sshd | grep LISTEN | head -n 1 | awk '{print $4}' | sed 's/.*://')
DEF_SSH=${SSH_Current:-22}
DEF_VISION=443
DEF_XHTTP=8443

# SSH
if wait_input "SSH 端口" "$DEF_SSH"; then
    SSH_PORT=$DEF_SSH
else
    read U_SSH
    SSH_PORT=${U_SSH:-$DEF_SSH}
fi

# Vision
if wait_input "Vision 端口" "$DEF_VISION"; then
    PORT_VISION=$DEF_VISION
else
    read U_VISION
    PORT_VISION=${U_VISION:-$DEF_VISION}
fi

# XHTTP
if wait_input "xhttp 端口" "$DEF_XHTTP"; then
    PORT_XHTTP=$DEF_XHTTP
else
    read U_XHTTP
    PORT_XHTTP=${U_XHTTP:-$DEF_XHTTP}
fi

echo -e "${C_CYAN}│${C_RESET}"
msg_info "配置已锁定，准备执行安装..."

# ==============================================================
# 2. 系统安装 (静默执行)
# ==============================================================
print_title "System Installation"

# 基础环境修复
run_silent "检查并修复包管理器" "dpkg --configure -a"
run_silent "更新系统软件源" "apt-get update -qq"

# 安装依赖
DEPS="curl wget sudo nano git htop tar unzip socat fail2ban rsyslog chrony iptables qrencode iptables-persistent"
export DEBIAN_FRONTEND=noninteractive
run_silent "安装必要组件" "apt-get install -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' $DEPS"

# 设置时区
timedatectl set-timezone Asia/Shanghai

# 性能优化
if ! grep -q "tcp_congestion_control=bbr" /etc/sysctl.conf; then
    run_silent "启用 BBR 拥塞控制" "echo 'net.core.default_qdisc=fq' >> /etc/sysctl.conf && echo 'net.ipv4.tcp_congestion_control=bbr' >> /etc/sysctl.conf && sysctl -p"
else
    msg_ok "BBR 已启用"
fi

# Swap
if [ "$(free -m | grep Mem | awk '{print $2}')" -lt 2048 ] && [ "$(swapon --show | wc -l)" -lt 2 ]; then
    run_silent "创建 1GB Swap 分区" "fallocate -l 1G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile && echo '/swapfile none swap sw 0 0' >> /etc/fstab"
fi

# 安装 Xray
run_silent "下载并安装 Xray 核心" "bash -c \"\$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)\" @ install"
mkdir -p /usr/local/share/xray/
run_silent "更新 GeoIP/GeoSite 数据库" "wget -q -O /usr/local/share/xray/geoip.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat && wget -q -O /usr/local/share/xray/geosite.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"

# ==============================================================
# 3. 智能 SNI 优选
# ==============================================================
print_title "Smart SNI Selection"

DOMAINS=("www.icloud.com" "www.apple.com" "itunes.apple.com" "learn.microsoft.com" "www.microsoft.com" "www.bing.com" "www.tesla.com")
BEST_MS=9999
BEST_INDEX=0

msg_info "正在测试伪装域延迟..."
printf "${C_CYAN}│${C_RESET}   %-4s %-25s %-10s\n" "ID" "Domain" "Latency"
printf "${C_CYAN}│${C_RESET}   ${C_GRAY}───────────────────────────────────────${C_RESET}\n"

for i in "${!DOMAINS[@]}"; do
    domain="${DOMAINS[$i]}"
    # 连接测试
    time_cost=$(LC_NUMERIC=C curl -4 -w "%{time_connect}" -o /dev/null -s --connect-timeout 2 "https://$domain")
    
    ms="Timeout"
    ms_raw=9999
    
    if [ -n "$time_cost" ] && [ "$time_cost" != "0.000" ]; then
        ms_raw=$(LC_NUMERIC=C awk -v t="$time_cost" 'BEGIN { printf "%.0f", t * 1000 }')
        ms="${ms_raw}ms"
    fi
    
    # 打印行
    if [ "$ms" == "Timeout" ]; then
        printf "${C_CYAN}│${C_RESET}   %-4s %-25s ${C_RED}%-10s${C_RESET}\n" "$((i+1))" "$domain" "$ms"
    else
        # 最优，用绿色高亮
        if [ "$ms_raw" -lt "$BEST_MS" ]; then
            BEST_MS=$ms_raw
            BEST_INDEX=$((i+1))
            printf "${C_CYAN}│${C_RESET}   %-4s %-25s ${C_GREEN}%-10s${C_RESET}\n" "$((i+1))" "$domain" "$ms"
        else
            printf "${C_CYAN}│${C_RESET}   %-4s %-25s ${C_WHITE}%-10s${C_RESET}\n" "$((i+1))" "$domain" "$ms"
        fi
    fi
done

if [ "$BEST_MS" == "9999" ]; then BEST_INDEX=1; fi
DEFAULT_DOMAIN=${DOMAINS[$((BEST_INDEX-1))]}

echo -e "${C_CYAN}│${C_RESET}"
if wait_input "选择 SNI (推荐 ${BEST_INDEX})" "${BEST_INDEX}"; then
    SNI_HOST="$DEFAULT_DOMAIN"
else
    read SNI_CHOICE
    if [[ "$SNI_CHOICE" =~ ^[0-9]+$ ]] && [ "$SNI_CHOICE" -ge 1 ] && [ "$SNI_CHOICE" -le "${#DOMAINS[@]}" ]; then
        SNI_HOST="${DOMAINS[$((SNI_CHOICE-1))]}"
    else
        # 自定义或默认
        read -p "      请输入自定义域名: " CUSTOM_DOMAIN
        SNI_HOST="${CUSTOM_DOMAIN:-$DEFAULT_DOMAIN}"
    fi
fi
msg_ok "已选择 SNI: ${C_BLUE}${SNI_HOST}${C_RESET}"

# ==============================================================
# 4. 生成配置与服务
# ==============================================================
run_silent "生成 Xray 配置文件" "sleep 0.5" # UI 统一

# ... (变量生成逻辑保持不变)
XRAY_BIN="/usr/local/bin/xray"
UUID=$($XRAY_BIN uuid)
KEYS=$($XRAY_BIN x25519)
PRIVATE_KEY=$(echo "$KEYS" | grep "Private" | awk '{print $2}')
PUBLIC_KEY=$(echo "$KEYS" | grep -E "Public|Password" | awk '{print $2}')
SHORT_ID=$(openssl rand -hex 8)
XHTTP_PATH="/req"

# 写入 Config
mkdir -p /usr/local/etc/xray/
cat > /usr/local/etc/xray/config.json <<CONFIG_EOF
{
  "log": { "loglevel": "warning" },
  "dns": { "servers": [ "1.1.1.1", "8.8.8.8", "localhost" ] },
  "inbounds": [
    {
      "tag": "vision_node", "port": ${PORT_VISION}, "protocol": "vless",
      "settings": { "clients": [ { "id": "${UUID}", "flow": "xtls-rprx-vision" } ], "decryption": "none" },
      "streamSettings": { "network": "tcp", "security": "reality", "realitySettings": { "show": false, "dest": "${SNI_HOST}:443", "serverNames": [ "${SNI_HOST}" ], "privateKey": "${PRIVATE_KEY}", "shortIds": [ "${SHORT_ID}" ], "fingerprint": "chrome" } },
      "sniffing": { "enabled": true, "destOverride": [ "http", "tls", "quic" ], "routeOnly": true }
    },
    {
      "tag": "xhttp_node", "port": ${PORT_XHTTP}, "protocol": "vless",
      "settings": { "clients": [ { "id": "${UUID}", "flow": "" } ], "decryption": "none" },
      "streamSettings": { "network": "xhttp", "security": "reality", "xhttpSettings": { "path": "${XHTTP_PATH}" }, "realitySettings": { "show": false, "dest": "${SNI_HOST}:443", "serverNames": [ "${SNI_HOST}" ], "privateKey": "${PRIVATE_KEY}", "shortIds": [ "${SHORT_ID}" ], "fingerprint": "chrome" } },
      "sniffing": { "enabled": true, "destOverride": [ "http", "tls", "quic" ], "routeOnly": true }
    }
  ],
  "outbounds": [ { "protocol": "freedom", "tag": "direct" }, { "protocol": "blackhole", "tag": "block" } ],
  "routing": { "domainStrategy": "IPIfNonMatch", "rules": [ { "type": "field", "ip": [ "geoip:private", "geoip:cn" ], "outboundTag": "block" }, { "type": "field", "protocol": [ "bittorrent" ], "outboundTag": "block" } ] }
}
CONFIG_EOF

# Systemd 优化
mkdir -p /etc/systemd/system/xray.service.d
echo -e "[Service]\nLimitNOFILE=infinity\nLimitNPROC=infinity\nTasksMax=infinity\nRestart=on-failure\nRestartSec=5" > /etc/systemd/system/xray.service.d/override.conf
systemctl daemon-reload

# 防火墙设置
run_silent "配置防火墙规则 (iptables)" "sleep 1"
iptables -F
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -A INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT
[ "$SSH_PORT" != "22" ] && iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp -m multiport --dports ${PORT_VISION},${PORT_XHTTP} -j ACCEPT
iptables -A INPUT -p udp -m multiport --dports ${PORT_VISION},${PORT_XHTTP} -j ACCEPT
iptables -P INPUT DROP; iptables -P FORWARD DROP; iptables -P OUTPUT ACCEPT

if [ -f /proc/net/if_inet6 ]; then
    ip6tables -F >/dev/null 2>&1
    ip6tables -P INPUT ACCEPT; ip6tables -P FORWARD ACCEPT; ip6tables -P OUTPUT ACCEPT
fi
netfilter-persistent save >/dev/null 2>&1

# Fail2ban
cat > /etc/fail2ban/jail.local << FAIL2BAN_EOF
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
findtime  = 1d
maxretry = 3
bantime  = 24h
bantime.increment = true
backend = systemd
banaction = iptables-multiport
[sshd]
enabled = true
port    = $SSH_PORT,22
mode    = aggressive
FAIL2BAN_EOF
run_silent "启动安全服务 (Fail2ban)" "systemctl restart rsyslog && systemctl enable fail2ban && systemctl restart fail2ban"

# Mode 脚本
cp /usr/local/etc/xray/config.json /usr/local/etc/xray/config_block.json
sed 's/, "geoip:cn"//g' /usr/local/etc/xray/config_block.json > /usr/local/etc/xray/config_allow.json

cat > /usr/local/bin/mode << 'MODE_EOF'
#!/bin/bash
# ... (Simple Mode Switcher) ...
GREEN='\033[32m'; RED='\033[31m'; WHITE='\033[37m'; PLAIN='\033[0m'; BLUE='\033[36m'
CONFIG="/usr/local/etc/xray/config.json"
BLOCK_CFG="/usr/local/etc/xray/config_block.json"
ALLOW_CFG="/usr/local/etc/xray/config_allow.json"
clear
echo -e "${BLUE}╭── Mode Selection ────────────────────${PLAIN}"
if grep -q "geoip:cn" "$CONFIG"; then
    echo -e "${BLUE}│${PLAIN}  Current: ${GREEN}🔒 Block CN (阻断回国)${PLAIN}"
else
    echo -e "${BLUE}│${PLAIN}  Current: ${RED}🔓 Allow CN (允许回国)${PLAIN}"
fi
echo -e "${BLUE}├──────────────────────────────────────${PLAIN}"
echo -e "${BLUE}│${PLAIN}  1. Switch to Block CN"
echo -e "${BLUE}│${PLAIN}  2. Switch to Allow CN"
echo -e "${BLUE}╰──────────────────────────────────────${PLAIN}"
read -p "Select [1/2]: " choice
case "$choice" in 
    1) cp "$BLOCK_CFG" "$CONFIG"; systemctl restart xray; echo "✅ Mode set to Block CN"; ;; 
    2) cp "$ALLOW_CFG" "$CONFIG"; systemctl restart xray; echo "✅ Mode set to Allow CN"; ;; 
    *) echo "Exit."; ;; 
esac
MODE_EOF
chmod +x /usr/local/bin/mode

# 启动
systemctl enable xray >/dev/null 2>&1
systemctl restart xray

# ==============================================================
# 5. 生成最终 Info 展示
# ==============================================================
cat > /usr/local/bin/info <<EOF
#!/bin/bash
C_RESET="\033[0m"; C_TITLE="\033[1;36m"; C_LABEL="\033[0;37m"; C_VALUE="\033[1;37m"
C_ACCENT="\033[0;34m"; C_LINK="\033[4;32m"
UUID="${UUID}"; PUBLIC_KEY="${PUBLIC_KEY}"; SHORT_ID="${SHORT_ID}"; SNI_HOST="${SNI_HOST}"
XHTTP_PATH="${XHTTP_PATH}"; SSH_PORT="${SSH_PORT}"; PORT_VISION="${PORT_VISION}"; PORT_XHTTP="${PORT_XHTTP}"
IPV4=\$(curl -s4m 2 https://1.1.1.1/cdn-cgi/trace | grep "ip=" | cut -d= -f2)
[ -z "\$IPV4" ] && IPV4=\$(curl -s4m 2 https://api.ipify.org)
HOST_TAG=\$(hostname | tr ' ' '.')
[ -z "\$HOST_TAG" ] && HOST_TAG="XrayServer"
LINK_VISION="vless://\${UUID}@\${IPV4}:\${PORT_VISION}?security=reality&encryption=none&pbk=\${PUBLIC_KEY}&headerType=none&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=\${SNI_HOST}&sid=\${SHORT_ID}#\${HOST_TAG}_Vision"
LINK_XHTTP="vless://\${UUID}@\${IPV4}:\${PORT_XHTTP}?security=reality&encryption=none&pbk=\${PUBLIC_KEY}&headerType=none&fp=chrome&type=xhttp&path=\${XHTTP_PATH}&sni=\${SNI_HOST}&sid=\${SHORT_ID}#\${HOST_TAG}_xhttp"

clear
print_line() { printf "\${C_ACCENT}│\${C_RESET} %-16s : %b\n" "\$1" "\$2"; }
print_sep()  { printf "\${C_ACCENT}├────────────────────────────────────────────────────────────\${C_RESET}\n"; }

echo -e "\${C_ACCENT}╭── \${C_TITLE}Xray Configuration Summary\${C_ACCENT} ─────────────────────────────\${C_RESET}"
printf "\${C_ACCENT}│\${C_RESET}\n"
print_line "Server IP"    "\${C_VALUE}\${IPV4}\${C_RESET}"
print_line "SNI Domain"   "\${C_VALUE}\${SNI_HOST}\${C_RESET}"
print_line "SSH Port"     "\${C_VALUE}\${SSH_PORT}\${C_RESET}"
print_sep
print_line "UUID"         "\${C_VALUE}\${UUID}\${C_RESET}"
print_line "Public Key"   "\${C_VALUE}\${PUBLIC_KEY}\${C_RESET}"
print_line "Short ID"     "\${C_VALUE}\${SHORT_ID}\${C_RESET}"
print_sep
printf "\${C_ACCENT}│\${C_RESET} \${C_TITLE}Node Details\${C_RESET}\n"
printf "\${C_ACCENT}│\${C_RESET}  %-8s | %-8s | %-15s | %-10s\n" "Type" "Port" "Protocol" "Path/Flow"
printf "\${C_ACCENT}│\${C_RESET}  \${C_ACCENT}---------+----------+-----------------+-----------\${C_RESET}\n"
printf "\${C_ACCENT}│\${C_RESET}  %-8s | \${C_VALUE}%-8s\${C_RESET} | %-15s | %-10s\n" "Vision" "\${PORT_VISION}" "TCP/Reality" "xtls-vision"
printf "\${C_ACCENT}│\${C_RESET}  %-8s | \${C_VALUE}%-8s\${C_RESET} | %-15s | %-10s\n" "xhttp" "\${PORT_XHTTP}" "xhttp/Reality" "\${XHTTP_PATH}"
printf "\${C_ACCENT}│\${C_RESET}\n"
echo -e "\${C_ACCENT}╰────────────────────────────────────────────────────────────\${C_RESET}"
echo ""
echo -e "\${C_TITLE}⚡ Connection Links\${C_RESET}"
echo -e "  \${C_ACCENT}•\${C_RESET} Vision : \${C_LINK}\${LINK_VISION}\${C_RESET}"
echo -e "  \${C_ACCENT}•\${C_RESET} xhttp  : \${C_LINK}\${LINK_XHTTP}\${C_RESET}"
echo ""
read -p "View QR Codes? [y/N]: " -n 1 -r
echo
if [[ \$REPLY =~ ^[Yy]$ ]]; then
    echo -e "\n\${C_TITLE}📷 Vision Node QR\${C_RESET}"
    qrencode -t ANSIUTF8 "\${LINK_VISION}"
    echo -e "\n\${C_TITLE}📷 xhttp Node QR\${C_RESET}"
    qrencode -t ANSIUTF8 "\${LINK_XHTTP}"
fi
EOF
chmod +x /usr/local/bin/info

# 展示
bash /usr/local/bin/info

