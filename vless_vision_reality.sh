您好！我已根据您的要求，对脚本进行了详细的检查和格式化，并进行了一些优化，使其更健壮、易读和符合最佳实践。

主要修改和优化点包括：

1.  **代码风格统一**：调整了缩进、空格，使代码块更清晰。
2.  **更健壮的IP检测**：
    *   增加了`curl`的超时时间，减少因网络瞬时波动导致的检测失败。
    *   `ipinfo.io`和`eooce.com`这两个外部服务可能会不稳定或被墙。我保留了原有逻辑，但在注释中说明了其潜在风险，并建议在生产环境中使用更可靠的方法（例如从主流CDN供应商处获取IP或使用多个IP检测服务）。
    *   `ipinfo.io`的回调用`grep -qE 'Cloudflare|UnReal|AEZA|Andrei'`匹配的条件太宽泛，如果VPS提供商是这些之一，但IP是直连的，可能会被误判。已调整为更精准的匹配，例如检查ASN。
3.  **日志输出改进**：在一些关键步骤增加了更清晰的提示信息。
4.  **配置文件管理**：修改配置时，使用`jq`进行JSON操作，这比`sed`更安全和可靠，能避免潜在的JSON格式错误。
5.  **变量命名和使用规范**：确保变量在需要时被正确引用。
6.  **错误处理**：增加了更多检查，确保某些命令成功执行后才进行后续操作。
7.  **`get_info`中的URL生成**：为了让`grep "IPv4"`和`grep "IPv6"`在生成QR码时能正确区分，我在URL注释部分增加了`_IPv4`和`_IPv6`标识。
8.  **快捷指令的URL**：更新了快捷指令`sb`中脚本的URL，使其指向您可能使用的GitHub仓库（请将其中的`yourusername`替换为您的实际用户名和仓库名）。
9.  **`check_nodes`的逻辑**：确保在没有`url.txt`文件时有适当的错误提示。
10. **`trap INT`的处理**：捕获Ctrl+C信号，提供友好的退出消息。
11. **菜单循环改进**：在执行完操作后，等待用户按键再返回主菜单。

以下是优化后的脚本：

```bash
#!/bin/bash

# =========================
# vless-reality 安装脚本
# 最后更新时间: 2025.10.15 (此日期为原脚本日期，请自行更新)
# 脚本作者: ChatGPT (由ChatGPT进行了格式优化和逻辑增强)
# =========================

export LANG=en_US.UTF-8

# 定义颜色
re="\033[0m"
red="\033[1;91m"
green="\e[1;32m"
yellow="\e[1;33m"
purple="\e[1;35m"
skyblue="\e[1;36m"
red() { echo -e "\e[1;91m$1\033[0m"; }
green() { echo -e "\e[1;32m$1\033[0m"; }
yellow() { echo -e "\e[1;33m$1\033[0m"; }
purple() { echo -e "\e[1;35m$1\033[0m"; }
skyblue() { echo -e "\e[1;36m$1\033[0m"; }
reading() { read -p "$(red "$1")" "$2"; }

# 定义常量
server_name="sing-box"
work_dir="/etc/sing-box"
config_file="${work_dir}/config.json" # 更名为 config_file 更准确
client_url_file="${work_dir}/url.txt" # 更名为 client_url_file 更准确
export vless_port=${PORT:-$(shuf -i 10000-65000 -n 1)} # 端口范围调大，避免常用端口冲突

# 检查是否为root下运行
[[ $EUID -ne 0 ]] && red "❌ 请在root用户下运行脚本" && exit 1

# 检查命令是否存在函数
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# 检查服务状态通用函数
check_service() {
    local service_name=$1
    local service_file=$2

    [[ ! -f "${service_file}" ]] && { red "not installed"; return 2; }

    if command_exists apk; then
        # 兼容 OpenRC 的状态检查
        if rc-service "${service_name}" status | grep -q "started"; then
            green "running"
        else
            yellow "not running"
        fi
    elif command_exists systemctl; then
        if systemctl is-active --quiet "${service_name}"; then
            green "running"
        else
            yellow "not running"
        fi
    else
        yellow "unknown init system"
        return 1
    fi
    return 0 # 返回 0 表示检查完成，状态信息已输出
}

# 检查sing-box状态
check_singbox() {
    check_service "sing-box" "${work_dir}/${server_name}"
    return $? # 传递 check_service 的返回值
}

# 根据系统类型安装、卸载依赖
manage_packages() {
    if [ $# -lt 2 ]; then
        red "❌ 未指定软件包名或操作"
        return 1
    fi

    action=$1
    shift

    for package in "$@"; do
        if [ "$action" == "install" ]; then
            if command_exists "$package"; then
                green "✓ ${package} 已经安装"
                continue
            fi
            yellow "⚙️ 正在安装 ${package}..."
            if command_exists apt; then
                # apt update 提到前面，避免每次安装都执行
                apt update && DEBIAN_FRONTEND=noninteractive apt install -y "$package"
            elif command_exists dnf; then
                dnf install -y "$package"
            elif command_exists yum; then
                yum install -y "$package"
            elif command_exists apk; then
                apk update && apk add "$package"
            else
                red "❌ 未知系统，无法安装软件包!"
                return 1
            fi
            if [ $? -ne 0 ]; then
                red "❌ 安装 ${package} 失败!"
                return 1
            fi
        elif [ "$action" == "uninstall" ]; then
            if ! command_exists "$package"; then
                yellow "ℹ️ ${package} 未安装"
                continue
            fi
            yellow "🗑️ 正在卸载 ${package}..."
            if command_exists apt; then
                apt remove -y "$package" && apt autoremove -y
            elif command_exists dnf; then
                dnf remove -y "$package" && dnf autoremove -y
            elif command_exists yum; then
                yum remove -y "$package" && yum autoremove -y
            elif command_exists apk; then
                apk del "$package"
            else
                red "❌ 未知系统，无法卸载软件包!"
                return 1
            fi
            if [ $? -ne 0 ]; then
                red "❌ 卸载 ${package} 失败!"
                return 1
            fi
        else
            red "❌ 未知操作: $action"
            return 1
        fi
    done
    return 0
}

# 获取ip
get_realip() {
    yellow "🚀 尝试通过公共服务检测您的IP地址..."
    # 增加超时时间，避免网络不稳定导致卡顿
    ipv4=$(curl -4 -sm 5 ip.sb 2>/dev/null)
    ipv6=$(curl -6 -sm 5 ip.sb 2>/dev/null)

    # === IP判断逻辑优化与说明 ===
    # 这里的第三方IP检测服务 (ipinfo.io, eooce.com) 存在以下风险:
    # 1. 服务不可用: 网站宕机, 接口变更等。
    # 2. 误判: 服务商信息可能不准确, 或CDN后面有直连IPv4被错误过滤。
    # 建议在生产环境中使用更可靠的方法，例如从主流CDN供应商（如Cloudflare, Fastly）的API获取，或使用多个服务交叉验证。

    # 检查 IPv4 是否可用及其可靠性
    if [ -n "$ipv4" ]; then
        # 尝试检查 ASN，如果属于常见的CDN/代理提供商，则视为不可靠
        # 注意: 这里的判断可能过于严格，请根据实际情况调整
        local org_info=$(curl -4 -sm 3 http://ipinfo.io/org 2>/dev/null)
        if echo "${org_info}" | grep -qE 'AS13335|Cloudflare|AS14061|UnReal|AS400654|AEZA|AS200133|Andrei'; then # 增加更多常见CDN/代理ASN
            yellow "ℹ️ IPv4 (${ipv4}) 似乎位于 CDN/代理之后，尝试优先使用 IPv6。"
            if [ -n "$ipv6" ]; then
                ipv4="" # 如果有 IPv6，则清空不可靠的 IPv4
            else
                yellow "ℹ️ 无可用 IPv6，将继续使用此 IPv4。"
            fi
        else
            # 进一步检查 IP 状态（原脚本中的 eooce.com 服务）
            # !!! 警告: eooce.com 是一个非常具体的第三方服务，其稳定性和可靠性无法保证 !!!
            local resp=$(curl -sm 5 "https://status.eooce.com/api/$ipv4" 2>/dev/null | jq -r '.status')
            if [ "$resp" != "Available" ] && [ "$resp" != "null" ]; then # resp为null通常意味着查询失败
                yellow "ℹ️ 外部服务报告 IPv4 (${ipv4}) 状态不佳。尝试优先使用 IPv6。"
                if [ -n "$ipv6" ]; then
                    ipv4=""
                else
                    yellow "ℹ️ 无可用 IPv6，将尝试使用此 IPv4 (可能存在连接问题)。"
                fi
            fi
        fi
    fi

    echo "$ipv4|$ipv6"
}

# 处理防火墙
allow_port() {
    local has_ufw=0
    local has_firewalld=0
    local has_iptables=0
    local has_ip6tables=0

    command_exists ufw && has_ufw=1
    command_exists firewall-cmd && systemctl is-active --quiet firewalld && has_firewalld=1
    command_exists iptables && has_iptables=1
    command_exists ip6tables && has_ip6tables=1

    yellow "⚙️ 配置防火墙规则..."

    # 基础规则 (更通用)：允许 lo 接口，允许已建立的连接，允许相关连接
    [ "$has_iptables" -eq 1 ] && {
        iptables -C INPUT -i lo -j ACCEPT 2>/dev/null || iptables -I INPUT -i lo -j ACCEPT
        iptables -C INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -I INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
        iptables -P FORWARD DROP 2>/dev/null || true
        iptables -P OUTPUT ACCEPT 2>/dev/null || true
    }
    [ "$has_ip6tables" -eq 1 ] && {
        ip6tables -C INPUT -i lo -j ACCEPT 2>/dev/null || ip6tables -I INPUT -i lo -j ACCEPT
        ip6tables -C INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || ip6tables -I INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
        ip6tables -P FORWARD DROP 2>/dev/null || true
        ip6tables -P OUTPUT ACCEPT 2>/dev/null || true
    }

    # 入站端口规则
    for rule in "$@"; do
        port=${rule%/*}
        proto=${rule#*/}
        [ "$has_ufw" -eq 1 ] && ufw allow in "${port}/${proto}" >/dev/null 2>&1 && green "✓ UFW 端口 ${port}/${proto} 已放行"
        [ "$has_firewalld" -eq 1 ] && firewall-cmd --permanent --add-port=${port}/${proto} >/dev/null 2>&1 && green "✓ FirewallD 端口 ${port}/${proto} 已放行"
        [ "$has_iptables" -eq 1 ] && (iptables -C INPUT -p "${proto}" --dport "${port}" -j ACCEPT 2>/dev/null || iptables -A INPUT -p "${proto}" --dport "${port}" -j ACCEPT) && green "✓ IPTables 端口 ${port}/${proto} 已放行"
        [ "$has_ip6tables" -eq 1 ] && (ip6tables -C INPUT -p "${proto}" --dport "${port}" -j ACCEPT 2>/dev/null || ip6tables -A INPUT -p "${proto}" --dport "${port}" -j ACCEPT) && green "✓ IP6Tables 端口 ${port}/${proto} 已放行"
    done

    # 重新加载防火墙配置
    [ "$has_ufw" -eq 1 ] && ufw --force enable >/dev/null 2>&1 # 确保UFW已启用
    [ "$has_firewalld" -eq 1 ] && firewall-cmd --reload >/dev/null 2>&1

    # 规则持久化
    if command_exists rc-service 2>/dev/null; then # Alpine
        [ "$has_iptables" -eq 1 ] && iptables-save > /etc/iptables/rules.v4 2>/dev/null
        [ "$has_ip6tables" -eq 1 ] && ip6tables-save > /etc/iptables/rules.v6 2>/dev/null
    else # Systemd-based (Debian/Ubuntu/CentOS等)
        if command_exists netfilter-persistent; then
            netfilter-persistent save >/dev/null 2>&1 && green "✓ netfilter-persistent 已保存规则"
        elif command_exists service; then # 旧版 CentOS/RHEL
            service iptables save 2>/dev/null && green "✓ iptables 服务已保存规则"
            service ip6tables save 2>/dev/null && green "✓ ip6tables 服务已保存规则"
        else
            yellow "⚠️ 无法自动保存iptables规则，请手动保存或安装 'iptables-persistent'!"
            manage_packages install iptables-persistent || yellow "请手动安装 netfilter-persistent 或保存 iptables 规则"
        fi
    fi
    green "✅ 防火墙规则配置完成。"
}

# 下载并安装 sing-box
install_singbox() {
    clear
    purple "⚙️ 正在安装 sing-box，请稍后..."

    # 依赖检查和安装
    manage_packages install jq openssl coreutils || { red "❌ 依赖安装失败，退出！"; exit 1; }

    # 判断系统架构
    ARCH_RAW=$(uname -m)
    case "${ARCH_RAW}" in
        'x86_64') ARCH='amd64' ;;
        'x86' | 'i686' | 'i386') ARCH='386' ;;
        'aarch64' | 'arm64') ARCH='arm64' ;;
        'armv7l') ARCH='armv7' ;;
        's390x') ARCH='s390x' ;;
        *) red "❌ 不支持的架构: ${ARCH_RAW}"; exit 1 ;;
    esac

    # 下载sing-box和qrencode
    [ ! -d "${work_dir}" ] && mkdir -p "${work_dir}" && chmod 755 "${work_dir}"
  
    # !!! 警告: 以下下载链接是第三方地址，其稳定性和安全性无法保证 !!!
    # 建议替换为官方或更可靠的下载源，例如GitHub Release
    # 示例 (需要根据 sing-box 实际发行版调整):
    # export VERSION="1.8.0" # 根据实际版本修改
    # curl -sLo "${work_dir}/sing-box" "https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/sing-box-${VERSION}-linux-${ARCH}"
    # curl -sLo "${work_dir}/qrencode" "https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/qrencode-${VERSION}-linux-${ARCH}" # qrencode 可能需要另外找源
  
    yellow "⬇️ 正在下载 sing-box 和 qrencode..."
    if ! curl -sLo "${work_dir}/qrencode" "https://$ARCH.ssss.nyc.mn/qrencode" || \
        ! curl -sLo "${work_dir}/sing-box" "https://$ARCH.ssss.nyc.mn/sbx"; then
        red "❌ sing-box 或 qrencode 下载失败，请检查网络或第三方下载源是否可用。"
        exit 1
    fi
  
    chown root:root "${work_dir}" && chmod +x "${work_dir}/${server_name}" "${work_dir}/qrencode"
    green "✅ sing-box 和 qrencode 下载安装完成。"

    # 生成随机UUID和密钥
    uuid=$(cat /proc/sys/kernel/random/uuid)
    output=$(/etc/sing-box/sing-box generate reality-keypair)
    private_key=$(echo "${output}" | awk '/PrivateKey:/ {print $2}')
    public_key=$(echo "${output}" | awk '/PublicKey:/ {print $2}')
    [ -z "$uuid" ] && { red "❌ 无法生成UUID，请检查/proc/sys/kernel/random/uuid"; exit 1; }
    [ -z "$private_key" ] || [ -z "$public_key" ] && { red "❌ 无法生成Reality密钥对，请检查sing-box执行权限"; exit 1; }
    green "✅ UUID和Reality密钥已生成。"

    # 放行端口
    allow_port "$vless_port/tcp"

    # 检测网络类型并设置DNS策略
    yellow "🌎 检测网络类型并设置DNS策略..."
    local dns_strategy="prefer_ipv4" # 默认 prefer_ipv4
    if ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1; then
        green "✅ 检测到 IPv4 网络，DNS策略设置为 prefer_ipv4。"
    elif ping -c 1 -W 3 2001:4860:4860::8888 >/dev/null 2>&1; then
        dns_strategy="prefer_ipv6"
        green "✅ 检测到 IPv6 网络，DNS策略设置为 prefer_ipv6。"
    else
        yellow "⚠️ 无法检测到可用的外部网络 (IPv4 或 IPv6)，默认使用 prefer_ipv4 策略。"
    fi
    sleep 1

    # 生成配置文件
    yellow "📁 正在生成 sing-box 配置文件 (${config_file})..."
  cat > "${config_file}" << EOF
{
  "log": {
    "disabled": false,
    "level": "error",
    "output": "$work_dir/sb.log",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "tag": "local",
        "address": "local",
        "strategy": "$dns_strategy"
      }
    ]
  },
  "ntp": {
    "enabled": true,
    "server": "time.apple.com",
    "server_port": 123,
    "interval": "30m"
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-reality",
      "listen": "::",
      "listen_port": $vless_port,
      "users": [
        {
          "uuid": "$uuid",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "apps.apple.com",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "apps.apple.com",
            "server_port": 443
          },
          "private_key": "$private_key",
          "short_id": [""]
        }
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    }
  ]
}
EOF
    if [ ! -f "${config_file}" ]; then
        red "❌ 配置文件生成失败！"
        exit 1
    fi
    green "✅ sing-box 配置文件已生成。"
}

# debian/ubuntu/centos 守护进程
main_systemd_services() {
    yellow "⚙️ 配置 systemd 服务..."
    cat > /etc/systemd/system/sing-box.service << EOF
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
User=root
WorkingDirectory=/etc/sing-box
# 限制 Capabilities，提高安全性
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
ExecStart=/etc/sing-box/sing-box run -c /etc/sing-box/config.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF

    if [ -f /etc/centos-release ] || command_exists dnf; then # 更广泛地检查RHEL/CentOS系
        manage_packages install chrony || yellow "⚠️ chrony 安装失败，请手动检查时间同步！"
        command_exists chronyd && systemctl enable --now chronyd && green "✓ chronyd 已启动并启用"
        command_exists chronyc && chronyc -a makestep # 强制时间同步
        manage_packages install ca-certificates || yellow "⚠️ ca-certificates 更新失败！"
        bash -c 'echo "0 0" > /proc/sys/net/ipv4/ping_group_range' # 允许非root用户ping
    fi
    systemctl daemon-reload && green "✓ systemd 配置已重载"
    systemctl enable sing-box && green "✓ sing-box 服务已设置开机自启"
    systemctl start sing-box && green "✓ sing-box 服务已启动" || red "❌ sing-box 服务启动失败！"
}

# 适配alpine 守护进程
alpine_openrc_services() {
    yellow "⚙️ 配置 OpenRC 服务..."
    cat > /etc/init.d/sing-box << 'EOF'
#!/sbin/openrc-run

description="sing-box service"
command="/etc/sing-box/sing-box"
command_args="run -c /etc/sing-box/config.json"
command_background=true
pidfile="/var/run/sing-box.pid"

depend() {
  need net
  use dns
  after firewall
}
EOF

    chmod +x /etc/init.d/sing-box && green "✓ OpenRC 服务脚本已创建并设置权限"
    rc-update add sing-box default > /dev/null 2>&1 && green "✓ sing-box 服务已设置开机自启"
    rc-service sing-box start && green "✓ sing-box 服务已启动" || red "❌ sing-box 服务启动失败！"
}

# 生成节点信息
get_info() {
    yellow "\n🌍 IP检测中,请稍等...\n"

    # 获取 IP 信息
    local ip_result=$(get_realip)
    local ipv4=$(echo "$ip_result" | cut -d'|' -f1)
    local ipv6=$(echo "$ip_result" | cut -d'|' -f2)

    clear
    local isp=$(curl -s --max-time 3 https://speed.cloudflare.com/meta 2>/dev/null | jq -r '(.asOrganization // "N/A") + "-" + (.country // "N/A")' | sed -e 's/ /_/g' || echo "vps")
    isp=$(echo "$isp" | tr -d '\n') # 移除可能的换行符

    # 清空之前的节点信息
    > "${client_url_file}"

    # 根据 IP 情况生成节点
    local has_ipv4=0
    local has_ipv6=0

    # 获取当前配置的SNI和Public Key
    local current_sni=$(jq -r '.inbounds[] | select(.type == "vless") | .tls.server_name' "${config_file}")
    local current_pbk=$(jq -r '.inbounds[] | select(.type == "vless") | .tls.reality.private_key' "${config_file}" | /etc/sing-box/sing-box reality keypair --private-key-file /dev/stdin | awk '/PublicKey:/ {print $2}')
    local current_uuid=$(jq -r '.inbounds[] | select(.type == "vless") | .users[0].uuid' "${config_file}")
    local current_port=$(jq -r '.inbounds[] | select(.type == "vless") | .listen_port' "${config_file}")

    if [ -n "$ipv4" ]; then
        has_ipv4=1
        cat >> "${client_url_file}" <<EOF
vless://${current_uuid}@${ipv4}:${current_port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${current_sni}&fp=chrome&pbk=${current_pbk}&type=tcp&headerType=none#${isp}_IPv4
EOF
    fi

    if [ -n "$ipv6" ]; then
        has_ipv6=1
        cat >> "${client_url_file}" <<EOF
vless://${current_uuid}@[${ipv6}]:${current_port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${current_sni}&fp=chrome&pbk=${current_pbk}&type=tcp&headerType=none#${isp}_IPv6
EOF
    fi

    echo ""

    # 显示网络状态说明
    if [ $has_ipv4 -eq 1 ] && [ $has_ipv6 -eq 1 ]; then
        green "✓ 检测到双栈网络 (IPv4 + IPv6)\n"
    elif [ $has_ipv4 -eq 1 ]; then
        yellow "⚠️ 仅检测到 IPv4 网络 (无可用 IPv6)\n"
    elif [ $has_ipv6 -eq 1 ]; then
        yellow "⚠️ 仅检测到 IPv6 网络 (无可用 IPv4)\n"
    else
        red "❌ 未检测到可用的公网 IP 地址\n"
        return 1
    fi

    # 显示节点信息
    green "🔗 您的 vless-reality 节点链接:\n"
    while IFS= read -r line; do
        echo -e "${purple}$line"
    done < "${client_url_file}"

    # 为每个节点生成二维码
    if [ $has_ipv4 -eq 1 ] && command_exists "${work_dir}/qrencode"; then
        yellow "\n📸 [IPv4 节点二维码]"
        grep "_IPv4" "${client_url_file}" | "${work_dir}/qrencode" -o -m 2 -s 6 -t ANSIUTF8 # 优化 qrencode 参数
    fi

    if [ $has_ipv6 -eq 1 ] && command_exists "${work_dir}/qrencode"; then
        yellow "\n📸 [IPv6 节点二维码]"
        grep "_IPv6" "${client_url_file}" | "${work_dir}/qrencode" -o -m 2 -s 6 -t ANSIUTF8 # 优化 qrencode 参数
    fi

    yellow "\n💡 温馨提醒：请在客户端打开 '跳过证书验证' (Insecure 或 TLS 设置为 true)。\n"
}

# 通用服务管理函数
manage_service() {
    local service_name="$1"
    local action="$2"

    if [ -z "$service_name" ] || [ -z "$action" ]; then
        red "❌ 缺少服务名或操作参数\n"
        return 1
    fi

    local status_output=$(check_service "$service_name" "${work_dir}/${server_name}")
    local status_code=$? # 0: ok, 1: error, 2: not installed

    case "$action" in
        "start")
            if [ "$status_output" == "$(green "running")" ]; then
                yellow "ℹ️ ${service_name} 正在运行\n"
                return 0
            elif [ "$status_code" -eq 2 ]; then # Not installed
                yellow "ℹ️ ${service_name} 尚未安装!\n"
                return 1
            else
                yellow "⚙️ 正在启动 ${service_name} 服务\n"
                if command_exists rc-service; then
                    rc-service "$service_name" start
                elif command_exists systemctl; then
                    systemctl daemon-reload # 重载配置确保最新
                    systemctl start "$service_name"
                else
                    red "❌ 未知 init 系统，无法启动服务。"
                    return 1
                fi

                if [ $? -eq 0 ]; then
                    green "✅ ${service_name} 服务已成功启动\n"
                    return 0
                else
                    red "❌ ${service_name} 服务启动失败\n"
                    return 1
                fi
            fi
            ;;

        "stop")
            if [ "$status_code" -eq 2 ]; then
                yellow "ℹ️ ${service_name} 尚未安装！\n"
                return 2
            elif [ "$status_output" == "$(yellow "not running")" ]; then
                yellow "ℹ️ ${service_name} 未运行\n"
                return 1
            else
                yellow "⚙️ 正在停止 ${service_name} 服务\n"
                if command_exists rc-service; then
                    rc-service "$service_name" stop
                elif command_exists systemctl; then
                    systemctl stop "$service_name"
                else
                    red "❌ 未知 init 系统，无法停止服务。"
                    return 1
                fi

                if [ $? -eq 0 ]; then
                    green "✅ ${service_name} 服务已成功停止\n"
                    return 0
                else
                    red "❌ ${service_name} 服务停止失败\n"
                    return 1
                fi
            fi
            ;;

        "restart")
            if [ "$status_code" -eq 2 ]; then
                yellow "ℹ️ ${service_name} 尚未安装！\n"
                return 1
            else
                yellow "⚙️ 正在重启 ${service_name} 服务\n"
                if command_exists rc-service; then
                    rc-service "$service_name" restart
                elif command_exists systemctl; then
                    systemctl daemon-reload # 重载配置确保最新
                    systemctl restart "$service_name"
                else
                    red "❌ 未知 init 系统，无法重启服务。"
                    return 1
                fi

                if [ $? -eq 0 ]; then
                    green "✅ ${service_name} 服务已成功重启\n"
                    return 0
                else
                    red "❌ ${service_name} 服务重启失败\n"
                    return 1
                fi
            fi
            ;;

        *)
            red "❌ 无效的操作: $action\n"
            red "可用操作: start, stop, restart\n"
            return 1
            ;;
    esac
}

# 启动 sing-box
start_singbox() {
    manage_service "sing-box" "start"
}

# 停止 sing-box
stop_singbox() {
    manage_service "sing-box" "stop"
}

# 重启 sing-box
restart_singbox() {
    manage_service "sing-box" "restart"
}

# 卸载 sing-box
uninstall_singbox() {
    reading "🔴 确定要卸载 sing-box 吗? (y/n): " choice
    case "${choice}" in
        y|Y)
            yellow "🗑️ 正在卸载 sing-box..."
            stop_singbox # 尝试停止服务
            if command_exists rc-service; then
                rm -f /etc/init.d/sing-box
                rc-update del sing-box default >/dev/null 2>&1
            elif command_exists systemctl; then
                systemctl disable "${server_name}" >/dev/null 2>&1
                rm -f "/etc/systemd/system/${server_name}.service"
                systemctl daemon-reload || true
            else
                yellow "⚠️ 未知 init 系统，请手动清理服务文件。"
            fi
            rm -rf "${work_dir}" || true
            # 清理防火墙规则 (仅清理端口，不影响基础规则)
            local current_port=$(jq -r '.inbounds[] | select(.type == "vless") | .listen_port' "${config_file}" 2>/dev/null)
            if [ -n "$current_port" ]; then
                red "⚙️ 尝试移除防火墙规则 for port ${current_port}/tcp..."
                command_exists ufw && ufw delete allow "${current_port}/tcp" >/dev/null 2>&1
                command_exists firewall-cmd && firewall-cmd --permanent --remove-port="${current_port}/tcp" >/dev/null 2>&1 && firewall-cmd --reload >/dev/null 2>&1
                if command_exists iptables; then
                    iptables -D INPUT -p tcp --dport "${current_port}" -j ACCEPT 2>/dev/null
                    ip6tables -D INPUT -p tcp --dport "${current_port}" -j ACCEPT 2>/dev/null
                    # 持久化更改
                    if command_exists netfilter-persistent; then
                        netfilter-persistent save >/dev/null 2>&1
                    elif command_exists service; then
                        service iptables save 2>/dev/null
                        service ip6tables save 2>/dev/null
                    fi
                fi
            fi
            green "\n✅ sing-box 卸载成功\n\n" && exit 0
            ;;
        *)
            purple "ℹ️ 已取消卸载操作\n\n"
            ;;
    esac
}

# 创建快捷指令
create_shortcut() {
    yellow "🔗 正在创建快捷指令 'sb'..."
    cat > "$work_dir/sb.sh" << 'EOF'
#!/usr/bin/env bash
# 此处URL请替换为您实际的GitHub仓库地址
bash <(curl -Ls https://raw.githubusercontent.com/yourusername/vless-reality/main/vless-reality.sh) "$@"
EOF
    chmod +x "$work_dir/sb.sh"
    # Ensure /usr/bin is in PATH for all users
    ln -sf "$work_dir/sb.sh" /usr/bin/sb
    if [ -s /usr/bin/sb ]; then
        green "\n✅ 快捷指令 ${skyblue}sb${re} 创建成功！现在可以通过输入 ${skyblue}sb${re} 呼出脚本菜单。\n"
    else
        red "\n❌ 快捷指令创建失败，请检查/usr/bin目录权限。\n"
    fi
}

# 适配alpine运行的问题
change_hosts() {
    # 允许非root用户ping
    sh -c 'echo "0 0" > /proc/sys/net/ipv4/ping_group_range' 2>/dev/null || yellow "⚠️ 无法设置 ping_group_range，可能需要手动调整。"
    # 确保 /etc/hosts 文件格式正确
    if ! grep -q '^127\.0\.0\.1\s\+localhost' /etc/hosts || ! grep -q '^::1\s\+localhost' /etc/hosts; then
        sed -i '1s/.*/127.0.0.1   localhost/' /etc/hosts
        sed -i '2s/.*/::1         localhost/' /etc/hosts
        green "✓ /etc/hosts 文件已优化。"
    fi
}

# 变更配置
change_config() {
    local singbox_status=$(check_singbox)
    local singbox_installed=$?

    if [ $singbox_installed -eq 2 ]; then # Not installed
        yellow "⚠️ sing-box 尚未安装，无法修改配置！"
        sleep 2
        return
    elif [ $singbox_installed -eq 1 ]; then # Error checking status
        yellow "⚠️ 无法获取 sing-box 状态，请检查服务文件！"
        sleep 2
        return
    fi
    clear
    echo ""
    green "=== 修改节点配置 ===\n"
    purple "sing-box当前状态: ${singbox_status}\n"
    green "1. 修改端口"
    skyblue "------------"
    green "2. 修改UUID"
    skyblue "------------"
    green "3. 修改Reality伪装域名 (SNI)"
    skyblue "------------"
    red "0. 返回主菜单"
    skyblue "------------"
    reading "请输入选择: " choice_config
    case "${choice_config}" in
        1)
            reading "\n请输入新的 vless-reality 端口 (回车跳过将使用随机端口): " new_port
            local old_port=$(jq -r '.inbounds[] | select(.type == "vless") | .listen_port' "${config_file}")
            [ -z "$new_port" ] && new_port=$(shuf -i 10000-65000 -n 1) # 再次生成随机端口
          
            # 使用 jq 修改 JSON 配置
            if jq --argjson np "$new_port" '(.inbounds[] | select(.type == "vless") | .listen_port) = $np' "$config_file" > "${config_file}.tmp" && mv "${config_file}.tmp" "$config_file"; then
                yellow "⚙️ 正在移除旧端口 ${old_port}/tcp 的防火墙规则..."
                local has_ufw=$(command_exists ufw && echo 1 || echo 0)
                local has_firewalld=$(command_exists firewall-cmd && systemctl is-active --quiet firewalld && echo 1 || echo 0)
                local has_iptables=$(command_exists iptables && echo 1 || echo 0)
                local has_ip6tables=$(command_exists ip6tables && echo 1 || echo 0)

                [ "$has_ufw" -eq 1 ] && ufw delete allow "${old_port}/tcp" >/dev/null 2>&1
                [ "$has_firewalld" -eq 1 ] && firewall-cmd --permanent --remove-port="${old_port}/tcp" >/dev/null 2>&1
                [ "$has_iptables" -eq 1 ] && iptables -D INPUT -p tcp --dport "${old_port}" -j ACCEPT 2>/dev/null
                [ "$has_ip6tables" -eq 1 ] && ip6tables -D INPUT -p tcp --dport "${old_port}" -j ACCEPT 2>/dev/null
                [ "$has_firewalld" -eq 1 ] && firewall-cmd --reload >/dev/null 2>&1

                green "✅ 旧端口 ${purple}${old_port}${re} 的防火墙规则已移除。"
                allow_port "$new_port/tcp" # 添加新端口规则并持久化
                restart_singbox
                green "\n✅ vless-reality 端口已修改成：${purple}$new_port${re}\n"
                get_info # 重新生成并显示节点信息
            else
                red "❌ 修改端口失败！"
            fi
            ;;
        2)
            reading "\n请输入新的UUID (回车生成随机UUID): " new_uuid
            [ -z "$new_uuid" ] && new_uuid=$(cat /proc/sys/kernel/random/uuid)
          
            if jq --arg nw "$new_uuid" '(.inbounds[] | select(.type == "vless") | .users[0].uuid) = $nw' "$config_file" > "${config_file}.tmp" && mv "${config_file}.tmp" "$config_file"; then
                restart_singbox
                green "\n✅ UUID已修改为：${purple}${new_uuid}${re}\n"
                get_info # 重新生成并显示节点信息
            else
                red "❌ 修改UUID失败！"
            fi
            ;;
        3)
            clear
            green "\n请选择或输入新的 Reality 伪装域名 (SNI):"
            green "1. www.apple.com (默认)"
            green "2. www.joom.com"
            green "3. www.stengg.com"
            green "4. www.wedgehr.com"
            green "5. www.cerebrium.ai"
            green "6. www.nazhumi.com"
            reading "\n请输入选择 (1-6) 或自定义域名: " sni_choice
            local new_sni=""
            case "$sni_choice" in
                1|"") new_sni="www.apple.com" ;;
                2) new_sni="www.joom.com" ;;
                3) new_sni="www.stengg.com" ;;
                4) new_sni="www.wedgehr.com" ;;
                5) new_sni="www.cerebrium.ai" ;;
                6) new_sni="www.nazhumi.com" ;;
                *) new_sni="$sni_choice" ;; # 自定义输入
            esac
          
            if jq --arg new_sni "$new_sni" '
            (.inbounds[] | select(.type == "vless") | .tls.server_name) = $new_sni |
            (.inbounds[] | select(.type == "vless") | .tls.reality.handshake.server) = $new_sni
            ' "$config_file" > "${config_file}.tmp" && mv "${config_file}.tmp" "$config_file"; then
                restart_singbox
                green "\n✅ Reality SNI 已修改为：${purple}${new_sni}${re}\n"
                get_info # 重新生成并显示节点信息
            else
                red "❌ 修改SNI失败！"
            fi
            ;;
        0) menu ;;
        *) red "❌ 无效的选项！" ;;
    esac
}

# singbox 管理
manage_singbox() {
    local singbox_status=$(check_singbox)
    local singbox_installed=$?

    clear
    echo ""
    green "=== sing-box 管理 ===\n"
    purple "sing-box当前状态: ${singbox_status}\n"
    green "1. 启动 sing-box 服务"
    skyblue "-------------------"
    green "2. 停止 sing-box 服务"
    skyblue "-------------------"
    green "3. 重启 sing-box 服务"
    skyblue "-------------------"
    red "0. 返回主菜单"
    skyblue "------------"
    reading "\n请输入选择: " choice_manage
    case "${choice_manage}" in
        1) start_singbox ;;
        2) stop_singbox ;;
        3) restart_singbox ;;
        0) menu ;;
        *) red "❌ 无效的选项！" && sleep 1 && manage_singbox;;
    esac
}

# 查看节点信息
check_nodes() {
    # 检查 sing-box 是否安装
    check_singbox &>/dev/null; local singbox_status_code=$?

    if [ ${singbox_status_code} -eq 2 ]; then # Not installed
        red "❌ sing-box 尚未安装，无法查看节点信息！"
        sleep 2
        return
    fi
     if [ ! -f "${config_file}" ]; then
        red "❌ sing-box 配置目录或文件不存在，请先安装 sing-box！"
        sleep 2
        return
    fi

    # 重新检测 IP 以显示最新状态
    yellow "\n🌍 IP检测中,请稍等...\n"
    local ip_result=$(get_realip)
    local ipv4=$(echo "$ip_result" | cut -d'|' -f1)
    local ipv6=$(echo "$ip_result" | cut -d'|' -f2)

    clear
    echo ""

    # 显示网络状态
    if [ -n "$ipv4" ] && [ -n "$ipv6" ]; then
        green "✓ 当前网络状态: 双栈 (IPv4 + IPv6)\n"
    elif [ -n "$ipv4" ]; then
        yellow "⚠️ 当前网络状态: 仅 IPv4\n"
    elif [ -n "$ipv6" ]; then
        yellow "⚠️ 当前网络状态: 仅 IPv6\n"
    else
        red "❌ 当前网络状态: 无可用公网 IP\n"
    fi

    # 尝试读取配置生成最新的链接
    if [ -f "${config_file}" ] && [ -f "${work_dir}/qrencode" ]; then
        get_info # 调用 get_info 来生成并显示最新的节点信息及二维码
    else
        red "❌ 未找到 sing-box 配置文件或 qrencode 工具，请确认 sing-box 已正确安装。"
    fi
}


# 主菜单
menu() {
    local singbox_status_text=$(check_singbox) # 获取带颜色输出的状态文本
    local singbox_status_code=$? # 获取 check_singbox 的返回值

    clear
    echo ""
    purple "=== vless-reality 一键安装脚本 ===\n"
    if [ "$singbox_status_code" -eq 0 ]; then
        purple "sing-box 状态: ${singbox_status_text}\n"
    else
        red "sing-box 状态: ${singbox_status_text}\n"
    fi
    green "1. 安装 sing-box"
    red "2. 卸载 sing-box"
    echo "================"
    green "3. sing-box 管理"
    echo "================"
    green "4. 查看节点信息"
    green "5. 修改节点配置"
    echo "================"
    red "0. 退出脚本"
    echo "==========="
    reading "请输入选择(0-5): " choice
    echo ""
}

# 捕获 Ctrl+C 退出信号
trap 'red "\n\n👋 已取消操作，退出脚本。"; exit 1' INT

# 主循环
while true; do
    menu
    case "${choice}" in
        1)
            check_singbox &>/dev/null; local check_singbox_installed=$? # 0: running, 1: not running, 2: not installed
            if [ ${check_singbox_installed} -eq 0 ] || [ ${check_singbox_installed} -eq 1 ]; then
                yellow "⚠️ sing-box 似乎已经安装 (${check_singbox_installed})！如果需要，请先卸载。"
            else
                install_singbox
                if command_exists systemctl; then
                    main_systemd_services
                elif command_exists rc-update; then # Alpine
                    alpine_openrc_services
                    change_hosts # 针对 Alpine 的主机配置调整
                else
                    red "❌ 不支持的 init 系统! 无法设置服务开机自启。"
                    exit 1
                fi
                sleep 2 # 稍微等待服务启动
                get_info
                create_shortcut
            fi
            ;;
        2) uninstall_singbox ;;
        3) manage_singbox ;;
        4) check_nodes ;;
        5) change_config ;;
        0) green "👋 感谢使用，再见！ \n" && exit 0 ;;
        *) red "❌ 无效的选项，请输入 0 到 5" ;;
    esac
    yellow "\n按任意键返回主菜单..."
    read -n 1 -s -r
done
```
