#!/usr/bin/env bash
set -e

#############################################
#  简化版 Shadowsocks Rust 安装脚本
#  仅做：安装依赖 + 下载 ss-rust + 写配置 + 写 systemd
#############################################

# 路径设置
INSTALL_DIR="/etc/ss-rust"
CONFIG_PATH="${INSTALL_DIR}/config.json"
BINARY_PATH="/usr/local/bin/ss-rust"
SERVICE_FILE="/etc/systemd/system/ss-rust.service"

# 变量
OS_TYPE=""
OS_ARCH=""
SS_VERSION=""

NODE_NAME=""
SS_PORT=""
SS_METHOD=""
SS_PASSWORD=""
SS_TFO=true
SS_DNS=""
IPV4=""
IPV6=""

# 颜色
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
PLAIN="\033[0m"

INFO="${GREEN}[信息]${PLAIN}"
ERROR="${RED}[错误]${PLAIN}"
SUCCESS="${GREEN}[成功]${PLAIN}"

error_exit() {
    echo -e "${ERROR} $1" >&2
    exit 1
}

check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        error_exit "请使用 root 用户或 sudo 运行此脚本。"
    fi
}

detect_os() {
    if [[ -e /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        case "$ID" in
            ubuntu|debian)
                OS_TYPE="debian"
                ;;
            centos|rocky|almalinux|rhel)
                OS_TYPE="centos"
                ;;
            *)
                error_exit "暂不支持的发行版: $ID"
                ;;
        esac
    else
        error_exit "无法检测操作系统类型。"
    fi
    echo -e "${INFO} 检测到系统类型: ${OS_TYPE}"
}

detect_arch() {
    case "$(uname -m)" in
        x86_64)
            OS_ARCH="x86_64-unknown-linux-gnu"
            ;;
        aarch64|arm64)
            OS_ARCH="aarch64-unknown-linux-gnu"
            ;;
        *)
            error_exit "暂不支持的架构: $(uname -m)"
            ;;
    esac
    echo -e "${INFO} 检测到架构: ${OS_ARCH}"
}

install_dependencies() {
    echo -e "${INFO} 安装依赖：curl / xz / tar / qrencode（二维码可选）..."
    case "$OS_TYPE" in
        debian)
            apt-get update
            apt-get install -y curl xz-utils tar qrencode
            ;;
        centos)
            yum install -y curl xz tar qrencode
            ;;
        *)
            error_exit "未知 OS_TYPE: $OS_TYPE"
            ;;
    esac
    echo -e "${SUCCESS} 依赖安装完成。"
}

get_latest_version() {
    echo -e "${INFO} 获取 Shadowsocks Rust 最新版本..."
    SS_VERSION=$(
        curl -fsSL "https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases" \
        | grep -Eo '"tag_name": *"v[0-9.]+"' \
        | head -n1 \
        | sed -E 's/.*"v([0-9.]+)".*/\1/'
    )

    if [[ -z "$SS_VERSION" ]]; then
        error_exit "无法从 GitHub 获取最新版本号，请稍后重试。"
    fi

    echo -e "${INFO} 最新版本: v${SS_VERSION}"
}

download_ss() {
    local version="$1"
    local arch="$2"
    local filename="shadowsocks-v${version}.${arch}.tar.xz"
    local url="https://github.com/shadowsocks/shadowsocks-rust/releases/download/v${version}/${filename}"

    echo -e "${INFO} 正在下载 Shadowsocks Rust v${version}..."
    curl -fL "${url}" -o "${filename}" || error_exit "下载失败：${url}"

    echo -e "${INFO} 解压中..."
    tar -xf "${filename}" || error_exit "解压失败：${filename}"

    if [[ ! -x ssserver ]]; then
        error_exit "解压目录中未找到 ssserver 可执行文件。"
    fi

    echo -e "${INFO} 安装 ssserver 到 ${BINARY_PATH}..."
    install -m 755 ssserver "${BINARY_PATH}"
    rm -f "${filename}" sslocal ssmanager ssservice ssurl ssclient 2>/dev/null || true

    echo -e "${SUCCESS} Shadowsocks Rust 已安装：${BINARY_PATH}"
}

ask_node_name() {
    echo
    read -rp "请输入节点名称（用于客户端展示，例如 HK-ORACLE_CLOUD）: " NODE_NAME
    [[ -z "$NODE_NAME" ]] && NODE_NAME="HK-ORACLE_CLOUD"
    echo -e "${INFO} 节点名称：${NODE_NAME}"
}

ask_port() {
    echo
    while true; do
        read -rp "请输入监听端口 [1-65535]（默认 2525）: " SS_PORT
        [[ -z "$SS_PORT" ]] && SS_PORT=2525
        if [[ "$SS_PORT" =~ ^[0-9]+$ ]] && (( SS_PORT >= 1 && SS_PORT <= 65535 )); then
            echo -e "${INFO} 使用端口：${SS_PORT}"
            break
        else
            echo -e "${ERROR} 端口无效，请重新输入。"
        fi
    done
}

ask_method() {
    echo
    echo "请选择加密方式："
    echo "  1) 2022-blake3-aes-128-gcm"
    echo "  2) 2022-blake3-aes-256-gcm (推荐，默认)"
    echo "  3) 2022-blake3-chacha20-poly1305"
    echo "  4) chacha20-ietf-poly1305（老 AEAD）"
    read -rp "输入数字 [1-4]（默认 2）: " m
    [[ -z "$m" ]] && m=2

    case "$m" in
        1) SS_METHOD="2022-blake3-aes-128-gcm" ;;
        2) SS_METHOD="2022-blake3-aes-256-gcm" ;;
        3) SS_METHOD="2022-blake3-chacha20-poly1305" ;;
        4) SS_METHOD="chacha20-ietf-poly1305" ;;
        *) SS_METHOD="2022-blake3-aes-256-gcm" ;;
    esac

    echo -e "${INFO} 加密方式：${SS_METHOD}"
}

ask_password() {
    echo
    echo "请输入密码（留空则自动生成安全随机密钥）:"
    read -rp "密码: " SS_PASSWORD

    if [[ -z "$SS_PASSWORD" ]]; then
        case "$SS_METHOD" in
            2022-blake3-aes-128-gcm)
                SS_PASSWORD=$(dd if=/dev/urandom bs=16 count=1 2>/dev/null | base64)
                ;;
            2022-blake3-aes-256-gcm|2022-blake3-chacha20-poly1305)
                local raw len
                while true; do
                    raw=$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | base64)
                    len=$(printf "%s" "$raw" | base64 -d 2>/dev/null | wc -c | tr -d ' ')
                    if [[ "$len" -eq 32 ]]; then
                        SS_PASSWORD="$raw"
                        break
                    fi
                done
                ;;
            *)
                SS_PASSWORD=$(dd if=/dev/urandom bs=16 count=1 2>/dev/null | base64)
                ;;
        esac
        echo -e "${INFO} 已生成随机密码。"
    fi

    echo -e "${INFO} 密码：${SS_PASSWORD}"
}

ask_tfo() {
    echo
    read -rp "是否启用 TCP Fast Open? [Y/n]（默认 Y）: " t
    [[ -z "$t" ]] && t="y"
    case "$t" in
        [Yy]*)
            SS_TFO=true
            ;;
        *)
            SS_TFO=false
            ;;
    esac
    echo -e "${INFO} TFO：${SS_TFO}"
}

ask_dns() {
    echo
    read -rp "是否自定义 DNS（默认使用系统 DNS）? [y/N]: " d
    [[ -z "$d" ]] && d="n"
    if [[ "$d" == "y" || "$d" == "Y" ]]; then
        read -rp "请输入 DNS 服务器（可多个，用逗号分隔，如 8.8.8.8,1.1.1.1）: " SS_DNS
        [[ -z "$SS_DNS" ]] && SS_DNS="8.8.8.8"
        echo -e "${INFO} 使用自定义 DNS：${SS_DNS}"
    else
        SS_DNS=""
        echo -e "${INFO} 使用系统 DNS。"
    fi
}

write_config() {
    echo
    echo -e "${INFO} 写入配置文件到 ${CONFIG_PATH} ..."
    mkdir -p "${INSTALL_DIR}"

    if [[ -n "${SS_DNS}" ]]; then
        cat > "${CONFIG_PATH}" <<EOF
{
  "server": "::",
  "server_port": ${SS_PORT},
  "password": "${SS_PASSWORD}",
  "method": "${SS_METHOD}",
  "fast_open": ${SS_TFO},
  "mode": "tcp_and_udp",
  "user": "nobody",
  "timeout": 300,
  "nameserver": "${SS_DNS}"
}
EOF
    else
        cat > "${CONFIG_PATH}" <<EOF
{
  "server": "::",
  "server_port": ${SS_PORT},
  "password": "${SS_PASSWORD}",
  "method": "${SS_METHOD}",
  "fast_open": ${SS_TFO},
  "mode": "tcp_and_udp",
  "user": "nobody",
  "timeout": 300
}
EOF
    fi

    chmod 600 "${CONFIG_PATH}"
    echo -e "${SUCCESS} 配置文件已生成。"
}

install_service() {
    echo
    echo -e "${INFO} 写入 systemd 服务到 ${SERVICE_FILE} ..."
    cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=Shadowsocks Rust Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=${BINARY_PATH} -c ${CONFIG_PATH}
Restart=on-failure
RestartSec=3s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now ss-rust
    echo -e "${SUCCESS} systemd 服务已安装并启动：ss-rust"
}

get_ip() {
    IPV4=$(curl -m 3 -s4 https://api.ipify.org || true)
    IPV6=$(curl -m 3 -s6 https://api64.ipify.org || true)
    [[ -z "$IPV4" ]] && IPV4="IPv4_Unavailable"
    [[ -z "$IPV6" ]] && IPV6="IPv6_Unavailable"
}

print_info() {
    get_ip

    echo
    echo -e "${GREEN}=========== 节点信息 ===========${PLAIN}"
    echo -e " 节点名称 : ${NODE_NAME}"
    [[ "$IPV4" != "IPv4_Unavailable" ]] && echo -e " IPv4     : ${IPV4}"
    [[ "$IPV6" != "IPv6_Unavailable" ]] && echo -e " IPv6     : ${IPV6}"
    echo -e " 端口     : ${SS_PORT}"
    echo -e " 加密     : ${SS_METHOD}"
    echo -e " 密码     : ${SS_PASSWORD}"
    echo -e " TFO      : ${SS_TFO}"
    [[ -n "${SS_DNS}" ]] && echo -e " DNS      : ${SS_DNS}"
    echo -e "${GREEN}================================${PLAIN}"

    local userinfo
    userinfo=$(printf "%s:%s" "${SS_METHOD}" "${SS_PASSWORD}" | base64 | tr -d '\n')

    echo
    echo -e "${YELLOW}=== Shadowsocks 链接（ss://）===${PLAIN}"
    if [[ "$IPV4" != "IPv4_Unavailable" ]]; then
        local ss_url_v4
        ss_url_v4="ss://${userinfo}@${IPV4}:${SS_PORT}#${NODE_NAME}"
        echo -e " IPv4: ${ss_url_v4}"
    fi
    if [[ "$IPV6" != "IPv6_Unavailable" ]]; then
        local ss_url_v6
        ss_url_v6="ss://${userinfo}@[${IPV6}]:${SS_PORT}#${NODE_NAME}"
        echo -e " IPv6: ${ss_url_v6}"
    fi

    if command -v qrencode >/dev/null 2>&1; then
        echo
        echo -e "${YELLOW}=== 二维码（终端显示）===${PLAIN}"
        if [[ "$IPV4" != "IPv4_Unavailable" ]]; then
            echo -e " IPv4:"
            echo "ss://${userinfo}@${IPV4}:${SS_PORT}#${NODE_NAME}" | qrencode -t UTF8
        fi
        if [[ "$IPV6" != "IPv6_Unavailable" ]]; then
            echo -e " IPv6:"
            echo "ss://${userinfo}@[${IPV6}]:${SS_PORT}#${NODE_NAME}" | qrencode -t UTF8
        fi
    fi

    echo
    echo -e "${YELLOW}=== Surge 配置示例 ===${PLAIN}"
    if [[ "$IPV4" != "IPv4_Unavailable" ]]; then
        echo "${NODE_NAME} = ss, ${IPV4}, ${SS_PORT}, encrypt-method=${SS_METHOD}, password=${SS_PASSWORD}, tfo=${SS_TFO}, udp-relay=true"
    fi
    if [[ "$IPV6" != "IPv6_Unavailable" ]]; then
        echo "${NODE_NAME}-v6 = ss, ${IPV6}, ${SS_PORT}, encrypt-method=${SS_METHOD}, password=${SS_PASSWORD}, tfo=${SS_TFO}, udp-relay=true"
    fi

    echo
    echo -e "${SUCCESS} 已完成安装并输出节点信息。"
}

#############################################
#                 主流程
#############################################

check_root
detect_os
detect_arch
install_dependencies

echo -e "${INFO} 开始配置 Shadowsocks Rust 节点 ..."
ask_node_name
ask_port
ask_method
ask_password
ask_tfo
ask_dns

get_latest_version
download_ss "${SS_VERSION}" "${OS_ARCH}"
write_config
install_service
print_info
