  #!/bin/bash

  # =========================
  # vless-reality 安装脚本
  # 最后更新时间: 2025.10.15
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
  config_dir="${work_dir}/config.json"
  client_dir="${work_dir}/url.txt"
  export vless_port=${PORT:-$(shuf -i 1000-65000 -n 1)}

  # 检查是否为root下运行
  [[ $EUID -ne 0 ]] && red "请在root用户下运行脚本" && exit 1

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
          rc-service "${service_name}" status | grep -q "started" && green "running" || yellow "not running"
      else
          systemctl is-active "${service_name}" | grep -q "^active$" && green "running" || yellow "not running"
      fi
      return $?
  }

  # 检查sing-box状态
  check_singbox() {
      check_service "sing-box" "${work_dir}/${server_name}"
  }

  #根据系统类型安装、卸载依赖
  manage_packages() {
      if [ $# -lt 2 ]; then
          red "Unspecified package name or action"
          return 1
      fi

      action=$1
      shift

      for package in "$@"; do
          if [ "$action" == "install" ]; then
              if command_exists "$package"; then
                  green "${package} already installed"
                  continue
              fi
              yellow "正在安装 ${package}..."
              if command_exists apt; then
                  DEBIAN_FRONTEND=noninteractive apt install -y "$package"
              elif command_exists dnf; then
                  dnf install -y "$package"
              elif command_exists yum; then
                  yum install -y "$package"
              elif command_exists apk; then
                  apk update
                  apk add "$package"
              else
                  red "Unknown system!"
                  return 1
              fi
          elif [ "$action" == "uninstall" ]; then
              if ! command_exists "$package"; then
                  yellow "${package} is not installed"
                  continue
              fi
              yellow "正在卸载 ${package}..."
              if command_exists apt; then
                  apt remove -y "$package" && apt autoremove -y
              elif command_exists dnf; then
                  dnf remove -y "$package" && dnf autoremove -y
              elif command_exists yum; then
                  yum remove -y "$package" && yum autoremove -y
              elif command_exists apk; then
                  apk del "$package"
              else
                  red "Unknown system!"
                  return 1
              fi
          else
              red "Unknown action: $action"
              return 1
          fi
      done

      return 0
  }

  # 获取ip
  get_realip() {
      ipv4=$(curl -4 -sm 2 ip.sb 2>/dev/null)
      ipv6=$(curl -6 -sm 2 ip.sb 2>/dev/null)

      # 检查 IPv4 是否可用
      if [ -n "$ipv4" ]; then
          if curl -4 -sm 2 http://ipinfo.io/org 2>/dev/null | grep -qE 'Cloudflare|UnReal|AEZA|Andrei'; then
              # 检查是否有可用的 IPv6
              if [ -z "$ipv6" ]; then
                  ipv4=""
              else
                  # 如果有 IPv6，则清空不可靠的 IPv4
                  ipv4=""
              fi
          else
              resp=$(curl -sm 8 "https://status.eooce.com/api/$ipv4" 2>/dev/null | jq -r '.status')
              if [ "$resp" != "Available" ]; then
                  # IP 不可用，尝试使用 IPv6
                  if [ -z "$ipv6" ]; then
                      # 没有 IPv6，保留 IPv4
                      :
                  else
                      # 有 IPv6 且 IPv4 状态不佳，清空 IPv4
                      ipv4=""
                  fi
              fi
          fi
      fi

      # 返回结果
      echo "$ipv4|$ipv6"
  }

  # 处理防火墙
  allow_port() {
      has_ufw=0
      has_firewalld=0
      has_iptables=0
      has_ip6tables=0

      command_exists ufw && has_ufw=1
      command_exists firewall-cmd && systemctl is-active firewalld >/dev/null 2>&1 && has_firewalld=1
      command_exists iptables && has_iptables=1
      command_exists ip6tables && has_ip6tables=1

      # 出站和基础规则
      [ "$has_ufw" -eq 1 ] && ufw --force default allow outgoing >/dev/null 2>&1
      [ "$has_firewalld" -eq 1 ] && firewall-cmd --permanent --zone=public --set-target=ACCEPT >/dev/null 2>&1
      [ "$has_iptables" -eq 1 ] && {
          iptables -C INPUT -i lo -j ACCEPT 2>/dev/null || iptables -I INPUT 3 -i lo -j ACCEPT
          iptables -C INPUT -p icmp -j ACCEPT 2>/dev/null || iptables -I INPUT 4 -p icmp -j ACCEPT
          iptables -P FORWARD DROP 2>/dev/null || true
          iptables -P OUTPUT ACCEPT 2>/dev/null || true
      }
      [ "$has_ip6tables" -eq 1 ] && {
          ip6tables -C INPUT -i lo -j ACCEPT 2>/dev/null || ip6tables -I INPUT 3 -i lo -j ACCEPT
          ip6tables -C INPUT -p icmp -j ACCEPT 2>/dev/null || ip6tables -I INPUT 4 -p icmp -j ACCEPT
          ip6tables -P FORWARD DROP 2>/dev/null || true
          ip6tables -P OUTPUT ACCEPT 2>/dev/null || true
      }

      # 入站
      for rule in "$@"; do
          port=${rule%/*}
          proto=${rule#*/}
          [ "$has_ufw" -eq 1 ] && ufw allow in ${port}/${proto} >/dev/null 2>&1
          [ "$has_firewalld" -eq 1 ] && firewall-cmd --permanent --add-port=${port}/${proto} >/dev/null 2>&1
          [ "$has_iptables" -eq 1 ] && (iptables -C INPUT -p ${proto} --dport ${port} -j ACCEPT 2>/dev/null || iptables -I INPUT 4 -p
  ${proto} --dport ${port} -j ACCEPT)
          [ "$has_ip6tables" -eq 1 ] && (ip6tables -C INPUT -p ${proto} --dport ${port} -j ACCEPT 2>/dev/null || ip6tables -I INPUT 4 -p
   ${proto} --dport ${port} -j ACCEPT)
      done

      [ "$has_firewalld" -eq 1 ] && firewall-cmd --reload >/dev/null 2>&1

      # 规则持久化
      if command_exists rc-service 2>/dev/null; then
          [ "$has_iptables" -eq 1 ] && iptables-save > /etc/iptables/rules.v4 2>/dev/null
          [ "$has_ip6tables" -eq 1 ] && ip6tables-save > /etc/iptables/rules.v6 2>/dev/null
      else
          if ! command_exists netfilter-persistent; then
              manage_packages install iptables-persistent || yellow "请手动安装netfilter-persistent或保存iptables规则"
              netfilter-persistent save >/dev/null 2>&1
          elif command_exists service; then
              service iptables save 2>/dev/null
              service ip6tables save 2>/dev/null
          fi
      fi
  }

  # 下载并安装 sing-box
  install_singbox() {
      clear
      purple "正在安装sing-box中，请稍后..."
      # 判断系统架构
      ARCH_RAW=$(uname -m)
      case "${ARCH_RAW}" in
          'x86_64') ARCH='amd64' ;;
          'x86' | 'i686' | 'i386') ARCH='386' ;;
          'aarch64' | 'arm64') ARCH='arm64' ;;
          'armv7l') ARCH='armv7' ;;
          's390x') ARCH='s390x' ;;
          *) red "不支持的架构: ${ARCH_RAW}"; exit 1 ;;
      esac

      # 下载sing-box
      [ ! -d "${work_dir}" ] && mkdir -p "${work_dir}" && chmod 777 "${work_dir}"
      curl -sLo "${work_dir}/qrencode" "https://$ARCH.ssss.nyc.mn/qrencode"
      curl -sLo "${work_dir}/sing-box" "https://$ARCH.ssss.nyc.mn/sbx"
      chown root:root ${work_dir} && chmod +x ${work_dir}/${server_name} ${work_dir}/qrencode

      # 生成随机UUID和密钥
      uuid=$(cat /proc/sys/kernel/random/uuid)
      output=$(/etc/sing-box/sing-box generate reality-keypair)
      private_key=$(echo "${output}" | awk '/PrivateKey:/ {print $2}')
      public_key=$(echo "${output}" | awk '/PublicKey:/ {print $2}')

      # 放行端口
      allow_port $vless_port/tcp > /dev/null 2>&1

      # 检测网络类型并设置DNS策略
      dns_strategy=$(ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1 && echo "prefer_ipv4" || (ping -c 1 -W 3 2001:4860:4860::8888 >/dev/null
  2>&1 && echo "prefer_ipv6" || echo "prefer_ipv4"))

      # 生成配置文件
  cat > "${config_dir}" << EOF
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
  }

  # debian/ubuntu/centos 守护进程
  main_systemd_services() {
      cat > /etc/systemd/system/sing-box.service << EOF
  [Unit]
  Description=sing-box service
  Documentation=https://sing-box.sagernet.org
  After=network.target nss-lookup.target

  [Service]
  User=root
  WorkingDirectory=/etc/sing-box
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

      if [ -f /etc/centos-release ]; then
          yum install -y chrony
          systemctl start chronyd
          systemctl enable chronyd
          chronyc -a makestep
          yum update -y ca-certificates
          bash -c 'echo "0 0" > /proc/sys/net/ipv4/ping_group_range'
      fi
      systemctl daemon-reload
      systemctl enable sing-box
      systemctl start sing-box
  }

  # 适配alpine 守护进程
  alpine_openrc_services() {
      cat > /etc/init.d/sing-box << 'EOF'
  #!/sbin/openrc-run

  description="sing-box service"
  command="/etc/sing-box/sing-box"
  command_args="run -c /etc/sing-box/config.json"
  command_background=true
  pidfile="/var/run/sing-box.pid"
  EOF

      chmod +x /etc/init.d/sing-box
      rc-update add sing-box default > /dev/null 2>&1
  }

  # 生成节点信息
  get_info() {
      yellow "\nIP检测中,请稍等...\n"

      # 获取 IP 信息
      ip_result=$(get_realip)
      ipv4=$(echo "$ip_result" | cut -d'|' -f1)
      ipv6=$(echo "$ip_result" | cut -d'|' -f2)

      clear
      isp=$(curl -s --max-time 2 https://speed.cloudflare.com/meta | awk -F\" '{print $26"-"$18}' | sed -e 's/ /_/g' || echo "vps")

      # 清空之前的节点信息
      > ${work_dir}/url.txt

      # 根据 IP 情况生成节点
      has_ipv4=0
      has_ipv6=0

      if [ -n "$ipv4" ]; then
          has_ipv4=1
          cat >> ${work_dir}/url.txt <<EOF
  vless://${uuid}@${ipv4}:${vless_port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=apps.apple.com&fp=chrome&pbk=${public
  _key}&type=tcp&headerType=none#${isp}
  EOF
      fi

      if [ -n "$ipv6" ]; then
          has_ipv6=1
          cat >> ${work_dir}/url.txt <<EOF
  vless://${uuid}@[${ipv6}]:${vless_port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=apps.apple.com&fp=chrome&pbk=${publ
  ic_key}&type=tcp&headerType=none#${isp}
  EOF
      fi

      echo ""

      # 显示网络状态说明
      if [ $has_ipv4 -eq 1 ] && [ $has_ipv6 -eq 1 ]; then
          green "✓ 检测到双栈网络 (IPv4 + IPv6)\n"
      elif [ $has_ipv4 -eq 1 ]; then
          yellow "⚠ 仅检测到 IPv4 网络 (无可用 IPv6)\n"
      elif [ $has_ipv6 -eq 1 ]; then
          yellow "⚠ 仅检测到 IPv6 网络 (无可用 IPv4)\n"
      else
          red "✗ 未检测到可用的公网 IP 地址\n"
          return 1
      fi

      # 显示节点信息
      while IFS= read -r line; do
          echo -e "${purple}$line"
      done < ${work_dir}/url.txt

      # 为每个节点生成二维码
      if [ $has_ipv4 -eq 1 ]; then
          yellow "\n[IPv4 节点二维码]"
          grep "IPv4" ${work_dir}/url.txt | $work_dir/qrencode
      fi

      if [ $has_ipv6 -eq 1 ]; then
          yellow "\n[IPv6 节点二维码]"
          grep "IPv6" ${work_dir}/url.txt | $work_dir/qrencode
      fi

      yellow "\n温馨提醒：需打开V2rayN或其他软件里的 "跳过证书验证"，或将节点的Insecure或TLS里设置为"true"\n"
  }

  # 通用服务管理函数
  manage_service() {
      local service_name="$1"
      local action="$2"

      if [ -z "$service_name" ] || [ -z "$action" ]; then
          red "缺少服务名或操作参数\n"
          return 1
      fi

      local status=$(check_service "$service_name" 2>/dev/null)

      case "$action" in
          "start")
              if [ "$status" == "running" ]; then
                  yellow "${service_name} 正在运行\n"
                  return 0
              elif [ "$status" == "not installed" ]; then
                  yellow "${service_name} 尚未安装!\n"
                  return 1
              else
                  yellow "正在启动 ${service_name} 服务\n"
                  if command_exists rc-service; then
                      rc-service "$service_name" start
                  elif command_exists systemctl; then
                      systemctl daemon-reload
                      systemctl start "$service_name"
                  fi

                  if [ $? -eq 0 ]; then
                      green "${service_name} 服务已成功启动\n"
                      return 0
                  else
                      red "${service_name} 服务启动失败\n"
                      return 1
                  fi
              fi
              ;;

          "stop")
              if [ "$status" == "not installed" ]; then
                  yellow "${service_name} 尚未安装！\n"
                  return 2
              elif [ "$status" == "not running" ]; then
                  yellow "${service_name} 未运行\n"
                  return 1
              else
                  yellow "正在停止 ${service_name} 服务\n"
                  if command_exists rc-service; then
                      rc-service "$service_name" stop
                  elif command_exists systemctl; then
                      systemctl stop "$service_name"
                  fi

                  if [ $? -eq 0 ]; then
                      green "${service_name} 服务已成功停止\n"
                      return 0
                  else
                      red "${service_name} 服务停止失败\n"
                      return 1
                  fi
              fi
              ;;

          "restart")
              if [ "$status" == "not installed" ]; then
                  yellow "${service_name} 尚未安装！\n"
                  return 1
              else
                  yellow "正在重启 ${service_name} 服务\n"
                  if command_exists rc-service; then
                      rc-service "$service_name" restart
                  elif command_exists systemctl; then
                      systemctl daemon-reload
                      systemctl restart "$service_name"
                  fi

                  if [ $? -eq 0 ]; then
                      green "${service_name} 服务已成功重启\n"
                      return 0
                  else
                      red "${service_name} 服务重启失败\n"
                      return 1
                  fi
              fi
              ;;

          *)
              red "无效的操作: $action\n"
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
      reading "确定要卸载 sing-box 吗? (y/n): " choice
      case "${choice}" in
          y|Y)
              yellow "正在卸载 sing-box"
              if command_exists rc-service; then
                  rc-service sing-box stop
                  rm /etc/init.d/sing-box
                  rc-update del sing-box default
              else
                  systemctl stop "${server_name}"
                  systemctl disable "${server_name}"
                  systemctl daemon-reload || true
              fi
              rm -rf "${work_dir}" || true
              rm -rf /etc/systemd/system/sing-box.service > /dev/null 2>&1

              green "\nsing-box 卸载成功\n\n" && exit 0
              ;;
          *)
              purple "已取消卸载操作\n\n"
              ;;
      esac
  }

  # 创建快捷指令
  create_shortcut() {
      cat > "$work_dir/sb.sh" << 'EOF'
  #!/usr/bin/env bash
  bash <(curl -Ls https://raw.githubusercontent.com/yourusername/vless-reality/main/vless-reality.sh) $1
  EOF
      chmod +x "$work_dir/sb.sh"
      ln -sf "$work_dir/sb.sh" /usr/bin/sb
      if [ -s /usr/bin/sb ]; then
          green "\n快捷指令 sb 创建成功\n"
      else
          red "\n快捷指令创建失败\n"
      fi
  }

  # 适配alpine运行的问题
  change_hosts() {
      sh -c 'echo "0 0" > /proc/sys/net/ipv4/ping_group_range'
      sed -i '1s/.*/127.0.0.1   localhost/' /etc/hosts
      sed -i '2s/.*/::1         localhost/' /etc/hosts
  }

  # 变更配置
  change_config() {
      local singbox_status=$(check_singbox 2>/dev/null)
      local singbox_installed=$?

      if [ $singbox_installed -eq 2 ]; then
          yellow "sing-box 尚未安装！"
          sleep 1
          menu
          return
      fi

      clear
      echo ""
      green "=== 修改节点配置 ===\n"
      green "sing-box当前状态: $singbox_status\n"
      green "1. 修改端口"
      skyblue "------------"
      green "2. 修改UUID"
      skyblue "------------"
      green "3. 修改Reality伪装域名"
      skyblue "------------"
      purple "0. 返回主菜单"
      skyblue "------------"
      reading "请输入选择: " choice
      case "${choice}" in
          1)
              reading "\n请输入vless-reality端口 (回车跳过将使用随机端口): " new_port
              [ -z "$new_port" ] && new_port=$(shuf -i 2000-65000 -n 1)
              sed -i '/"type": "vless"/,/listen_port/ s/"listen_port": [0-9]\+/"listen_port": '"$new_port"'/' $config_dir
              restart_singbox
              allow_port $new_port/tcp > /dev/null 2>&1
              sed -i 's/\(vless:\/\/[^@]*@[^:]*:\)[0-9]\{1,\}/\1'"$new_port"'/' $client_dir
              while IFS= read -r line; do yellow "$line"; done < ${work_dir}/url.txt
              green "\nvless-reality端口已修改成：${purple}$new_port${re} ${green}请手动更改节点端口${re}\n"
              ;;
          2)
              reading "\n请输入新的UUID: " new_uuid
              [ -z "$new_uuid" ] && new_uuid=$(cat /proc/sys/kernel/random/uuid)
              sed -i -E 's/"uuid": "([a-f0-9-]+)"/"uuid": "'"$new_uuid"'"/g' $config_dir
              restart_singbox
              sed -i -E 's/(vless:\/\/)[^@]*(@.*)/\1'"$new_uuid"'\2/' $client_dir
              while IFS= read -r line; do yellow "$line"; done < ${work_dir}/url.txt
              green "\nUUID已修改为：${purple}${new_uuid}${re} ${green}请手动更改节点UUID${re}\n"
              ;;
          3)
              clear
              green "\n1. www.joom.com\n\n2. www.stengg.com\n\n3. www.wedgehr.com\n\n4. www.cerebrium.ai\n\n5. www.nazhumi.com\n"
              reading "\n请输入新的Reality伪装域名(可自定义输入,回车留空将使用默认1): " new_sni
              if [ -z "$new_sni" ]; then
                  new_sni="www.joom.com"
              elif [[ "$new_sni" == "1" ]]; then
                  new_sni="www.joom.com"
              elif [[ "$new_sni" == "2" ]]; then
                  new_sni="www.stengg.com"
              elif [[ "$new_sni" == "3" ]]; then
                  new_sni="www.wedgehr.com"
              elif [[ "$new_sni" == "4" ]]; then
                  new_sni="www.cerebrium.ai"
              elif [[ "$new_sni" == "5" ]]; then
                  new_sni="www.nazhumi.com"
              else
                  new_sni="$new_sni"
              fi
              jq --arg new_sni "$new_sni" '
              (.inbounds[] | select(.type == "vless") | .tls.server_name) = $new_sni |
              (.inbounds[] | select(.type == "vless") | .tls.reality.handshake.server) = $new_sni
              ' "$config_dir" > "${config_dir}.tmp" && mv "${config_dir}.tmp" "$config_dir"
              restart_singbox
              sed -i "s/\(vless:\/\/[^\?]*\?\([^\&]*\&\)*sni=\)[^&]*/\1$new_sni/" $client_dir
              while IFS= read -r line; do yellow "$line"; done < ${work_dir}/url.txt
              echo ""
              green "\nReality sni已修改为：${purple}${new_sni}${re} ${green}请手动更改节点sni域名${re}\n"
              ;;
          0)  menu ;;
          *)  red "无效的选项！" ;;
      esac
  }

  # singbox 管理
  manage_singbox() {
      local singbox_status=$(check_singbox 2>/dev/null)
      local singbox_installed=$?

      clear
      echo ""
      green "=== sing-box 管理 ===\n"
      green "sing-box当前状态: $singbox_status\n"
      green "1. 启动sing-box服务"
      skyblue "-------------------"
      green "2. 停止sing-box服务"
      skyblue "-------------------"
      green "3. 重启sing-box服务"
      skyblue "-------------------"
      purple "0. 返回主菜单"
      skyblue "------------"
      reading "\n请输入选择: " choice
      case "${choice}" in
          1) start_singbox ;;
          2) stop_singbox ;;
          3) restart_singbox ;;
          0) menu ;;
          *) red "无效的选项！" && sleep 1 && manage_singbox;;
      esac
  }

  # 查看节点信息
  check_nodes() {
      # 重新检测 IP 以显示最新状态
      yellow "\nIP检测中,请稍等...\n"
      ip_result=$(get_realip)
      ipv4=$(echo "$ip_result" | cut -d'|' -f1)
      ipv6=$(echo "$ip_result" | cut -d'|' -f2)

      clear
      echo ""

      # 显示网络状态
      if [ -n "$ipv4" ] && [ -n "$ipv6" ]; then
          green "✓ 当前网络状态: 双栈 (IPv4 + IPv6)\n"
      elif [ -n "$ipv4" ]; then
          yellow "⚠ 当前网络状态: 仅 IPv4\n"
      elif [ -n "$ipv6" ]; then
          yellow "⚠ 当前网络状态: 仅 IPv6\n"
      else
          red "✗ 当前网络状态: 无可用公网 IP\n"
      fi

      # 显示节点信息
      if [ -f "${work_dir}/url.txt" ]; then
          while IFS= read -r line; do
              echo -e "${purple}$line"
          done < ${work_dir}/url.txt

          # 显示二维码
          if grep -q "IPv4" ${work_dir}/url.txt; then
              yellow "\n[IPv4 节点二维码]"
              grep "IPv4" ${work_dir}/url.txt | $work_dir/qrencode
          fi

          if grep -q "IPv6" ${work_dir}/url.txt; then
              yellow "\n[IPv6 节点二维码]"
              grep "IPv6" ${work_dir}/url.txt | $work_dir/qrencode
          fi
      else
          red "未找到节点信息文件\n"
      fi
  }

  # 主菜单
  menu() {
      singbox_status=$(check_singbox 2>/dev/null)

      clear
      echo ""
      purple "=== vless-reality 安装脚本 ===\n"
      purple "singbox 状态: ${singbox_status}\n"
      green "1. 安装sing-box"
      red "2. 卸载sing-box"
      echo "==============="
      green "3. sing-box管理"
      echo "==============="
      green "4. 查看节点信息"
      green "5. 修改节点配置"
      echo "==============="
      red "0. 退出脚本"
      echo "==========="
      reading "请输入选择(0-5): " choice
      echo ""
  }

  # 捕获 Ctrl+C 退出信号
  trap 'red "已取消操作"; exit' INT

  # 主循环
  while true; do
      menu
      case "${choice}" in
          1)
              check_singbox &>/dev/null; check_singbox=$?
              if [ ${check_singbox} -eq 0 ]; then
                  yellow "sing-box 已经安装！\n"
              else
                  manage_packages install jq openssl coreutils
                  install_singbox
                  if command_exists systemctl; then
                      main_systemd_services
                  elif command_exists rc-update; then
                      alpine_openrc_services
                      change_hosts
                      rc-service sing-box restart
                  else
                      echo "Unsupported init system"
                      exit 1
                  fi

                  sleep 3
                  get_info
                  create_shortcut
              fi
              ;;
          2) uninstall_singbox ;;
          3) manage_singbox ;;
          4) check_nodes ;;
          5) change_config ;;
          0) exit 0 ;;
          *) red "无效的选项，请输入 0 到 5" ;;
      esac
      read -n 1 -s -r -p $'\033[1;91m按任意键返回...\033[0m'
  done
