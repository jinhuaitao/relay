#!/bin/bash

# =========================================================
#  Relay Manager - One-Click Installer (TLS/HTTPS Support)
#  System: Debian/Ubuntu (Systemd) & Alpine (OpenRC)
#  Features: Auto IP, Self-signed Certs, Auto-start
# =========================================================

# --- 基础配置 ---
# 下载链接 (默认为 AMD64，如需支持 ARM 请修改此处或添加逻辑)
DOWNLOAD_URL="https://jht126.eu.org/https://github.com/jinhuaitao/relay/releases/latest/download/relay"
BIN_PATH="/usr/local/bin/relay"
SERVICE_NAME="relay"
# 关键：工作目录，证书将生成在此处，程序也会在此处寻找证书
WORK_DIR="/root"

# --- 颜色配置 ---
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[34m'
CYAN='\033[36m'
BOLD='\033[1m'
PLAIN='\033[0m'

# --- 图标 ---
ICON_SUCCESS="✅"
ICON_FAIL="❌"
ICON_WARN="⚠️"
ICON_INFO="ℹ️"
ICON_ROCKET="🚀"
ICON_TRASH="🗑️"
ICON_GLOBE="🌍"
ICON_KEY="🔑"

# --- 辅助函数 ---

clear_screen() {
    clear
}

print_line() {
    echo -e "${BLUE}————————————————————————————————————————————————————${PLAIN}"
}

print_logo() {
    clear_screen
    echo -e "${CYAN}${BOLD}"
    echo "    ____        __            "
    echo "   / __ \___   / /___ ___  __"
    echo "  / /_/ / _ \ / / __ \`/ / / /"
    echo " / _, _/  __// / /_/ / /_/ / "
    echo "/_/ |_|\___/_/\__,_/\__, /  "
    echo "                   /____/   "
    echo -e "${PLAIN}"
    echo -e "   ${YELLOW}Relay 流量转发管理脚本 (TLS增强版)${PLAIN}"
    print_line
}

log_info() {
    echo -e "${BLUE}[${ICON_INFO}] ${PLAIN} $1"
}

log_success() {
    echo -e "${GREEN}[${ICON_SUCCESS}] ${PLAIN} $1"
}

log_error() {
    echo -e "${RED}[${ICON_FAIL}] ${PLAIN} $1"
}

log_warn() {
    echo -e "${YELLOW}[${ICON_WARN}] ${PLAIN} $1"
}

# --- 环境检查 ---

check_root() {
    if [ "$(id -u)" != "0" ]; then
        log_error "请使用 root 用户运行此脚本！"
        exit 1
    fi
}

check_dependencies() {
    # 检查 wget 和 openssl
    if ! command -v wget >/dev/null || ! command -v openssl >/dev/null; then
        log_info "正在安装必要组件 (wget, openssl)..."
        if [ -f /etc/alpine-release ]; then
            apk add --no-cache wget openssl >/dev/null 2>&1
        elif [ -f /etc/debian_version ]; then
            apt-get update >/dev/null 2>&1 && apt-get install -y wget openssl >/dev/null 2>&1
        fi
        log_success "组件安装完成"
    fi
}

check_arch() {
    local arch=$(uname -m)
    log_info "系统架构: $arch"
    if [[ $arch != "x86_64" ]]; then
        log_warn "当前脚本默认下载 AMD64 版本，您的架构为 $arch，可能无法运行。"
        read -p "是否继续安装? (y/n): " confirm
        if [[ "$confirm" != "y" ]]; then
            exit 1
        fi
    fi
}

# --- 核心安装逻辑 ---

install_relay() {
    print_logo
    echo -e "${BOLD}正在开始安装 Relay...${PLAIN}\n"
    
    check_dependencies
    check_arch

    # 1. 获取 IP (用于证书签名)
    log_info "正在检测服务器 IP (用于生成证书)..."
    SERVER_IP=$(wget -qO- -t1 -T2 ipv4.icanhazip.com)
    if [ -z "$SERVER_IP" ]; then
        SERVER_IP=$(wget -qO- -t1 -T2 ifconfig.me)
    fi
    if [ -z "$SERVER_IP" ]; then
        SERVER_IP="127.0.0.1"
    fi
    log_info "检测到 IP: ${CYAN}$SERVER_IP${PLAIN}"

    # 2. 下载
    log_info "正在下载二进制文件..."
    # 尝试代理下载
    wget -q -O "$BIN_PATH" "$DOWNLOAD_URL"
    if [ $? -ne 0 ]; then
        log_warn "代理下载失败，尝试 GitHub 直连..."
        REAL_URL="${DOWNLOAD_URL##*https://github.com}" 
        REAL_URL="https://github.com${REAL_URL}"
        wget -q -O "$BIN_PATH" "$REAL_URL"
        if [ $? -ne 0 ]; then
            log_error "下载失败，请检查网络连接。"
            read -p "按回车键返回..."
            return
        fi
    fi
    chmod +x "$BIN_PATH"
    log_success "下载成功"

    # 3. 证书生成
    # 检查是否已有证书，防止覆盖
    if [[ ! -f "$WORK_DIR/server.crt" || ! -f "$WORK_DIR/server.key" ]]; then
        log_info "正在生成自签名 SSL 证书..."
        
        # 生成私钥
        openssl genrsa -out "$WORK_DIR/server.key" 2048 >/dev/null 2>&1
        
        # 生成证书 (有效期10年, CN=SERVER_IP)
        openssl req -new -x509 -sha256 -key "$WORK_DIR/server.key" \
            -out "$WORK_DIR/server.crt" -days 3650 \
            -subj "/C=CN/ST=Internet/L=Internet/O=GoRelay/CN=${SERVER_IP}" >/dev/null 2>&1
            
        if [[ -f "$WORK_DIR/server.crt" ]]; then
            log_success "证书生成成功 (有效期 10 年)"
        else
            log_error "证书生成失败"
            return
        fi
    else
        log_warn "检测到已有证书 ($WORK_DIR)，跳过生成步骤。"
    fi

    # 4. 配置服务
    log_info "正在配置系统服务..."
    
    if [ -f /etc/alpine-release ]; then
        # --- Alpine OpenRC ---
        cat > /etc/init.d/$SERVICE_NAME <<EOF
#!/sbin/openrc-run
name="relay"
command="$BIN_PATH"
directory="$WORK_DIR"
command_args="-mode master"
command_background=true
pidfile="/run/${SERVICE_NAME}.pid"

depend() {
    need net
    after firewall
}
EOF
        chmod +x /etc/init.d/$SERVICE_NAME
        rc-update add $SERVICE_NAME default >/dev/null 2>&1
        service $SERVICE_NAME restart >/dev/null 2>&1
        log_success "Alpine OpenRC 服务配置完成"

    elif command -v systemctl >/dev/null; then
        # --- Debian/Systemd ---
        cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=Relay Master Service
After=network.target

[Service]
Type=simple
WorkingDirectory=$WORK_DIR
ExecStart=$BIN_PATH -mode master
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable $SERVICE_NAME >/dev/null 2>&1
        systemctl restart $SERVICE_NAME
        log_success "Systemd 服务配置完成"
    else
        log_warn "未识别的初始化系统，仅完成了下载和证书生成。"
    fi

    # 5. 完成显示
    echo ""
    print_line
    echo -e " ${ICON_ROCKET} ${GREEN}Relay 安装并启动成功！${PLAIN}"
    print_line
    echo -e " 运行状态: ${GREEN}Active${PLAIN}"
    echo -e " 程序路径: ${CYAN}$BIN_PATH${PLAIN}"
    echo -e " 证书路径: ${CYAN}$WORK_DIR/server.crt${PLAIN}"
    echo -e " ${ICON_GLOBE} 访问地址: ${CYAN}${BOLD}http://${SERVER_IP}:8888${PLAIN}"
    print_line
    echo ""
    read -p "按回车键返回主菜单..."
}

uninstall_relay() {
    print_logo
    echo -e "${BOLD}正在卸载 Relay...${PLAIN}\n"

    # 停止服务
    if [ -f /etc/alpine-release ]; then
        if [ -f /etc/init.d/$SERVICE_NAME ]; then
            service $SERVICE_NAME stop >/dev/null 2>&1
            rc-update del $SERVICE_NAME default >/dev/null 2>&1
            rm -f /etc/init.d/$SERVICE_NAME
            log_success "服务已移除 (OpenRC)"
        fi
    elif command -v systemctl >/dev/null; then
        if [ -f /etc/systemd/system/${SERVICE_NAME}.service ]; then
            systemctl stop $SERVICE_NAME >/dev/null 2>&1
            systemctl disable $SERVICE_NAME >/dev/null 2>&1
            rm -f /etc/systemd/system/${SERVICE_NAME}.service
            systemctl daemon-reload
            systemctl reset-failed >/dev/null 2>&1
            log_success "服务已移除 (Systemd)"
        fi
    fi

    # 删除二进制
    if [ -f "$BIN_PATH" ]; then
        rm -f "$BIN_PATH"
        log_success "程序文件已删除"
    fi

    # 询问是否删除证书
    echo ""
    read -p "是否删除配置文件和证书 ($WORK_DIR/server.*)? [y/N]: " del_conf
    if [[ "$del_conf" == "y" || "$del_conf" == "Y" ]]; then
        rm -f "$WORK_DIR/server.crt" "$WORK_DIR/server.key"
        log_success "证书文件已删除"
    else
        log_info "证书文件已保留"
    fi

    echo ""
    print_line
    echo -e " ${ICON_TRASH} ${GREEN}卸载完成。${PLAIN}"
    print_line
    echo ""
    read -p "按回车键返回主菜单..."
}

# --- 菜单系统 ---

show_menu() {
    check_root
    while true; do
        print_logo
        echo -e " ${GREEN}1.${PLAIN} 安装 Relay ${YELLOW}(Install)${PLAIN}"
        echo -e " ${GREEN}2.${PLAIN} 卸载 Relay ${YELLOW}(Uninstall)${PLAIN}"
        echo -e " ${GREEN}0.${PLAIN} 退出脚本 ${YELLOW}(Exit)${PLAIN}"
        echo ""
        print_line
        echo -e "${CYAN}系统识别: $([ -f /etc/alpine-release ] && echo "Alpine Linux" || echo "Standard Linux") ${PLAIN}"
        echo ""
        read -p " 请输入选项 [0-2]: " choice
        
        case "$choice" in
            1) install_relay ;;
            2) uninstall_relay ;;
            0) exit 0 ;;
            *) echo -e "\n${RED}输入无效，请重新输入...${PLAIN}"; sleep 1 ;;
        esac
    done
}

# --- 入口处理 ---

if [ "$1" == "install" ]; then
    check_root
    install_relay
    exit 0
elif [ "$1" == "uninstall" ]; then
    check_root
    uninstall_relay
    exit 0
else
    show_menu
fi
