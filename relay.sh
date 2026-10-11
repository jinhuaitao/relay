#!/bin/bash

# =========================================================
#  Relay Manager - One-Click Installer (Auto IP)
#  System: Debian/Ubuntu (Systemd) & Alpine (OpenRC)
# =========================================================

# --- 基础配置 ---
DOWNLOAD_URL="https://jht126.eu.org/https://github.com/jinhuaitao/relay/releases/latest/download/relay"
BIN_PATH="/usr/local/bin/relay"
SERVICE_NAME="relay"

# --- 颜色与样式配置 ---
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[34m'
CYAN='\033[36m'
BOLD='\033[1m'
PLAIN='\033[0m'

# 图标定义
ICON_SUCCESS="✅"
ICON_FAIL="❌"
ICON_WARN="⚠️"
ICON_INFO="ℹ️"
ICON_ROCKET="🚀"
ICON_TRASH="🗑️"
ICON_GLOBE="🌍"

# --- UI 辅助函数 ---

clear_screen() {
    clear
}

print_line() {
    echo -e "${BLUE}————————————————————————————————————————————————————${PLAIN}"
}

print_logo() {
    clear_screen
    echo -e "${CYAN}${BOLD}"
    echo "    ____       __           "
    echo "   / __ \___  / /___ ___  __"
    echo "  / /_/ / _ \/ / __ \`/ / / /"
    echo " / _, _/  __/ / /_/ / /_/ / "
    echo "/_/ |_|\___/_/\__,_/\__, /  "
    echo "                   /____/   "
    echo -e "${PLAIN}"
    echo -e "   ${YELLOW}Relay 流量转发管理脚本${PLAIN}"
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

# --- 系统检查 ---

check_root() {
    if [ "$(id -u)" != "0" ]; then
        log_error "请使用 root 用户运行此脚本！"
        exit 1
    fi
}

check_dependencies() {
    if ! command -v wget >/dev/null; then
        log_info "正在安装必要组件 (wget)..."
        if [ -f /etc/alpine-release ]; then
            apk add --no-cache wget >/dev/null 2>&1
        elif [ -f /etc/debian_version ]; then
            apt-get update >/dev/null 2>&1 && apt-get install -y wget >/dev/null 2>&1
        fi
        log_success "组件安装完成"
    fi
}

# --- 核心功能 ---

install_relay() {
    print_logo
    echo -e "${BOLD}正在开始安装 Relay...${PLAIN}\n"
    
    check_dependencies

    # --- 新增：自动识别架构并修改下载链接 ---
    ARCH=$(uname -m)
    BASE_URL="https://jht126.eu.org/https://github.com/jinhuaitao/relay/releases/latest/download"
    case "$ARCH" in
        x86_64)
            DOWNLOAD_URL="${BASE_URL}/relay-linux-amd64"
            ;;
        aarch64|arm64)
            DOWNLOAD_URL="${BASE_URL}/relay-linux-arm64"
            ;;
        *)
            log_error "不支持的系统架构: $ARCH"
            return
            ;;
    esac
    log_info "检测到系统架构: $ARCH，使用对应版本安装"
    # ----------------------------------------

    # 1. 下载
    log_info "正在下载二进制文件..."
    wget -q -O "$BIN_PATH" "$DOWNLOAD_URL"
    if [ $? -ne 0 ]; then
        log_error "下载失败，请检查网络连接。"
        read -p "按回车键返回..."
        return
    fi
    chmod +x "$BIN_PATH"
    log_success "下载成功，已安装至: ${CYAN}$BIN_PATH${PLAIN}"

    # 2. 配置服务
    log_info "正在配置系统服务..."
    
    if [ -f /etc/alpine-release ]; then
        # Alpine OpenRC
        # 注意：command_background=true 时若不指定 output_log/error_log，
        # OpenRC 会把 stdout/stderr 丢进 /dev/null，导致 /var/log/relay.log 永不生成。
        cat > /etc/init.d/$SERVICE_NAME <<EOF
#!/sbin/openrc-run
name="relay"
command="$BIN_PATH"
command_args="-mode master"
command_background=true
pidfile="/run/${SERVICE_NAME}.pid"
output_log="/var/log/relay.log"
error_log="/var/log/relay.log"

depend() {
    need net
    after firewall
}
EOF
        touch /var/log/relay.log
        chmod +x /etc/init.d/$SERVICE_NAME
        rc-update add $SERVICE_NAME default >/dev/null 2>&1
        service $SERVICE_NAME restart >/dev/null 2>&1
        log_success "Alpine OpenRC 服务配置完成（日志: /var/log/relay.log）"

    elif command -v systemctl >/dev/null; then
        # Debian Systemd
        cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=Relay Master Service
After=network.target

[Service]
Type=simple
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
        log_warn "未识别的初始化系统，仅完成了文件下载，未配置自启。"
    fi

    # 3. 获取 IP 地址
    log_info "正在检测服务器 IP 地址..."
    SERVER_IP=$(wget -qO- -t1 -T2 ipv4.icanhazip.com)
    if [ -z "$SERVER_IP" ]; then
        SERVER_IP=$(wget -qO- -t1 -T2 ifconfig.me)
    fi
    if [ -z "$SERVER_IP" ]; then
        SERVER_IP="[你的服务器IP]"
    fi

    echo ""
    print_line
    echo -e " ${ICON_ROCKET} ${GREEN}Relay 安装并启动成功！${PLAIN}"
    print_line
    echo -e " 运行状态: ${GREEN}Active${PLAIN}"
    echo -e " 程序路径: ${CYAN}$BIN_PATH${PLAIN}"
    echo -e " ${ICON_GLOBE} 访问地址: ${CYAN}${BOLD}http://${SERVER_IP}:8888${PLAIN}"
    print_line
    echo ""
    read -p "按回车键返回主菜单..."
}

uninstall_relay() {
    print_logo
    echo -e "${BOLD}正在卸载 Relay...${PLAIN}\n"

    # 停止并删除服务
    if [ -f /etc/alpine-release ]; then
        if [ -f /etc/init.d/$SERVICE_NAME ]; then
            service $SERVICE_NAME stop >/dev/null 2>&1
            rc-update del $SERVICE_NAME default >/dev/null 2>&1
            rm -f /etc/init.d/$SERVICE_NAME
            log_success "服务已停止并移除 (OpenRC)"
        fi
    elif command -v systemctl >/dev/null; then
        if [ -f /etc/systemd/system/${SERVICE_NAME}.service ]; then
            systemctl stop $SERVICE_NAME >/dev/null 2>&1
            systemctl disable $SERVICE_NAME >/dev/null 2>&1
            rm -f /etc/systemd/system/${SERVICE_NAME}.service
            systemctl daemon-reload
            log_success "服务已停止并移除 (Systemd)"
        fi
    fi

    # 删除文件
    if [ -f "$BIN_PATH" ]; then
        rm -f "$BIN_PATH"
        log_success "二进制文件已删除"
    else
        log_warn "未找到二进制文件 (可能已被删除)"
    fi

    echo ""
    print_line
    echo -e " ${ICON_TRASH} ${GREEN}Relay 已彻底卸载。${PLAIN}"
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
        echo -e "${CYAN}提示: 根据系统自动识别 Systemd 或 OpenRC${PLAIN}"
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
