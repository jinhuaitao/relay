<p align="right">
   <strong>中文</strong> | <a href="./README.en.md">English</a>
</p>

# 🌐 GoRelay Pro


<p align="center">
  <strong>安全、轻量、全能的分布式内网穿透与端口转发控制台</strong>
</p>

<p align="center">
  
[![Go Version](https://img.shields.io/badge/Go-1.20+-00ADD8?style=flat&logo=go)](https://golang.org/dl/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Alpine-lightgrey)](https://www.alpinelinux.org/)
[![Architecture](https://img.shields.io/badge/Architecture-Master%2FAgent-blue)](https://github.com/jinhuaitao/relay)
[![Database](https://img.shields.io/badge/Database-SQLite3-003B57?style=flat&logo=sqlite)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat)](LICENSE)
[![Stars](https://img.shields.io/github/stars/jinhuaitao/relay?style=flat&color=gold)](https://github.com/jinhuaitao/relay/stargazers)
[![Last Commit](https://img.shields.io/github/last-commit/jinhuaitao/relay?style=flat)](https://github.com/jinhuaitao/relay/commits)

</p>

---

**GoRelay Pro** 是一款基于 Go 语言原生编写的分布式内网穿透与端口转发控制台。采用 Master-Agent 分布式架构，无需繁琐的配置文件，只需一个单文件二进制包，即可通过现代化的 Web 面板实现全网节点的统一部署、流量调度与实时监控。

<p align="center">
  <a href="https://gorelay.888021.xyz">
    <img src="https://img.shields.io/badge/🚀-访问官方网站-c71a36" alt="Website"/>
  </a>
  <a href="https://github.com/jinhuaitao/relay">
    <img src="https://img.shields.io/badge/📂-查看源码-2088ff" alt="GitHub"/>
  </a>
  <a href="https://github.com/jinhuaitao/relay/releases">
    <img src="https://img.shields.io/badge/⬇️-下载最新版本-4kbhit" alt="Download"/>
  </a>
</p>

---

## 📑 目录导航

- [✨ 核心特性](#-核心特性)
- [🏗️ 系统架构](#️-系统架构)
- [📚 快速开始](#-快速开始)
- [🔧 部署教程](#-部署教程)
- [🛠️ 常用命令](#️-常用命令)
- [⚠️ 常见问题](#️-常见问题)
- [🖥️ 界面预览](#️-界面预览)

---

## ✨ 核心特性

### 🚀 强大的转发与流量调度

| 特性 | 说明 |
|------|------|
| **全协议支持** | 支持 TCP、UDP 以及双栈 (TCP+UDP) 端口转发，完美兼容 IPv4 & IPv6 环境 |
| **高可用负载均衡** | 内置 4 种智能分发策略，从容应对多目标 IP 场景 |
| **精准限流限速** | 支持对单条规则进行精确的流量限制（达标自动熔断）和最高带宽峰值限速 |

**负载均衡策略：**
- `Random` — 随机分配
- `Round Robin` — 轮询分发
- `Least Conn` — 最少连接优先
- `Fastest` — 最低延迟/Ping 优先（主备容灾利器）

### 🛡️ 极致的安全防护

| 特性 | 说明 |
|------|------|
| **Auto TLS** | 全自动申请并续期 Let's Encrypt 证书，面板访问与 Agent 通信均默认采用高强度 TLS 加密隧道 |
| **多重身份认证** | 内置 GitHub OAuth 一键授权登录，支持 Google Authenticator (2FA) 双因素动态验证码 |
| **Anti-Brute Force** | 自带防爆破机制，连续密码错误将自动封禁来源 IP |

### 📱 现代化 Web UI & PWA

| 特性 | 说明 |
|------|------|
| **实时监控大屏** | 基于 WebSocket 的毫秒级状态同步，动态图表直观展示全局 Tx/Rx 实时速率、节点负载与流量排行 |
| **PWA 原生体验** | 支持一键"添加到主屏幕"，秒变独立 App。提供沉浸式全屏体验、动态矢量图标及杀后台持久化登录 |

### 🤖 Telegram 智能助理

| 功能 | 说明 |
|------|------|
| **Inline Keyboard** | 发送 `/menu` 呼出全按键菜单，移动端无需输入指令，一键查看状态、无缝启停转发规则 |
| **自动化流量管理** | 设定每月账单重置日，系统将在零点自动执行全网流量清零 |
| **阶梯式告警** | 流量使用达 80%、95% 时触发预警；达到 100% 时自动精准熔断并发送警报 |
| **定时云端备份** | 每周一凌晨自动打包核心数据库，以加密文件形式发送至您的 Telegram |

---

## 🏗️ 系统架构

```
┌─────────────────────────────────────────────────────────────────┐
│                        Internet                                 │
└─────────────────────────┬───────────────────────────────────────┘
                          │
          ┌───────────────┴───────────────┐
          │                               │
    ┌─────▼─────┐                   ┌─────▼─────┐
    │  Panel    │    TLS/HTTPS      │  Node     │
    │ (Master)  │◄─────────────────►│ (Agent)   │
    │  :443     │   Encrypted       │  :8888    │
    └─────┬─────┘                   └───────────┘
          │
    ┌─────▼─────┐
    │ SQLite DB │
    │ (data.db) │
    └───────────┘
```

| 组件 | 角色 | 说明 |
|------|------|------|
| **Master** | 中转机 | 拥有公网 IP 的服务器，用于部署控制面板 |
| **Agent** | 节点机 | 用于实际转发流量的服务器（一台或多台） |

---

## 📚 快速开始

### ⚡ 一键安装（推荐）

```bash
curl -o relay.sh https://raw.githubusercontent.com/jinhuaitao/relay/master/relay.sh && chmod +x relay.sh && ./relay.sh
```

### 🐳 Docker 部署

```bash
mkdir -p gorelay && cd gorelay
docker run -d --name relay-master \
  --restart=always \
  --net=host \
  -v relay_data:/app \
  jhtone/relay -mode master
```

### 🔨 编译安装

```bash
# 1. 克隆项目
git clone https://github.com/jinhuaitao/relay.git
cd relay

# 2. 编译为 Linux 64位可执行文件
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o relay main.go

# 3. 赋予执行权限
chmod +x relay

# 4. 首次运行（自动进入安装引导）
./relay -mode master
```

---

## 🔧 部署教程

### 📋 第一步：准备服务器

| 服务器 | 需求 |
|--------|------|
| **Master (中转机)** | 拥有公网 IP，用于部署控制面板 |
| **Agent (节点机)** | 用于实际转发流量的服务器（一台或多台） |

> 💡 **推荐**：准备两个子域名，例如：
> - `panel.yourdomain.com` — 用于访问面板
> - `node.yourdomain.com` — 用于节点通信

---

### 📋 第二步：初始化 Master

首次运行后，访问 **http://您的服务器IP:8888**，进入向导设置初始管理员账号密码。

登录面板后，进入 **"系统设置"** → 配置您的网络域名：

| 配置项 | 说明 |
|--------|------|
| **面板访问域名** | 填写 `panel.yourdomain.com`（可在 Cloudflare 开启橙色小云朵 ☁️ 隐藏面板 IP） |
| **节点通信域名** | 填写 `node.yourdomain.com`（必须解析到真实 IP，**不能**开启 Cloudflare 云朵） |

> ⚠️ **重要**：保存后自动重启服务。面板将自动绑定 80 和 443 端口，并申请合法的 HTTPS 证书！

---

### 📋 第三步：配置 Telegram 通知（可选）

1. 申请 Telegram Bot 并获取 Token
2. 在面板中填入 Bot Token 和 Chat ID
3. 在 TG 中向机器人发送 `/menu` 激活智能交互中心
4. 设置自动流量重置日（如每月 1 日）

---

### 📋 第四步：添加 Agent 节点

1. 登录拥有安全绿锁的 HTTPS 面板
2. 进入 **"节点部署"** 页面
3. 填写节点名称、架构，一键生成专属安装命令
4. 复制脚本至目标服务器执行即可

> 🔒 节点将使用安全的 TLS 隧道自动接入 Master

---

## 🛠️ 常用命令

### 🐧 Debian / Ubuntu

```bash
# 查看运行状态
systemctl status relay

# 重启主控面板
systemctl restart relay

# 停止/启动服务
systemctl stop relay
systemctl start relay

# 实时查看运行日志
journalctl -u relay -f

# 查看最后50行日志
journalctl -u relay -n 50

# 彻底卸载
/root/relay -service uninstall -mode master
```

### ⛰️ Alpine Linux

```bash
# 查看运行状态
rc-service relay status

# 重启主控面板
rc-service relay restart

# 停止/启动服务
rc-service relay stop
rc-service relay start

# 实时查看日志
tail -f /var/log/relay.log

# 查看最后 50 行日志
tail -n 50 /var/log/relay.log

# 卸载并取消自启
/root/relay -service uninstall -mode master
```

---

## ⚠️ 常见问题

### 🔐 端口放行规则

| 端口 | 用途 |
|------|------|
| `80` / `443` | HTTPS 和证书申请 |
| `8888` | 未配域名时的默认 Web |
| `9999` | Agent 通信 |

### ☁️ Cloudflare CDN 避坑

- ✅ Web 面板域名可以套 CDN（开启小云朵）
- ❌ 节点通信域名必须直连（灰色云朵），否则节点永远无法上线

### 🔗 IP 连接限制

为了防止中间人攻击，如果您生成的 Agent 命令末尾带有 `-tls` 参数，则必须使用域名连接，不能修改为 IP 连接。

如需纯 IP 内网连接，请在命令末尾手动删去 `-tls`。

### 💾 安全提示

请妥善保管好 `data.db` 数据库文件及后台生成的节点凭证，这关系到您的整个转发网络安全。

---

## 🖥️ 界面预览

<img width="800" height="592" alt="mmexport1778420608453" src="https://github.com/user-attachments/assets/d09da35a-dfb0-491b-8f93-7174dac3b916" />


---

💖 [感谢赞助商 - ForZTN](https://sponsorship.forztn.com/github/jinhuaitao/relay)


## 📄 开源协议

本项目基于 [MIT](LICENSE) 协议开源。

---

<p align="center">
  <sub>Built with ❤️ by <a href="https://github.com/jinhuaitao">jinhuaitao</a></sub>
</p>
