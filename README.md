# [🌐 GoRelay Pro](https://gorelay.888021.xyz)

![Go Version](https://img.shields.io/badge/Go-1.20+-00ADD8?style=flat&logo=go)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Alpine-lightgrey)
![Architecture](https://img.shields.io/badge/Architecture-Master%2FAgent-blue)
![Database](https://img.shields.io/badge/Database-SQLite3-003B57?style=flat&logo=sqlite)

**GoRelay Pro** 是一款安全、轻量、全能的分布式内网穿透与端口转发控制台。基于 Go 语言原生编写，采用 Master-Agent 分布式架构。无需繁琐的配置文件，只需一个单文件二进制包，即可通过现代化的 Web 面板实现全网节点的统一部署、流量调度与实时监控。

---

## ✨ 核心特性 (Features)

### 🚀 强大的转发与流量调度
* **全协议支持**：支持 TCP、UDP 以及双栈 (TCP+UDP) 端口转发，完美兼容 IPv4 & IPv6 环境。
* **高可用负载均衡 (LB)**：内置 4 种智能分发策略，从容应对多目标 IP 场景：
  * `Random` (随机分配)
  * `Round Robin` (轮询分发)
  * `Least Conn` (最少连接优先)
  * `Fastest` (最低延迟/Ping 优先，主备容灾利器)
* **精准限流与限速**：支持对单条规则进行精确的流量限制（达标自动熔断）和最高带宽峰值限速（MB/s）。

### 🛡️ 极致的安全防护
* **Auto TLS 自动加密**：全自动申请并续期 Let's Encrypt 证书，面板访问与 Agent 通信均默认采用高强度 TLS 加密隧道。
* **多重身份认证**：内置 GitHub OAuth 一键授权登录，并支持开启 Google Authenticator (2FA) 双因素动态验证码。
* **Anti-Brute Force**：自带防爆破机制，连续密码错误将自动封禁来源 IP。

### 📱 现代化 Web UI & PWA 支持
* **实时监控大屏**：基于 WebSocket 的毫秒级状态同步，动态图表直观展示全局 Tx/Rx 实时速率、节点负载与流量排行。
* **PWA 原生应用体验**：支持将 Web 面板一键“添加到主屏幕”，秒变独立 App。提供沉浸式全屏体验、动态矢量图标及杀后台持久化登录。

### 🤖 交互式 Telegram 智能助理
* **Inline Keyboard 快捷控制**：发送 `/menu` 呼出全按键菜单，移动端无需输入指令，一键查看状态、无缝启停转发规则、远程重启面板。
* **自动化流量管理**：设定每月账单重置日，系统将在零点自动执行全网流量清零。
* **阶梯式告警与熔断**：流量使用达 80%、95% 时触发预警弹窗；达到 100% 时自动精准熔断目标端口，并发送最高级别警报。
* **定时云端备份**：每周一凌晨自动打包核心数据库，以加密文件形式私发至您的 Telegram，同时支持菜单一键手动备份。

---

## 💻 技术栈与架构
* **核心语言**：Go (Golang) —— 充分利用原生 Goroutines 实现千万级高并发。
* **数据存储**：纯 Go 驱动的 **SQLite 数据库 (`data.db`)**，开启 WAL 模式。无外部数据库依赖与 CGO 限制，备份和迁移仅需拷贝单一文件。
* **通信协议**：Master 与 Agent 之间基于纯 TCP 或标准 TLS 加密隧道，采用高效 JSON 协议并内置心跳保活机制。

---

## 📚 部署教程

# 第一步：准备工作
* **中转机 (Master)**：一台拥有公网 IP 的服务器，用于部署控制面板。
* **节点机 (Agent)**：一台或多台用于实际转发流量的服务器。
* *(推荐)* **双域名准备**：准备两个子域名（例如：`panel.yourdomain.com` 用于访问面板，`node.yourdomain.com` 用于节点通信）。

# 第二步：安装 Master 控制端

#### 方法 1：一键安装脚本（推荐）

```
curl -o relay.sh https://raw.githubusercontent.com/jinhuaitao/relay/master/relay.sh && chmod +x relay.sh && ./relay.sh
```

## 方法2.Docker


#### Docker命令
```
mkdir -p gorelay && cd gorelay && docker run -d --name relay-master --restart=always --net=host -v relay_data:/app jhtone/relay -mode master
```
## 方法3.编译与安装 (Master端方式)

假设您已经在 Master 服务器上。

 * 编译项目 (如果您没有 Go 环境，请先安装 Go 1.20+)：
 * 
###  下载代码并保存为 main.go
### 编译为 Linux 64位可执行文件
```
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o relay main.go
```
### 赋予执行权限
```
chmod +x relay
```
 * 首次运行与配置：
   首次运行请直接启动，它会自动进入安装引导模式。
```
   ./relay -mode master
```
# 第三步：初始化与域名配置 (极度重要 ⚠️)
首次运行后，访问 http://您的服务器IP:8888，进入向导设置初始管理员账号密码。

登录面板后，进入 “系统设置”，配置您的网络域名：

### 1.面板访问域名 (Panel)：填写 panel.yourdomain.com（此处可去 Cloudflare 开启橙色小云朵 ☁️ 隐藏面板 IP）,加密模式:在 Cloudflare 的左侧菜单找到 SSL/TLS -> 概述，将加密模式设置为 “完全 (严格)” (Full Strict)。



### 2.节点通信域名 (Node)：填写 node.yourdomain.com（必须解析到真实 IP，绝对不能开启 Cloudflare 云朵 ☁️）。

保存后自动重启服务。面板将自动绑定 80 和 443 端口，并申请合法的 HTTPS 证书！后续请使用 https://panel... 访问。

Telegram 通知配置：

申请 Bot 并在面板填入 Bot Token 和 Chat ID。

在 TG 中向机器人发送 /menu 即可激活智能交互中心。

自动流量重置日：针对有月流量限制的 VPS，填入账单日 (如 1 代表每月 1号)，机器人会自动守护您的钱包。

# 第四步：添加 Agent 节点
登录拥有安全绿锁的 HTTPS 面板，进入 “节点部署” 页面。

填写节点名称、架构，一键生成专属安装命令。

复制脚本至目标服务器 (VPS) 的终端中执行即可，节点将使用安全的 TLS 隧道自动接入 Master。

# 🛠️ 常用维护命令 (Cheat Sheet)

GoRelay Pro 内置了服务注册逻辑，在 Debian/Ubuntu 系统上会注册为 systemd 服务，在 Alpine 系统上会注册为 OpenRC 服务。

⚠️ 注意：主控端服务名为 relay，节点端服务名为 gorelay。以下命令以主控端 relay 为例。

##### 🐧 Debian / Ubuntu 维护命令操作命令

```
查看运行状态systemctl status relay
重启主控面板systemctl restart relay
停止/启动服务systemctl stop relay / systemctl start relay
实时查看运行日志journalctl -u relay -f
查看最后50行日志journalctl -u relay -n 50
彻底卸载主控/root/relay -service uninstall -mode master
```

##### ⛰️ Alpine Linux 维护命令

```
查看运行状态rc-service relay status
重启主控面板rc-service relay restart
停止/启动服务rc-service relay stop / rc-service relay start
卸载并取消自启/root/relay -service uninstall -mode master
实时滚动查看日志：tail -f /var/log/relay.log
查看最后 50 行日志：tail -n 50 /var/log/relay.log

```
⚠️ 常见排错与注意事项
端口放行规则：确保 Master 服务器防火墙放行了 80, 443（用于 HTTPS 和证书申请）、8888（未配域名时的默认 Web）和 9999（Agent 通信）端口。Agent 机器需要放行您分配的具体转发业务端口。

Cloudflare CDN 避坑：Web 面板域名可以套 CDN（开启小云朵）；但用于 Agent 连接的节点域名必须直连（灰色云朵），否则节点永远无法上线。

IP 连接限制：为了防止中间人攻击，如果您生成的 Agent 命令末尾带有 -tls 参数，则必须使用域名连接，不能修改为 IP 连接。如需纯 IP 内网连接，请在命令末尾手动删去 -tls。

安全提示：请妥善保管好 data.db 数据库文件及后台生成的节点凭证，这关系到您的整个转发网络安全。

# 界面效果

<img width="1527" height="1123" alt="3b48c24a-ae28-41f7-82fd-44091febc0ac" src="https://github.com/user-attachments/assets/d3db9e90-b3c5-4ddb-ad1a-c8c1b38537aa" />


<img width="1524" height="1116" alt="1bfc2073-6d0a-4b62-b1f3-0d742a89d3a6" src="https://github.com/user-attachments/assets/f23da23f-919e-40f5-ae53-025a1ddb9a9a" />


<img width="1521" height="1115" alt="cadbe6e7-80c3-492e-ad06-ea30f2e17118" src="https://github.com/user-attachments/assets/25248c27-a4dc-4700-89e5-44ac50e2551e" />


<img width="1583" height="1178" alt="329d2333-3acb-4924-8407-1d30f0930ab8" src="https://github.com/user-attachments/assets/507cab32-c548-464e-9f85-4ac37f4d51b3" />


<img width="1525" height="1115" alt="aa24c8c5-8446-428f-aeab-1d9cf758f460" src="https://github.com/user-attachments/assets/48f4e8fb-2b2d-422c-ac07-b79a2b689f23" />


<img width="1529" height="1119" alt="f772e119-2588-411e-9dd3-2d4307ea4fad" src="https://github.com/user-attachments/assets/1d559ac5-0b43-4a3f-9fe7-ab43c7847538" />


<img width="1522" height="1118" alt="aaefdd1b-6dea-435c-98f4-ca59894f4e6f" src="https://github.com/user-attachments/assets/12123cf0-5c2c-4169-b480-8a98d4367ca0" />


<img width="1517" height="1116" alt="9655527c-55d4-49d0-909d-cf7ecabaf665" src="https://github.com/user-attachments/assets/4da54d17-1b29-4505-af39-6daed1faf113" />
