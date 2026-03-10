🌐 GoRelay Pro
GoRelay Pro 是一款安全、轻量、全能的分布式内网穿透与端口转发控制台。基于 Go 语言原生编写，采用 Master-Agent 分布式架构。无需繁琐的配置文件，只需一个单文件二进制包，即可在 Web 面板上实现全网节点的统一部署、流量调度与实时监控。

✨ 核心特性 (Features)
## 🚀 强大的转发与调度
全协议支持：支持 TCP、UDP 以及双栈 (TCP+UDP) 端口转发，完美兼容 IPv4 & IPv6。

高可用负载均衡 (LB)：内置 4 种智能分发策略应对多目标 IP：

Random (随机分配)

Round Robin (轮询分发)

Least Conn (最少连接优先)

Fastest (最低延迟/Ping 优先，主备容灾利器)

精准限流与限速：支持对单条规则进行精确的流量限制（自动熔断）和最高带宽限速（MB/s）。

## 🛡️ 极致的安全防护
Auto TLS 自动加密：全自动申请 Let's Encrypt 证书，面板访问与 Agent 通信均支持高强度 TLS 加密。

多重登录保护：内置 GitHub OAuth 一键授权登录，支持开启 Google Authenticator (2FA) 双因素动态动态码认证。

Anti-Brute Force：自带防爆破机制，连续密码错误自动封禁来源 IP。

## 📱 现代化 Web UI & PWA 支持
实时监控大屏：基于 WebSocket 的毫秒级状态同步，动态图表展示全局 Tx/Rx 实时速率、节点负载与流量排行。

PWA 原生应用体验：支持将 Web 面板一键“添加到主屏幕”，秒变独立 App。自带沉浸式全屏体验、动态矢量图标（无浏览器角标）与杀后台持久化登录。

## 🤖 交互式 Telegram 机器人
Inline Keyboard 快捷控制：发送 /menu 呼出全按键菜单，手机端无需打字，一键查看状态、无缝启停转发规则、远程重启面板。

账单日流量清零：设定每月重置日，系统自动在零点执行全网流量清零。

阶梯式告警防破产：流量使用达 80%、95% 时触发预警弹窗；达到 100% 自动精确熔断目标端口并发送最高警报。

☁️ 定时云备份：每周一凌晨自动将核心数据库打包，以加密文件的形式私发到您的 Telegram，也可随时在菜单一键手动云备份，数据永不丢失。
---

## 💻 技术栈与实现细节
* **编程语言**：Go (Golang) - 利用其原生的高并发特性（Goroutines）。
* **数据存储**：纯 Go 驱动的 **SQLite 数据库 (`data.db`)**，支持 WAL 模式，无外部数据库与 CGO 依赖，备份和迁移只需拷贝一个文件。
* **通信协议**：Master 与 Agent 之间使用纯 TCP 或合法 TLS 加密隧道，采用 JSON 协议并包含心跳保活机制。

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
```
mkdir gorelay && cd gorelay

```

#### Docker命令
```
docker run -d --name relay-master --restart=always --net=host -v $(pwd):/data jhtone/relay -mode master
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

保存后点击 “重启服务”。面板将自动绑定 80 和 443 端口，并申请合法的 HTTPS 证书！后续请使用 https://panel... 访问。

Telegram 通知配置：

申请 Bot 并在面板填入 Bot Token 和 Chat ID。

在 TG 中向机器人发送 /start 即可激活智能交互中心。

自动流量重置日：针对有月流量限制的 VPS，填入账单日 (如 1 代表每月 1号)，机器人会自动守护您的钱包。

# 第四步：添加 Agent 节点
登录拥有安全绿锁的 HTTPS 面板，进入 “节点部署” 页面。

填写节点名称、架构，一键生成专属安装命令。

复制脚本至目标服务器 (VPS) 的终端中执行即可，节点将使用安全的 TLS 隧道自动接入 Master。

# 🛠️ 常用维护命令
Master (面板) 维护：

停止/卸载服务：relay -service uninstall (会移除开机自启并停止进程)

手动重启：systemctl restart relay 或在面板设置页点击重启。

查看日志：journalctl -u relay -f

⚠️ 常见排错与注意事项
端口放行规则：确保 Master 服务器防火墙放行了 80, 443（用于 HTTPS 和证书申请）、8888（未配域名时的默认 Web）和 9999（Agent 通信）端口。Agent 机器需要放行您分配的具体转发业务端口。

Cloudflare CDN 避坑：Web 面板域名可以套 CDN（开启小云朵）；但用于 Agent 连接的节点域名必须直连（灰色云朵），否则节点永远无法上线。

IP 连接限制：为了防止中间人攻击，如果您生成的 Agent 命令末尾带有 -tls 参数，则必须使用域名连接，不能修改为 IP 连接。如需纯 IP 内网连接，请在命令末尾手动删去 -tls。

安全提示：请妥善保管好 data.db 数据库文件及后台生成的节点凭证，这关系到您的整个转发网络安全。

# 界面效果

<img width="1632" height="1091" alt="00fbb834-8587-449d-aa54-51262044ab4d" src="https://github.com/user-attachments/assets/d6de1cfa-838a-4a6e-b1f8-b9b2be38ee3a" />

<img width="1633" height="1083" alt="d85805e6-d2ff-4c9b-b74f-cff44cb42e69" src="https://github.com/user-attachments/assets/e79789f0-9fe1-4df6-bf91-ccb5b11891e9" />

<img width="1637" height="1090" alt="3c991d56-85b5-4be7-bfb2-9adbdfb5d72f" src="https://github.com/user-attachments/assets/444bc6ba-685c-4204-90ab-191c62f9c461" />

<img width="1639" height="1091" alt="1edc02ea-6bdf-4689-8efa-169b32254f2c" src="https://github.com/user-attachments/assets/0256c07f-9de7-47de-8342-24defd50b52f" />

