🚀 GoRelay Pro - 高性能分布式流量转发管理系统

GoRelay Pro 是一个基于 Go 语言（Golang）开发的轻量级、高性能多节点流量转发与中转管理平台。它采用 Master-Agent（主控-被控） 分布式架构，允许用户通过一个中心化的 Web 仪表盘，轻松管理分散在全球各地的服务器节点，构建灵活的 TCP/UDP 转发链路。

该项目特别针对大流量传输、中转加速、端口映射等场景进行了深度优化，具备毫秒级热更新、全自动 HTTPS 证书、动静域名分离和企业级可视化监控等特性。

## ✨ 核心功能特性

### 1. 🔒 极致的安全防护架构 (New!)
* **全自动 HTTPS (Auto TLS)**：内置 ACME 客户端，填入域名自动向 Let's Encrypt 申请并续期合法 TLS 证书。
* **动静域名分离**：支持分别配置“面板访问域名（可套 CDN 保护）”与“节点通信域名（直连）”。
* **控制台隐身伪装**：通过节点域名尝试访问 Web 面板将被拦截并返回 404，完美隐藏服务端真实身份。
* **防中间人劫持 (MITM)**：Agent 节点强制进行严格的 TLS 证书域名校验，数据传输绝对防窃听。
* **严密的 Web 安全防护**：全面防御 CSRF 跨站伪造、CSWSH WebSocket 劫持、IP 伪造及密码暴力破解，支持 Google Authenticator 2FA 双因素认证与 GitHub OAuth 授权登录。

### 2. 🖥️ 现代化实时仪表盘
* **毫秒级流量监控**：集成 WebSocket + Chart.js，提供类似专业网管软件的动态波形图，实时展示全网总传输速率。
* **资源状态透视**：在面板上直接查看所有 Agent 节点的 CPU 负载和内存使用率，拒绝盲目运维。
* **数据可视化**：直观展示在线节点数、规则总数、累计消耗流量以及各条规则的流量进度条。

### 3. 🚀 强大的转发能力
* **全协议支持**：完美支持 TCP、UDP 以及 TCP+UDP 双协议并发转发。
* **灵活的负载均衡**：支持多目标 IP 轮询 (RR)、最少连接 (Least Conn)、最低延迟 (Fastest) 和随机分配。
* **灵活的拓扑结构**：支持入口节点与出口节点分离，轻松构建中转链路（A机 -> B机 -> 目标）。

### 4. 🛡️ 智能流控与管理
* **流量配额限制**：支持为每条规则设置流量上限（GB）与带宽限速（MB/s），超额自动断流。
* **一键启停开关**：无需删除规则即可一键暂停/恢复指定端口的转发，支持批量操作。
* **Telegram 通知**：集成 TG 机器人，节点上线/下线、系统更新等关键事件实时推送。

### 5. ⚡ 极致性能优化
* **内存池技术**：使用 `sync.Pool` 复用数据缓冲区，大幅降低垃圾回收（GC）压力。
* **秒级断流**：当删除规则或流量耗尽时，不仅关闭监听，还会强制切断所有活跃的 TCP/UDP 会话，杜绝流量“偷跑”。

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

面板访问域名 (Panel)：填写 panel.yourdomain.com（此处可去 Cloudflare 开启橙色小云朵 ☁️ 隐藏面板 IP）。

节点通信域名 (Node)：填写 node.yourdomain.com（必须解析到真实 IP，绝对不能开启 Cloudflare 云朵 ☁️）。

保存后点击 “重启服务”。面板将自动绑定 80 和 443 端口，并申请合法的 HTTPS 证书！后续请使用 https://panel... 访问。
 
# 第四步：添加 Agent 节点
登录拥有安全绿锁的 HTTPS 面板，进入 “节点部署” 页面。

填写节点名称、架构，一键生成专属安装命令。

复制脚本至目标服务器 (VPS) 的终端中执行即可，节点将使用安全的 TLS 隧道自动接入 Master。

🛠️ 常用维护命令
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

