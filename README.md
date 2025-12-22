🚀 GoRelay Pro - 高性能分布式流量转发管理系统
GoRelay Pro 是一个基于 Go 语言（Golang）开发的轻量级、高性能多节点流量转发与中转管理平台。它采用 Master-Agent（主控-被控） 分布式架构，允许用户通过一个中心化的 Web 仪表盘，轻松管理分散在全球各地的服务器节点，构建灵活的 TCP/UDP 转发链路。

该项目特别针对大流量传输、中转加速、端口映射等场景进行了深度优化，具备毫秒级热更新、流量自动熔断和可视化监控等企业级特性。

🛠️ 系统架构
GoRelay Pro 分为两个核心组件：

Master（主控端）：

提供 Web 管理界面（仪表盘）。

负责存储配置、调度任务、统计流量。

监听 Control Port，等待 Agent 主动连接（支持内网穿透）。

Agent（节点端）：

部署在实际转发流量的服务器上。

主动连接 Master，接收转发指令。

执行高效的流量转发（TCP/UDP）并上报统计数据。

✨ 核心功能亮点
1. 📊 可视化仪表盘
概览监控：实时显示在线节点数量、活跃规则数、累计总流量消耗。

精美 UI：采用现代化的卡片式布局，支持状态颜色预警，操作直观便捷。

一键部署：自动生成 Agent 安装命令，支持 IP/域名切换，一键复制即可在服务器上部署。

2. 🔗 灵活的转发规则管理
多节点链路：支持定义 入口节点 -> 出口节点 -> 目标地址 的完整转发链路。

全协议支持：支持 TCP、UDP 以及 TCP+UDP 双协议同时转发。

毫秒级热更新：修改规则或目标 IP 后，Agent 端会自动检测变更并平滑重启相关任务，无需重启整个服务。

3. 🛡️ 智能流量控制与熔断
流量配额：可以为每条规则设置总流量限制（单位：GB）。

自动熔断：当规则的 (上传 + 下载) 流量达到设定的阈值时，系统会自动切断该链路，防止流量超标。

实时统计：精确到字节的流量统计，并自动持久化保存到磁盘，服务重启数据不丢失。

4. ⚡ 极致性能优化
内存池技术：使用 sync.Pool 复用 64KB 缓冲区，大幅降低垃圾回收（GC）压力。

内核级调优：强制设置 Socket 读写缓冲区为 8MB-16MB，完美适配千兆/万兆高带宽及高延迟网络环境。

异步 I/O：配置保存与流量统计采用异步写入机制，杜绝磁盘 I/O 阻塞转发线程。

秒级断流：当删除规则或流量耗尽时，不仅关闭监听端口，还会强制切断所有活跃的 TCP/UDP 连接，杜绝“偷跑”流量。

💻 技术栈与实现细节
编程语言：Go (Golang) - 利用其原生的高并发特性（Goroutines）。

数据存储：轻量级 JSON 文件存储 (config.json)，无外部数据库依赖，迁移方便。

通信协议：Master 与 Agent 之间使用自定义的 JSON 协议通过 TCP 长连接通信，包含心跳保活机制。

并发模型：

sync.Map 处理高并发下的数据读写安全。

atomic 原子操作处理流量计数，确保统计准确且高效。

🚀 适用场景
游戏加速中转：通过优质线路的中转节点，降低游戏连接延迟。

业务端口映射：将内网服务器的端口映射到公网出口。

流量配额管理：为不同用户或业务分配固定的流量包，用完即停。

跨国网络优化：利用 IPLC/IEPL 或优质线路节点进行流量中继。
# 📚 部署教程
# 第一步：准备工作
您需要准备：
 * 中转机 (Master)：一台拥有公网 IP 的服务器，用于部署控制面板。
 * 节点机 (Agent)：一台或多台用于实际转发流量的服务器（可以是那台中转机自己，也可以是其他国内/国外机器）。
# 第二步：两种方式
## 1.一键安装脚本（方式）
```
curl -o go_relay.sh https://raw.githubusercontent.com/jinhuaitao/relay/master/go_relay.sh && chmod +x go_relay.sh && ./go_relay.sh
```

## 2.Docker
```
mkdir gorelay && cd gorelay
docker run -d --name relay-master --restart=always --net=host -v $(pwd):/data jhtone/relay -mode master
```
## 3.编译与安装 (Master端方式)

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
   此时终端会显示：面板启动: http://localhost:8888
 * 初始化设置：
   * 在浏览器访问 http://<你的服务器IP>:8888。
   * 您将看到 GoRelay Setup 界面。
   * 设置 管理员账号、密码 以及 Agent 通信 Token (用于节点连接的密钥)。
   * 点击 Initialize System。
 * 配置开机自启 (推荐)：
   初始化完成后，建议停止当前进程 (Ctrl+C)，使用内置的服务安装命令让其后台常驻运行：
   ./relay -service install -mode master

   系统会自动识别您的 OS (CentOS/Debian/Alpine) 并配置开机自启服务。
# 第三步：部署节点 (Agent 端)
 * 登录面板：
   访问 http://<你的服务器IP>:8888 并登录。
 * 设置面板 IP (重要)：
   * 进入左侧菜单 ⚙️ 系统设置。
   * 在 "面板公网IP" 中填入 Master 服务器的 公网 IP (例如 1.2.3.4)。
   * 点击保存。这一步是为了确保生成的命令能正确连接回面板。
 * 获取安装命令：
   * 进入左侧菜单 🚀 部署节点。
   * 输入节点名称（例如：HK-Server-1）。
   * 点击 生成安装命令，然后点击 复制。
 * 在节点服务器执行：
   登录到您的 B 机器或 C 机器 (Agent)，粘贴刚才复制的命令并回车。
   命令示例（自动处理下载、授权和开机自启）：
   curl -L -o /root/relay ... && /root/relay -service install -mode agent ...

 * 验证状态：
   回到 Web 面板的 📊 仪表盘监控，您应该能看到新节点状态显示为 “运行中”。
第四步：添加转发规则
假设您想通过 B机器 (入口) 转发流量到 C机器 (出口) 的 目标网站。
 * 进入 🔗 转发管理 页面。
 * 添加入口：选择 B 机器的 Agent，填写入库端口 (例如 8080)。
 * 添加出口：选择 C 机器的 Agent。
 * 填写目标：填写最终目标的 IP 和端口 (例如 1.1.1.1 和 80)。
 * 选择协议：TCP / UDP / TCP+UDP。
 * 点击 添加。
✅ 完成！ 现在访问 B机器IP:8080，流量就会自动经过 B -> C -> 目标。
🛠️ 常用维护命令
Master (面板) 维护：
 * 停止服务：relay -service uninstall (会移除开机自启并停止进程)
 * 手动重启：systemctl restart gorelay (Systemd 系统) 或 rc-service gorelay restart (Alpine 系统)
 * 查看日志：journalctl -u gorelay -f
配置文件：
所有配置和规则均保存在运行目录下的 config.json 文件中。
⚠️ 注意事项
 * 防火墙：请确保 Master 机器放行了 8888 (Web面板) 和 9999 (Agent通信) 端口。Agent 机器需要放行您设置的转发端口。
 * UDP 优化：如果您主要用于转发 UDP 流量（如游戏），建议在服务器上优化 sysctl 参数以获得最佳性能。
 * 安全性：请务必保管好您的 通信 Token，任何拥有 Token 的人都可以接入您的网络。
# 界面效果
<img width="1628" height="1080" alt="image" src="https://github.com/user-attachments/assets/8ff33329-ba11-499e-a856-a1caf4ab6efc" />
<img width="1632" height="1009" alt="image" src="https://github.com/user-attachments/assets/0b60bfea-c29a-486f-b5b8-2cdc55cd4dc3" />
<img width="1627" height="1003" alt="image" src="https://github.com/user-attachments/assets/1b548384-96cb-4640-aa50-80e8348c24b5" />
<img width="1638" height="1016" alt="f1593b89-d6f0-4f59-9dc6-5b71deea47d6" src="https://github.com/user-attachments/assets/4c0c3ada-2c65-4b04-b330-ef0ad1d78206" />
<img width="1633" height="1007" alt="image" src="https://github.com/user-attachments/assets/5b4c081d-aeb4-4c55-9f7e-ab3feecf8bf9" />



