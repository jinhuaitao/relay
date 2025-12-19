🚀 GoRelay Pro - 高性能分布式端口转发系统
GoRelay Pro 是一款专为极客和运维人员设计的现代化、高性能、分布式 TCP/UDP 端口转发与反向代理工具。
它采用 Master (控制面板) + Agent (转发节点) 的架构，通过一个单文件二进制程序即可完成所有角色的部署。无需繁琐的配置文件，所有操作均可在其精美的 Web 控制台中完成。
✨ 核心特性
 * ⚡ 极致性能：基于 Go 语言编写，底层采用内存池 (Buffer Pool) 和 Zero-Copy 技术，支持 TCP Nodelay 与 KeepAlive，轻松应对数万并发连接。
 * 🎨 星云美学 UI：拥有“流体极光”风格的现代化登录界面与响应式仪表盘，支持深色/浅色模式自动切换，提供极佳的用户体验。
 * 🛡️ 安全可靠：Master 与 Agent 之间采用 Token 鉴权机制，防止未授权连接。所有配置数据本地持久化保存 (config.json)，重启不丢失。
 * 📦 单文件部署：无任何第三方依赖，一个二进制文件走天下。内置 自安装 (Self-Install) 功能，一条命令即可自动配置 Systemd 或 OpenRC 开机自启。
 * 🌐 全协议支持：完美支持 TCP、UDP 以及 TCP+UDP 混合转发。原生支持 IPv6 网络环境。
 * 📊 实时监控：仪表盘提供精确到字节的实时流量监控与速率计算。
📚 部署教程
第一步：准备工作
您需要准备：
 * 中转机 (Master)：一台拥有公网 IP 的服务器，用于部署控制面板。
 * 节点机 (Agent)：一台或多台用于实际转发流量的服务器（可以是那台中转机自己，也可以是其他国内/国外机器）。
第二步：编译与安装 (Master 端)
假设您已经在 Master 服务器上。
 * 编译项目 (如果您没有 Go 环境，请先安装 Go 1.20+)：
   # 下载代码并保存为 main.go
# 编译为 Linux 64位可执行文件
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o relay main.go

# 赋予执行权限
chmod +x relay

 * 首次运行与配置：
   首次运行请直接启动，它会自动进入安装引导模式。
   ./relay -mode master

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
第三步：部署节点 (Agent 端)
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
