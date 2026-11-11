# GoRelay Pro 结构与调用链

本文说明 `internal/app`（package app）的分层、关键调用链与验证方式。全部实现由早期单文件 `main.go`（AppVersion v3.3.6）按职责拆分而来，仓库根目录只保留入口 `main.go`。

## 1. 分层

| 前缀 | 文件 | 职责 |
|------|------|------|
| `app.go` | `app.go` | 命令行解析与 `-mode master/agent` 分发；`-decrypt-backup` 离线解密入口 |
| `core_` | `core_consts.go` `core_types.go` `core_globals.go` `core_db.go` `core_config.go` `core_utils.go` `core_crypto.go` `core_sysinfo.go` | 常量、数据结构、全局状态、SQLite schema、配置持久化、工具函数、备份加密原语、/proc 采集 |
| `master_` | `master_core.go` | autocert TLS、Agent 长连接认证、HTTP 路由注册、统计/健康聚合、WS 广播、规则编排下发 |
| `node_` | `node_agent.go` `node_proxy.go` | Agent 重连/心跳/任务应用、TCP/UDP 转发内核、负载均衡、限速、目标健康探测 |
| `web_` | `web_auth.go` `web_page.go` `web_rule.go` `web_settings.go` `web_pwa.go` `web_assets.go` | 认证与会话、页面渲染、规则 CRUD、设置与导入导出、PWA、go:embed 资源 |
| `tg_` | `tg_api.go` `tg_bot.go` | Telegram API 封装、长轮询交互机器人 |
| `ops_` | `ops_service.go` `ops_update.go` `ops_traffic.go` `ops_backup_crypto.go` `tg_backup.go` | 服务安装/重启、自更新、定时任务、云备份生成与外发 |
| `web/` | `*.html` `manifest.json` `sw.js` `icons/` `vendor/` | 编译期内嵌的前端资源，运行时不依赖外部 CDN |

## 2. 启动流程

```
main.go → app.Main()
  ├─ -decrypt-backup → runDecryptBackup（离线工具，不启动服务）
  ├─ -service install|uninstall → handleService（systemd / OpenRC）
  └─ -mode master → initDB → loadConfig → runMaster
     └─ -mode agent → runAgent(name, connect, token)
```

`runMaster` 启动时并行拉起：30 秒维护循环（配置落盘、日志清理、每日统计刷盘、离线节点与过期会话回收）、WS 每秒广播、TG 长轮询、自动备份、账单日清零、每日流量日报。

TLS 由 `autocert.Manager` 按 `PanelDomain` / `MasterDomain` 白名单自动申请，`:80` 用于 ACME HTTP-01。**未配置有效域名时，面板为 HTTP `:8888`、Agent 为裸 TCP `:9999` 明文运行。**

## 3. 一条转发规则的两跳链路

`pushConfigToAll()` 把每条 `LogicalRule` 拆成两个 `ForwardTask`：

1. `_exit` 下发给 `ExitAgent`：监听 `:BridgePort`，转发到 `target_ip:target_port`，按规则的 `LBStrategy` 选路。
2. `_entry` 下发给 `EntryAgent`：监听 `:EntryPort`，固定用 `rr` 转发到 `ExitAgent.RemoteIP:BridgePort`。

用户流量不经过 Master；Master 只负责控制面（任务下发、统计汇总、告警与熔断）。`BridgePort` 在新建规则时用 crypto/rand 生成于 20000–49999。

Agent 侧 `node_agent.go` 对 `update` 消息做差分：新增任务起监听，参数变化的任务重启监听，消失的任务关闭监听器并清理计数器。目标地址每次建连时从 `activeTargets` 读取，因此改目标无需重启监听。

## 4. 控制面协议

Agent 与 Master 之间是以换行分隔的 JSON 帧：

| 方向 | Type | 频率 | 载荷 |
|------|------|------|------|
| A→M | `auth` | 连接建立时 | name / token / ipv4 / ipv6 / test_port / version |
| A→M | `stats` | 1s | 每个任务的 Tx/Rx 增量与独立 IP 数 |
| A→M | `ping` | 1s | `CPU:x\|MEM:y\|DSK:z` |
| A→M | `health` | 20s | 每任务最优目标延迟 |
| M→A | `update` | 事件驱动 | `[]ForwardTask` |
| M→A | `upgrade` / `uninstall` | 管理员触发 | 空 |

认证帧按行读取并限制 64KB，15 秒未认证即断开；认证后 TCP keepalive 60 秒、读超时 90 秒、写超时 5 秒。Token 支持全局 token 与按节点 token 两种。

## 5. 数据库

SQLite（`modernc.org/sqlite`，WAL，单连接）：

| 表 | 用途 |
|----|------|
| `settings` | key/value 配置、备份幂等键 `last_backup_date` |
| `rules` | 转发规则与累计流量、告警水位 |
| `logs` | 操作日志（保留最近 1000 条） |
| `daily_stats` | 按日聚合的 Tx/Rx |

`saveConfigNoLock` 用单个事务全量重写 `settings` 与 `rules`，并检查每条语句与提交的错误。导出配置使用 `VACUUM INTO` 生成一致性快照，避免 WAL 下拷贝到撕裂页。

## 6. 安全设计要点

- 初始化：未完成 setup 时生成一次性 `setupToken`，远程访问 `/setup` 必须携带；本机回环免令牌。
- 会话：`sid` 为 24 字节随机数，30 天有效，登出立即销毁，过期会话定期回收；Cookie 为 HttpOnly + SameSite=Lax，TLS 下加 Secure。
- 口令：argon2id（旧版 MD5 / 加盐 SHA256 登录时自动升级）；登录失败 5 次封禁来源 IP 15 分钟。
- 客户端 IP：默认只信任 TCP `RemoteAddr`，仅当对端位于 `TrustedProxies` 白名单才解析转发头。
- CSRF：所有非 GET 与全部 GET 型变更端点校验 Origin/Referer 同源；WebSocket 握手同源校验。
- 前端：所有进入 `innerHTML` 的动态内容统一 `esc()` 转义；模板注入的配置对象已剥离全部凭据字段。
- 云备份：快照先删除所有凭据类 settings 并 VACUUM 压实，再用备份口令做 AES-256-GCM 加密；未配置口令则拒绝外发。
- 自更新：只从官方 GitHub Release 下载，用同批 `checksums.txt` 做 SHA256 强校验，校验失败不替换二进制。
- 前端资源：Chart.js 4.4.1 与 Remix Icon 3.5.0 本地内嵌，运行时零外部 CDN 请求。

## 7. 验证

```bash
go vet ./...
go test ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o relay .
bash -n relay.sh
```

单元测试覆盖版本比较、三种口令格式兼容、可信代理 IP 解析、规则校验、加解密往返与篡改检测、备份脱敏闭环、CSRF 同源判定、四种负载均衡策略、独立 IP 计数。

## 8. 备份解密

```bash
GORELAY_BACKUP_PASSPHRASE='你的口令' ./relay -decrypt-backup=gorelay_backup_20260101_020000.db.enc
# 未设环境变量时会提示从标准输入读取口令
```

解密得到的是**已脱敏**的数据库：规则、统计、日志可恢复，但管理员口令、节点 token、Telegram/GitHub/R2 凭据需重新在面板填写。完整（含凭据）的备份请通过面板「系统设置 → 导出配置」自行下载并离线保管。
