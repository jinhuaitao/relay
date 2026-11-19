# 项目结构说明

GoRelay Pro 的全部实现位于 `internal/app`（单一 `package app`），按文件名前缀分层。
仓库根目录的 `main.go` 仅调用 `app.Main()`，`internal/` 保证实现包不被外部模块导入。

## 分层与职责

| 前缀 | 文件 | 职责 |
|------|------|------|
| `core_` | `core_consts.go` | 版本、端口、缓冲尺寸等常量；TCP/UDP 缓冲池 |
| | `core_types.go` | 规则、节点、控制消息、报表等数据结构；Agent 连接写串行化 |
| | `core_globals.go` | 进程级全局状态（DB 句柄、配置、运行时表、会话） |
| | `core_db.go` | SQLite 建表、WAL 参数、增量迁移 |
| | `core_config.go` | 配置加载/持久化（单行 upsert + 流量列增量刷新）、日志清理、离线节点/过期会话回收 |
| | `core_utils.go` | UUID/盐/bcrypt 口令、可信代理客户端 IP、操作日志、版本比较 |
| | `core_sysinfo.go` | Linux /proc CPU/内存/磁盘采集 |
| `master_` | `master_core.go` | 主控：autocert TLS、监听、Agent 认证与生命周期、统计/健康处理、WebSocket 广播、路由注册 |
| `node_` | `node_agent.go` | Agent：重连循环、心跳、目标健康探测、任务差量更新、流量硬熔断额度 |
| | `node_proxy.go` | 转发内核：TCP/UDP 监听、4 种负载均衡选路、令牌桶限速、额度扣减 |
| `web_` | `web_auth.go` | 登录限速、会话中间件、CSRF/同源校验、GitHub OAuth（state）、2FA |
| | `web_page.go` | 仪表盘模板渲染 |
| | `web_rule.go` | 规则增删改查、启停、批量操作、桥端口分配 |
| | `web_settings.go` | 系统设置、数据库快照导出/校验恢复、日志与规则导入导出 |
| | `web_pwa.go` / `web_assets.go` | PWA 资源服务；go:embed 前端内嵌 |
| `tg_` | `tg_api.go` | Telegram HTTP 封装：错误检查、长消息分片、编辑失败降级 |
| | `tg_bot.go` | 内联键盘 Bot 长轮询与交互 |
| | `tg_backup.go` | 周备份（一致性快照）+ Cloudflare R2 容灾 |
| `ops_` | `ops_service.go` | systemd/OpenRC 安装卸载、重启、自毁、信号处理 |
| | `ops_update.go` | 主控/节点自更新 |
| | `ops_traffic.go` | 月度流量清零、每日流量日报 |

## 关键调用链路

### 规则下发

```
面板 /add /edit /toggle /batch ──► rules 内存表 + 单行持久化
        └─► pushConfigToAll()
              ├─ 出口 Agent: {ID}_exit  监听 BridgePort → TargetIP:TargetPort（负载均衡）
              └─ 入口 Agent: {ID}_entry 监听 EntryPort → 出口IP:BridgePort
                    携带 TrafficLimit/UsedTraffic，节点侧额度耗尽即本地熔断
```

### 流量统计

```
Agent copyCount/handleUDP 原子计数（同时扣减熔断额度）
  ──每秒──► Master handleStatsReport 累加进规则
              ├─ 80%/95%/100% 阶梯 TG 告警
              ├─ dailyTxBuf/dailyRxBuf（5s 刷盘 daily_stats）
              └─ configDirty ──30s──► 仅 UPDATE 流量/告警列
```

### 备份

```
下载 /download_config ─┐
TG 周备份 / 手动备份 ──┼─► snapshotDB()（VACUUM INTO 一致性快照）
R2 容灾备份 ───────────┘
恢复 /upload_config ──► 临时文件 + quick_check + 必需表校验 ──► 替换运行库
```

## 前端

`internal/app/web/` 下的 HTML/JSON/JS 与图标全部经 `go:embed` 编译进二进制，
运行时不依赖外部文件。仪表盘图表/图标字体来自公共 CDN，离线环境会降级。

## 验证

```bash
go build ./...
go vet ./...
go test ./...
```