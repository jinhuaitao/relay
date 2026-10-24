// telegram_bot.go — Telegram Bot 交互层：Update 结构、菜单渲染、长轮询主循环
//
// 由原单文件 main.go（AppVersion v3.3.6）按职责拆分而来，
// 代码逻辑、执行顺序与对外行为完全未改动（同一 package main）。

package app

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

type InlineButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data"`
}

// --- Telegram Update 结构的具名定义 ---
// 原实现使用逐字复刻的匿名结构体，任何字段/tag 微调都会导致难以排查的编译错误。
type TgChat struct {
	ID int64 `json:"id"`
}

type TgMessage struct {
	MessageID int64  `json:"message_id"`
	Chat      TgChat `json:"chat"`
}

type TgCallbackQuery struct {
	ID      string     `json:"id"`
	Data    string     `json:"data"`
	Message *TgMessage `json:"message"`
}

type TgIncomingMessage struct {
	Chat TgChat `json:"chat"`
	Text string `json:"text"`
}

type TgUpdate struct {
	UpdateID      int64              `json:"update_id"`
	Message       *TgIncomingMessage `json:"message"`
	CallbackQuery *TgCallbackQuery   `json:"callback_query"`
}

type tgUpdatesResponse struct {
	OK          bool       `json:"ok"`
	ErrorCode   int        `json:"error_code"`
	Description string     `json:"description"`
	Result      []TgUpdate `json:"result"`
}

func sendTgMenu(chatID string) {
	markup := map[string]interface{}{
		"inline_keyboard": [][]InlineButton{
			{{Text: "📊 节点与流量状态", CallbackData: "cmd:status"}},
			{{Text: "📜 规则管理 (启停)", CallbackData: "cmd:rules"}},
			{{Text: "💾 立即云端备份", CallbackData: "cmd:backup"}},
			{{Text: "🔄 远程重启面板", CallbackData: "cmd:restart"}},
		},
	}
	tgRequest("sendMessage", map[string]interface{}{
		"chat_id":      chatID,
		"text":         "🤖 <b>GoRelay Pro 智能中控台</b>\n\n请点击下方按钮执行快捷操作：",
		"parse_mode":   "HTML",
		"reply_markup": markup,
	})
}

func buildRulesMenuMarkup(page int) map[string]interface{} {
	var rows [][]InlineButton
	mu.Lock()
	defer mu.Unlock()

	pageSize := 10 // 每页显示的规则数量
	totalRules := len(rules)
	totalPages := (totalRules + pageSize - 1) / pageSize
	if totalPages == 0 {
		totalPages = 1
	}
	if page < 1 {
		page = 1
	}
	if page > totalPages {
		page = totalPages
	}

	start := (page - 1) * pageSize
	end := start + pageSize
	if end > totalRules {
		end = totalRules
	}

	// 渲染当前页的规则按钮
	for i := start; i < end; i++ {
		r := rules[i]
		status := "🟢"
		if r.Disabled {
			status = "🔴"
		}
		text := fmt.Sprintf("%s %s", status, r.Note)
		if r.Group != "" {
			text += fmt.Sprintf(" (%s)", r.Group)
		}
		// 回调数据中带上当前页码，以便操作后能停留在本页
		rows = append(rows, []InlineButton{{Text: text, CallbackData: fmt.Sprintf("toggle:%s:%d", r.ID, page)}})
	}

	// 渲染分页导航行
	var navRow []InlineButton
	if page > 1 {
		navRow = append(navRow, InlineButton{Text: "⬅️ 上一页", CallbackData: fmt.Sprintf("page:%d", page-1)})
	}
	navRow = append(navRow, InlineButton{Text: fmt.Sprintf("📄 %d / %d", page, totalPages), CallbackData: "noop"})
	if page < totalPages {
		navRow = append(navRow, InlineButton{Text: "下一页 ➡️", CallbackData: fmt.Sprintf("page:%d", page+1)})
	}
	rows = append(rows, navRow)

	// 底部返回按钮
	rows = append(rows, []InlineButton{{Text: "🔙 返回主菜单", CallbackData: "cmd:menu"}})
	return map[string]interface{}{"inline_keyboard": rows}
}

func startTgBotLoop() {
	// 顶层兜底：任何未预期的 panic 都不应终止整个 Master 进程
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[TG] 轮询协程发生 panic: %v，5 秒后自动重启轮询", r)
			time.Sleep(5 * time.Second)
			go startTgBotLoop()
		}
	}()

	var offset int64 = 0
	lastToken := ""

	for {
		mu.Lock()
		token := strings.TrimSpace(config.TgBotToken)
		allowedChat := strings.TrimSpace(config.TgChatID)
		mu.Unlock()

		if token == "" || allowedChat == "" {
			time.Sleep(10 * time.Second)
			continue
		}

		// Token 变更时：重置 offset（update_id 跨 Bot 不通用）、
		// 清理残留 webhook、重新注册命令菜单
		if token != lastToken {
			lastToken = token
			offset = 0
			tgLogBotIdentity(token, allowedChat)
			deleteTgWebhook(token)
			setupTgBotCommands()
			log.Printf("[TG] Bot Token 已加载，长轮询启动")
		}

		client := http.Client{Timeout: 65 * time.Second}
		urlStr := fmt.Sprintf("https://api.telegram.org/bot%s/getUpdates?offset=%d&timeout=60", token, offset)
		resp, err := client.Get(urlStr)
		if err != nil {
			log.Printf("[TG] getUpdates 网络错误: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		var res tgUpdatesResponse
		decodeErr := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&res)
		resp.Body.Close()
		if decodeErr != nil {
			log.Printf("[TG] getUpdates 响应解析失败: %v", decodeErr)
			time.Sleep(5 * time.Second)
			continue
		}

		// 关键：Telegram 用 HTTP 200 + ok=false 表达错误（典型如 409 Conflict），
		// 旧实现直接忽略该字段，导致机器人静默失效且不留任何痕迹。
		if !res.OK {
			log.Printf("[TG] getUpdates 被拒绝 code=%d desc=%s（若为 409 请确认没有 webhook 或其他实例占用同一 Token）",
				res.ErrorCode, res.Description)
			time.Sleep(10 * time.Second)
			continue
		}

		for _, update := range res.Result {
			offset = update.UpdateID + 1

			// 处理直接输入的指令
			if update.Message != nil {
				chatIdStr := fmt.Sprintf("%d", update.Message.Chat.ID)
				if chatIdStr != allowedChat {
					continue
				}
				text := strings.TrimSpace(update.Message.Text)
				// 兼容群组场景下的 /menu@YourBot 形式
				if strings.HasPrefix(text, "/") {
					if at := strings.Index(text, "@"); at > 0 {
						text = text[:at]
					}
				}
				switch text {
				case "/start", "/menu", "/help":
					sendTgMenu(chatIdStr)
				case "/status":
					// 复用内联回调分支，构造一个"无消息上下文"的伪回调
					update.CallbackQuery = &TgCallbackQuery{
						Data:    "cmd:status",
						Message: &TgMessage{Chat: TgChat{ID: update.Message.Chat.ID}},
					}
				case "/rules":
					update.CallbackQuery = &TgCallbackQuery{
						Data:    "cmd:rules",
						Message: &TgMessage{Chat: TgChat{ID: update.Message.Chat.ID}},
					}
				}
			}

			// 处理内联键盘回调
			if update.CallbackQuery != nil {
				// message 在官方定义中是可选项（inline 消息或原消息已被删除时缺失），
				// 旧实现直接解引用，一旦为 nil 就会 panic 并终止整个进程
				if update.CallbackQuery.Message == nil {
					if update.CallbackQuery.ID != "" {
						tgRequest("answerCallbackQuery", map[string]interface{}{"callback_query_id": update.CallbackQuery.ID})
					}
					log.Printf("[TG] 回调缺少 message 上下文，已忽略: data=%s", update.CallbackQuery.Data)
					continue
				}

				chatIdStr := fmt.Sprintf("%d", update.CallbackQuery.Message.Chat.ID)
				if chatIdStr != allowedChat {
					continue
				}

				if update.CallbackQuery.ID != "" {
					tgRequest("answerCallbackQuery", map[string]interface{}{"callback_query_id": update.CallbackQuery.ID})
				}

				data := update.CallbackQuery.Data
				msgID := update.CallbackQuery.Message.MessageID

				// 区分回调来源，避免误判：
				// - 真实按钮点击必然带非空 callback_query.id，且 message_id 恒 >= 1
				// - /status、/rules 等文本命令走的是内部伪造回调（id 为空、msgID 恒为 0）
				// 因此：点击按钮后若日志里没有"来源=按钮点击"的行，说明回调根本没送达。
				cbSrc := "按钮点击"
				if update.CallbackQuery.ID == "" {
					cbSrc = "文本命令"
				}
				log.Printf("[TG] 收到回调 | 来源=%s cbid=%s data=%s msgID=%d chat=%s",
					cbSrc, update.CallbackQuery.ID, data, msgID, chatIdStr)

				if data == "noop" {
					continue
				} else if data == "cmd:menu" {
					markup := map[string]interface{}{
						"inline_keyboard": [][]InlineButton{
							{{Text: "📊 节点与流量状态", CallbackData: "cmd:status"}},
							{{Text: "📜 规则管理 (启停)", CallbackData: "cmd:rules"}},
							{{Text: "💾 立即云端备份", CallbackData: "cmd:backup"}},
							{{Text: "🔄 远程重启面板", CallbackData: "cmd:restart"}},
						},
					}
					tgSendOrEdit("editMessageText", chatIdStr, msgID,
						"🤖 <b>GoRelay Pro 智能中控台</b>\n\n请点击下方按钮执行快捷操作：", markup)
				} else if data == "cmd:status" {
					mu.Lock()
					var tx, rx int64
					for _, r := range rules {
						tx += r.TotalTx
						rx += r.TotalRx
					}
					reply := fmt.Sprintf("📊 <b>系统实时状态</b>\n\n🌐 总中继流量: <b>%s</b>\n🔌 在线节点数: <b>%d</b>\n📜 转发规则数: <b>%d</b>\n\n--- 探针状态 ---\n", formatBytes(tx+rx), len(agents), len(rules))

					// === 新增 TG 节点排序逻辑 ===
					var sortedAgents []*AgentInfo
					for _, a := range agents {
						sortedAgents = append(sortedAgents, a)
					}
					sort.Slice(sortedAgents, func(i, j int) bool {
						t1 := config.AgentAddTimes[sortedAgents[i].Name]
						t2 := config.AgentAddTimes[sortedAgents[j].Name]
						if t1 == t2 {
							return sortedAgents[i].Name < sortedAgents[j].Name
						}
						return t1 < t2
					})

					// 将原来的 for _, a := range agents 改为遍历 sortedAgents
					for _, a := range sortedAgents {
						// === 新增：如果是离线节点，直接显示离线状态并跳过资源渲染 ===
						if !a.IsOnline {
							reply += fmt.Sprintf("💻 <b>%s</b> <code>[%s]</code> (🔴 离线)\n\n", tgEscape(a.Name), tgEscape(a.RemoteIP))
							continue
						}
						// =======================================================

						var cpu, mem, dsk float64
						parts := strings.Split(a.SysStatus, "|")
						for _, p := range parts {
							kv := strings.Split(p, ":")
							if len(kv) == 2 {
								v, _ := strconv.ParseFloat(kv[1], 64)
								if kv[0] == "CPU" {
									cpu = v
								}
								if kv[0] == "MEM" {
									mem = v
								}
								if kv[0] == "DSK" {
									dsk = v
								}
							}
						}
						reply += fmt.Sprintf("💻 <b>%s</b> <code>[%s]</code> (🟢 在线)\n", tgEscape(a.Name), tgEscape(a.RemoteIP))
						reply += fmt.Sprintf(" ├ 🟢 <code>CPU: %5.1f%% [%s]</code>\n", cpu, makeAestheticBar(cpu, "━", "─"))
						reply += fmt.Sprintf(" ├ 🔵 <code>MEM: %5.1f%% [%s]</code>\n", mem, makeAestheticBar(mem, "━", "─"))
						reply += fmt.Sprintf(" └ 🟡 <code>DSK: %5.1f%% [%s]</code>\n\n", dsk, makeAestheticBar(dsk, "━", "─"))
					}
					if len(agents) == 0 {
						reply += "⚠️ <i>暂无节点在线</i>\n\n"
					}
					mu.Unlock()

					// 查询近 30 天流量消耗趋势
					reply += "--- 历史流量趋势 ---\n"

					var total30Tx, total30Rx int64
					var historyLines []string
					if db != nil {
						dsRows, err := db.Query("SELECT date, tx, rx FROM daily_stats ORDER BY date DESC LIMIT 30")
						if err == nil {
							for dsRows.Next() {
								var d string
								var dTx, dRx int64
								dsRows.Scan(&d, &dTx, &dRx)
								total30Tx += dTx
								total30Rx += dRx

								if len(historyLines) < 10 {
									shortDate := d
									if len(d) == 10 {
										shortDate = d[5:]
									}
									historyLines = append(historyLines, fmt.Sprintf("📅 %s ⬆️%s ⬇️%s", shortDate, formatBytes(dTx), formatBytes(dRx)))
								}
							}
							// 显式关闭：本函数（startTgBotLoop）永不返回，
							// 若用 defer 会在每次查看状态时向 defer 链追加一条永不释放的记录。
							dsRows.Close()
						}
					}

					if len(historyLines) > 0 {
						reply += fmt.Sprintf("🗓️ <b>近 30 天总计: %s</b>\n", formatBytes(total30Tx+total30Rx))
						for _, line := range historyLines {
							reply += line + "\n"
						}
					} else {
						reply += "<i>暂无历史流量数据</i>\n"
					}

					nowTime := time.Now().Format("2006-01-02 15:04:05")
					reply += fmt.Sprintf("\n<blockquote expandable>🕒 探针最后同步时间: \n<code>%s</code></blockquote>", nowTime)

					markup := map[string]interface{}{
						"inline_keyboard": [][]InlineButton{{{Text: "🔙 返回主菜单", CallbackData: "cmd:menu"}, {Text: "🔄 刷新状态", CallbackData: "cmd:status"}}},
					}
					tgSendOrEdit("editMessageText", chatIdStr, msgID, reply, markup)
				} else if data == "cmd:rules" || strings.HasPrefix(data, "page:") {
					page := 1
					if strings.HasPrefix(data, "page:") {
						pStr := strings.TrimPrefix(data, "page:")
						if p, err := strconv.Atoi(pStr); err == nil {
							page = p
						}
					}
					tgSendOrEdit("editMessageText", chatIdStr, msgID,
						"📜 <b>转发规则管理</b>\n\n点击下方按钮可一键切换 启动/暂停 状态：",
						buildRulesMenuMarkup(page))
				} else if data == "cmd:backup" {
					go func() {
						// 1. 先发送到 Telegram
						sendTelegramDocument(DBFile, fmt.Sprintf("☁️ <b>手动云备份</b>\n\n数据库文件已成功导出。\n时间: %s", time.Now().Format("2006-01-02 15:04:05")))

						// 2. 触发 Cloudflare R2 备份
						if err := uploadToR2(DBFile); err == nil {
							sendTelegram("✅ <b>R2 容灾备份成功</b>\n手动触发的备份已同步至 Cloudflare R2。")
						} else if err.Error() != "R2 配置未启用" {
							sendTelegram("❌ <b>R2 备份失败</b>\n" + err.Error())
						}
					}()
				} else if strings.HasPrefix(data, "toggle:") {
					// 格式: toggle:id:page
					parts := strings.Split(data, ":")
					if len(parts) >= 2 {
						id := parts[1]
						page := 1
						if len(parts) >= 3 {
							p, _ := strconv.Atoi(parts[2])
							page = p
						}

						mu.Lock()
						for i := range rules {
							if rules[i].ID == id {
								rules[i].Disabled = !rules[i].Disabled
								break
							}
						}
						saveConfigNoLock()
						mu.Unlock()
						go pushConfigToAll()

						tgSendOrEdit("editMessageText", chatIdStr, msgID,
							"📜 <b>转发规则管理</b>\n\n状态已更新！点击下方按钮可继续切换：",
							buildRulesMenuMarkup(page))
					}
				} else if data == "cmd:restart" {
					// 增加二级确认防护
					markup := map[string]interface{}{
						"inline_keyboard": [][]InlineButton{
							{{Text: "⚠️ 确认重启", CallbackData: "action:confirm_restart"}},
							{{Text: "❌ 取消操作", CallbackData: "cmd:menu"}},
						},
					}
					tgSendOrEdit("editMessageText", chatIdStr, msgID,
						"⚠️ <b>危险操作确认</b>\n\n您正在尝试远程重启整个中控系统，这会导致所有网络连接短暂中断。确定要继续吗？",
						markup)
				} else if data == "action:confirm_restart" {
					tgSendOrEdit("editMessageText", chatIdStr, msgID,
						"🔄 接收到安全指令，系统正在执行重启...", nil)
					go func() {
						time.Sleep(2 * time.Second)
						doRestart()
					}()
				}
			}
		}
	}
}
