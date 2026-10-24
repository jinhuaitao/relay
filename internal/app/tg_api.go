// telegram.go — Telegram Bot 基础能力：HTTP 调用、消息分片、发送/编辑、命令注册
//
// 由原单文件 main.go（AppVersion v3.3.6）按职责拆分而来，
// 代码逻辑、执行顺序与对外行为完全未改动（同一 package main）。

package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// tgToken 在锁保护下读取当前 Bot Token
func tgToken() string {
	mu.Lock()
	defer mu.Unlock()
	return strings.TrimSpace(config.TgBotToken)
}

// tgResponse 是 Telegram API 的统一响应信封，用于判断 ok / error_code
type tgResponse struct {
	OK          bool   `json:"ok"`
	ErrorCode   int    `json:"error_code"`
	Description string `json:"description"`
}

// tgRequest 异步调用 Telegram API。
// 与旧实现的区别：会读取响应体并检查 ok 字段，任何非 ok 结果都会写入日志，
// 避免"消息发不出去但毫无痕迹"的静默失败。
func tgRequest(method string, payload interface{}) {
	token := tgToken()
	if token == "" {
		return
	}

	urlStr := fmt.Sprintf("https://api.telegram.org/bot%s/%s", token, method)
	b, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[TG] %s 载荷序列化失败: %v", method, err)
		return
	}

	go func() {
		req, err := http.NewRequest("POST", urlStr, bytes.NewBuffer(b))
		if err != nil {
			log.Printf("[TG] %s 请求构造失败: %v", method, err)
			return
		}
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[TG] %s 请求失败(网络不可达/超时): %v", method, err)
			return
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))

		var r tgResponse
		if json.Unmarshal(body, &r) == nil && r.OK {
			return
		}

		// editMessageText 在内容未变化时必然返回该错误，属于预期行为，静默忽略
		if r.ErrorCode == 400 && strings.Contains(r.Description, "message is not modified") {
			return
		}

		log.Printf("[TG] %s 调用失败 status=%d code=%d desc=%s body=%s",
			method, resp.StatusCode, r.ErrorCode, r.Description, strings.TrimSpace(string(body)))
	}()
}

// deleteTgWebhook 清除 Bot 上可能残留的 webhook。
// 若 webhook 处于激活状态，getUpdates 会永久返回 409 Conflict，导致机器人完全无响应。
func deleteTgWebhook(token string) {
	urlStr := fmt.Sprintf("https://api.telegram.org/bot%s/deleteWebhook?drop_pending_updates=false", token)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(urlStr)
	if err != nil {
		log.Printf("[TG] deleteWebhook 请求失败: %v", err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))

	var r tgResponse
	if json.Unmarshal(body, &r) == nil && r.OK {
		log.Printf("[TG] deleteWebhook 成功，长轮询通道已就绪")
		return
	}
	log.Printf("[TG] deleteWebhook 返回异常: %s", strings.TrimSpace(string(body)))
}

// tgLogBotIdentity 在启动时打印 Bot 身份与授权 Chat ID。
// 用于快速确认"面板里填的 Token 与 Chat ID 是否配对"——
// 若 Token 与菜单消息所属的 Bot 不一致，按钮回调将永远无人应答。
func tgLogBotIdentity(token, allowedChat string) {
	urlStr := fmt.Sprintf("https://api.telegram.org/bot%s/getMe", token)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(urlStr)
	if err != nil {
		log.Printf("[TG] getMe 请求失败: %v", err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	var r struct {
		OK     bool `json:"ok"`
		Result struct {
			ID        int64  `json:"id"`
			Username  string `json:"username"`
			FirstName string `json:"first_name"`
		} `json:"result"`
	}
	if json.Unmarshal(body, &r) != nil || !r.OK {
		log.Printf("[TG] getMe 返回异常，Token 可能已失效: %s", strings.TrimSpace(string(body)))
		return
	}
	log.Printf("[TG] 当前 Bot: @%s (%s, id=%d)", r.Result.Username, r.Result.FirstName, r.Result.ID)
	log.Printf("[TG] 授权 Chat ID: %s（请确认与该 Bot 对话窗口的 Chat ID 一致）", allowedChat)
}

// tgTextLimit 是 Telegram 单条消息正文的硬上限（官方 4096，留出安全余量）
const tgTextLimit = 4000

// tgChunks 按行边界把长文本切分为多个不超过 limit 的片段。
// 直接对 rune 切片做区间切割，拼接结果与原文本严格相等；
// 优先在换行处断开，避免把 HTML 标签截成两半。
func tgChunks(text string, limit int) []string {
	runes := []rune(text)
	if len(runes) <= limit {
		return []string{text}
	}

	var chunks []string
	start := 0
	for start < len(runes) {
		end := start + limit
		if end >= len(runes) {
			end = len(runes)
		} else {
			// 向前回溯到最近的换行符（含换行本身）
			for i := end - 1; i > start; i-- {
				if runes[i] == '\n' {
					end = i + 1
					break
				}
			}
		}
		chunks = append(chunks, string(runes[start:end]))
		start = end
	}

	if len(chunks) == 0 {
		return []string{""}
	}
	return chunks
}

// tgCall 同步调用 Telegram API 并返回结果。
// 与 tgRequest 的区别：会阻塞等待响应，因此可以据此实现"失败降级"。
// 第二个返回值非空即表示失败，内容为可直接定位问题的详情。
func tgCall(method string, payload interface{}, timeout time.Duration) (*tgResponse, string) {
	token := tgToken()
	if token == "" {
		return nil, "未配置 Bot Token"
	}

	urlStr := fmt.Sprintf("https://api.telegram.org/bot%s/%s", token, method)
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, "载荷序列化失败: " + err.Error()
	}

	req, err := http.NewRequest("POST", urlStr, bytes.NewBuffer(b))
	if err != nil {
		return nil, "请求构造失败: " + err.Error()
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "网络错误: " + err.Error()
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))

	var r tgResponse
	if json.Unmarshal(body, &r) == nil && r.OK {
		return &r, ""
	}
	return &r, fmt.Sprintf("status=%d code=%d desc=%s body=%s",
		resp.StatusCode, r.ErrorCode, r.Description, strings.TrimSpace(string(body)))
}

// tgSendOrEdit 统一的"发送或编辑"出口。
//   - action 为 editMessageText 且 msgID 有效时优先编辑；
//     **编辑失败会自动降级为 sendMessage 重发**，保证用户一定能看到反馈，
//     并把失败原因写入日志（这是定位"点按钮没反应"的关键）；
//   - 超长文本自动分片，最后一片才挂载 reply_markup，避免键盘重复出现；
//   - sendMessage 不再携带无意义的 message_id 字段。
func tgSendOrEdit(action, chatID string, msgID int64, text string, markup map[string]interface{}) {
	chunks := tgChunks(text, tgTextLimit)
	go func() {
		for i, ch := range chunks {
			payload := map[string]interface{}{
				"chat_id":    chatID,
				"text":       ch,
				"parse_mode": "HTML",
			}
			if i == len(chunks)-1 && markup != nil {
				payload["reply_markup"] = markup
			}

			if i == 0 && action == "editMessageText" && msgID != 0 {
				payload["message_id"] = msgID
				r, detail := tgCall("editMessageText", payload, 12*time.Second)
				if r != nil && r.OK {
					continue
				}
				// 内容未发生变化属于正常情况，静默跳过，不降级重发
				if r != nil && r.ErrorCode == 400 && strings.Contains(r.Description, "message is not modified") {
					continue
				}
				log.Printf("[TG] editMessageText 失败，降级为发送新消息 | %s", detail)
				delete(payload, "message_id")
				if _, d2 := tgCall("sendMessage", payload, 12*time.Second); d2 != "" {
					log.Printf("[TG] 降级 sendMessage 亦失败 | %s", d2)
				}
				continue
			}

			if _, detail := tgCall("sendMessage", payload, 12*time.Second); detail != "" {
				log.Printf("[TG] sendMessage 失败 | %s", detail)
			}
		}
	}()
}

// tgEscape 转义将被嵌入 HTML parse_mode 的动态内容。
// 未转义的 & / < / > 会让 Telegram 返回 400 can't parse entities，导致整条消息丢失。
func tgEscape(s string) string {
	return html.EscapeString(s)
}

func sendTelegram(text string) {
	mu.Lock()
	chatID := strings.TrimSpace(config.TgChatID)
	mu.Unlock()
	if chatID == "" || tgToken() == "" {
		return
	}
	tgSendOrEdit("sendMessage", chatID, 0, text, nil)
}

// 终极美学进度条：支持传入自定义的 UI 设计字符
func makeAestheticBar(percent float64, fillChar, emptyChar string) string {
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}

	totalWidth := 12 // 12格是极简符号的视觉黄金比例

	filledBlocks := int((percent / 100.0) * float64(totalWidth))

	// 保证只要有占用，就至少亮起一格，避免 1% 显示为空
	if percent > 0 && filledBlocks == 0 {
		filledBlocks = 1
	}
	if filledBlocks > totalWidth {
		filledBlocks = totalWidth
	}

	emptyBlocks := totalWidth - filledBlocks

	return strings.Repeat(fillChar, filledBlocks) + strings.Repeat(emptyChar, emptyBlocks)
}

// 向 Telegram 自动注册原生快捷菜单 (Menu Button)
func setupTgBotCommands() {
	token := tgToken()
	if token == "" {
		return
	}

	commands := []map[string]string{
		{"command": "menu", "description": "🎛️ 打开智能中控台主菜单"},
		{"command": "status", "description": "📊 查看节点与实时流量状态"},
		{"command": "rules", "description": "📜 管理转发规则 (启停)"},
	}

	urlStr := fmt.Sprintf("https://api.telegram.org/bot%s/setMyCommands", token)
	b, _ := json.Marshal(map[string]interface{}{"commands": commands})

	go func() {
		req, err := http.NewRequest("POST", urlStr, bytes.NewBuffer(b))
		if err != nil {
			log.Printf("[TG] setMyCommands 请求构造失败: %v", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[TG] setMyCommands 请求失败: %v", err)
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))

		var r tgResponse
		if json.Unmarshal(body, &r) == nil && r.OK {
			log.Printf("[TG] 命令菜单注册成功")
			return
		}
		log.Printf("[TG] setMyCommands 返回异常: %s", strings.TrimSpace(string(body)))
	}()
}
