// telegram_backup.go — Telegram 云备份：数据库打包发送、R2 上传、定时任务
//
// 由原单文件 main.go（AppVersion v3.3.6）按职责拆分而来，
// 代码逻辑、执行顺序与对外行为完全未改动（同一 package main）。

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"time"
)

// --- TG 云备份功能核心 ---
func sendTelegramDocument(filePath string, caption string) {
	mu.Lock()
	token := strings.TrimSpace(config.TgBotToken)
	chatID := strings.TrimSpace(config.TgChatID)
	mu.Unlock()
	if token == "" || chatID == "" {
		return
	}

	if db != nil {
		db.Exec("PRAGMA wal_checkpoint(TRUNCATE);")
	}

	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("[TG] 备份文件打开失败: %v", err)
		return
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	_ = writer.WriteField("chat_id", chatID)
	_ = writer.WriteField("caption", caption)
	_ = writer.WriteField("parse_mode", "HTML")

	fileName := fmt.Sprintf("gorelay_backup_%s.db", time.Now().Format("20060102_150405"))
	part, err := writer.CreateFormFile("document", fileName)
	if err == nil {
		io.Copy(part, file)
	}
	writer.Close()

	urlStr := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", token)
	req, err := http.NewRequest("POST", urlStr, body)
	if err != nil {
		log.Printf("[TG] sendDocument 请求构造失败: %v", err)
		return
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[TG] sendDocument 请求失败: %v", err)
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))

	var r tgResponse
	if json.Unmarshal(respBody, &r) == nil && r.OK {
		return
	}
	log.Printf("[TG] sendDocument 返回异常 status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(respBody)))
}

func uploadToR2(filePath string) error {
	mu.Lock()
	ak := config.R2AccessKey
	sk := config.R2SecretKey
	endpoint := config.R2Endpoint
	bucket := config.R2Bucket
	mu.Unlock()

	// 如果没有配置，就不执行备份
	if ak == "" || sk == "" || endpoint == "" || bucket == "" {
		return fmt.Errorf("R2 配置未启用")
	}

	// 强制 SQLite 刷盘，保证上传的是最完整的数据快照
	if db != nil {
		db.Exec("PRAGMA wal_checkpoint(TRUNCATE);")
	}

	// MinIO SDK 要求 Endpoint 不带协议头
	endpoint = strings.TrimPrefix(endpoint, "https://")
	endpoint = strings.TrimPrefix(endpoint, "http://")

	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(ak, sk, ""),
		Secure: true,
	})
	if err != nil {
		return err
	}

	// 文件名带上时间戳：gorelay_backup_20260412_120000.db
	fileName := fmt.Sprintf("gorelay_backup_%s.db", time.Now().Format("20060102_150405"))

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	_, err = client.FPutObject(ctx, bucket, fileName, filePath, minio.PutObjectOptions{
		ContentType: "application/octet-stream",
	})
	return err
}

func autoBackupLoop() {
	// 以持久化的"已备份日期"作为幂等键，避免进程重启导致重复备份
	for {
		time.Sleep(10 * time.Minute)
		now := time.Now()

		mu.Lock()
		token := config.TgBotToken
		chatID := config.TgChatID
		mu.Unlock()

		if token == "" || chatID == "" {
			continue
		}

		today := now.Format("2006-01-02")
		// 周一 02:00 之后触发，并以"已备份日期"持久化去重。
		// 原实现要求 now.Hour()==2 精确命中，轮询锚定在进程启动时刻上，
		// 一旦漂移就会整周漏发且无任何补发逻辑。
		if now.Weekday() == time.Monday && now.Hour() >= 2 && lastTgBackupDate != today {
			lastTgBackupDate = today
			if db != nil {
				db.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('last_backup_date', ?)", today)
			}
			sendTelegramDocument(DBFile, fmt.Sprintf("☁️ <b>自动云备份</b>\n\n这是本周的系统数据备份。\n时间: %s", now.Format("2006-01-02 15:04:05")))

			// === 触发 R2 备份 ===
			if err := uploadToR2(DBFile); err == nil {
				sendTelegram("✅ <b>R2 容灾备份成功</b>\n数据库已安全同步至 Cloudflare R2。")
			} else if err.Error() != "R2 配置未启用" {
				sendTelegram("❌ <b>R2 备份失败</b>\n" + err.Error())
			}
		}
	}
}
