// telegram_backup.go — Telegram 云备份：脱敏 + 加密后发送、R2 上传、定时任务
//
// 外发文件一律由 createSecureBackup 生成（剥离全部凭据 + AES-256-GCM 加密）。
// 未配置备份口令时不发送任何内容，绝不回退成明文 data.db。

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// sendTelegramDocument 发送一份已经脱敏并加密的独立文件。
func sendTelegramDocument(filePath string, caption string) {
	mu.Lock()
	token := strings.TrimSpace(config.TgBotToken)
	chatID := strings.TrimSpace(config.TgChatID)
	mu.Unlock()
	if token == "" || chatID == "" {
		return
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

	fileName := fmt.Sprintf("gorelay_backup_%s%s", time.Now().Format("20060102_150405"), BackupExt)
	part, err := writer.CreateFormFile("document", fileName)
	if err == nil {
		_, _ = io.Copy(part, file)
	}
	_ = writer.Close()

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

	if ak == "" || sk == "" || endpoint == "" || bucket == "" {
		return fmt.Errorf("R2 配置未启用")
	}

	endpoint = strings.TrimPrefix(endpoint, "https://")
	endpoint = strings.TrimPrefix(endpoint, "http://")

	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(ak, sk, ""),
		Secure: true,
	})
	if err != nil {
		return err
	}

	fileName := fmt.Sprintf("gorelay_backup_%s%s", time.Now().Format("20060102_150405"), BackupExt)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	_, err = client.FPutObject(ctx, bucket, fileName, filePath, minio.PutObjectOptions{
		ContentType: "application/octet-stream",
	})
	return err
}

// performCloudBackup 是手动/自动备份的唯一出口。
func performCloudBackup() error {
	encPath, err := createSecureBackup()
	if err != nil {
		return err
	}
	defer os.Remove(encPath)

	caption := fmt.Sprintf("☁️ <b>GoRelay 云备份</b>\n\n已剥离全部凭据，并使用面板备份口令加密（AES-256-GCM）。\n解密: relay -decrypt-backup=文件.db.enc\n时间: %s", time.Now().Format("2006-01-02 15:04:05"))
	sendTelegramDocument(encPath, caption)

	if err := uploadToR2(encPath); err != nil && err.Error() != "R2 配置未启用" {
		return fmt.Errorf("TG 已发送，但 R2 备份失败: %w", err)
	}
	return nil
}

func autoBackupLoop() {
	var lastWarnDate string
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
		if !backupPassphraseConfigured() {
			if lastWarnDate != today {
				lastWarnDate = today
				log.Printf("⚠️ 未配置备份口令，已跳过云备份（不会外发明文数据库）")
				sendTelegram("⚠️ <b>云备份已跳过</b>\n\n尚未配置备份口令，系统不会外发明文数据库。请在 系统设置 → 备份口令 中填写。")
			}
			continue
		}

		if now.Weekday() != time.Monday || now.Hour() < 2 || lastTgBackupDate == today {
			continue
		}
		if err := performCloudBackup(); err != nil {
			log.Printf("⚠️ 自动云备份失败: %v", err)
			sendTelegram("❌ <b>自动云备份失败</b>\n" + tgEscape(err.Error()))
			continue // 不标记幂等键，10 分钟后自动重试
		}
		lastTgBackupDate = today
		if db != nil {
			_, _ = db.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('last_backup_date', ?)", today)
		}
		sendTelegram("✅ <b>自动云备份完成</b>\n本周备份已脱敏并加密后发送。")
	}
}
