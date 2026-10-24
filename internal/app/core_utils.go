// utils.go — 通用工具：UUID/Salt/口令散列、客户端 IP、操作日志、版本号比较
//
// 由原单文件 main.go（AppVersion v3.3.6）按职责拆分而来，
// 代码逻辑、执行顺序与对外行为完全未改动（同一 package main）。

package app

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func generateUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func generateSalt() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func hashPassword(password, salt string) string {
	h := sha256.New()
	h.Write([]byte(salt + password))
	return hex.EncodeToString(h.Sum(nil))
}

func md5Hash(s string) string {
	h := md5.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

func getClientIP(r *http.Request) string {
	if r == nil {
		return "System"
	}
	if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		ips := strings.Split(ip, ",")
		return strings.TrimSpace(ips[0])
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

// categorizeLog 根据操作类型关键字自动推断日志分类，向后兼容无显式分类的调用
func categorizeLog(action string) string {
	switch {
	case strings.Contains(action, "登录") || strings.Contains(action, "登出") || strings.Contains(action, "退出") || strings.Contains(action, "登陆"):
		return "login"
	case strings.Contains(action, "上线") || strings.Contains(action, "下线") || strings.Contains(action, "节点") || strings.Contains(action, "卸载"):
		return "node"
	case strings.Contains(action, "规则") || strings.Contains(action, "流量"):
		return "rule"
	case strings.Contains(action, "配置") || strings.Contains(action, "设置"):
		return "config"
	default:
		return "system"
	}
}

func addLog(r *http.Request, action, msg string) {
	ip := getClientIP(r)
	now := time.Now().Format("01-02 15:04:05")
	category := categorizeLog(action)
	if db != nil {
		_, _ = db.Exec("INSERT INTO logs (time, ip, category, action, msg) VALUES (?,?,?,?,?)", now, ip, category, action, msg)
	}
}

func addSystemLog(ip, action, msg string) {
	now := time.Now().Format("01-02 15:04:05")
	category := categorizeLog(action)
	if db != nil {
		_, _ = db.Exec("INSERT INTO logs (time, ip, category, action, msg) VALUES (?,?,?,?,?)", now, ip, category, action, msg)
	}
}

// compareVersions 语义化版本比较，返回 >0 表示 a 更新、<0 表示 b 更新、0 表示相等
func compareVersions(a, b string) int {
	pa := strings.Split(a, ".")
	pb := strings.Split(b, ".")
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(strings.SplitN(pa[i], "-", 2)[0])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(strings.SplitN(pb[i], "-", 2)[0])
		}
		if x > y {
			return 1
		}
		if x < y {
			return -1
		}
	}
	return 0
}

func formatBytes(b int64) string {
	const u = 1024
	if b < u {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(u), 0
	for n := b / u; n >= u; n /= u {
		div *= u
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
