// utils.go — 通用工具：UUID/Salt/口令散列、客户端 IP、操作日志、版本号比较
//
// 由原单文件 main.go（AppVersion v3.3.6）按职责拆分而来，
// 代码逻辑、执行顺序与对外行为完全未改动（同一 package main）。

package app

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
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

// hashPasswordBcrypt 是新口令的唯一散列方式（自适应成本，抗 GPU 爆破）。
func hashPasswordBcrypt(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(b), err
}

// verifyPassword 兼容三代存储格式：bcrypt、加盐 SHA256（salt$hash）、旧版无盐 MD5。
// 后两种仅为存量数据保留，登录成功后由调用方升级为 bcrypt。
func verifyPassword(stored, password string) bool {
	if stored == "" {
		return false
	}
	if strings.HasPrefix(stored, "$2") {
		return bcrypt.CompareHashAndPassword([]byte(stored), []byte(password)) == nil
	}
	parts := strings.Split(stored, "$")
	if len(parts) == 2 {
		return hashPassword(password, parts[0]) == parts[1]
	}
	return md5Hash(password) == stored
}

// cloudflareNets 是 Cloudflare 官方公布的回源网段。
// CF-Connecting-IP 只有在这批网段直连时才可信，否则任何人都能伪造该头
// 绕过登录防爆破封禁、污染审计日志。
var cloudflareNets = func() []*net.IPNet {
	cidrs := []string{
		"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
		"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
		"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
		"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
		"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
		"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
	}
	var nets []*net.IPNet
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}()

func isCloudflareIP(ip net.IP) bool {
	for _, n := range cloudflareNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// getClientIP 只在可信来源下采纳代理头：
//   - CF-Connecting-IP：仅当 TCP 层对端属于 Cloudflare 官方网段；
//   - X-Forwarded-For：仅当对端是本机/内网（本机反代场景）。
//
// 其余情况一律使用 TCP 层 RemoteAddr，伪造头不再影响封禁与日志。
func getClientIP(r *http.Request) string {
	if r == nil {
		return "System"
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remote := net.ParseIP(host)
	if remote != nil {
		if isCloudflareIP(remote) {
			if ip := r.Header.Get("CF-Connecting-IP"); ip != "" && net.ParseIP(ip) != nil {
				return ip
			}
		}
		if remote.IsLoopback() || remote.IsPrivate() {
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				first := strings.TrimSpace(strings.Split(xff, ",")[0])
				if net.ParseIP(first) != nil {
					return first
				}
			}
		}
	}
	return host
}

// isLoopbackRequest 判断请求是否来自本机（127.0.0.0/8 或 ::1）。
// 注意：这里必须只看 TCP 层的 RemoteAddr，不能信任 X-Forwarded-For /
// CF-Connecting-IP —— 那些头可被伪造，用它做"本机"判定等于没有校验。
func isLoopbackRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// enableKeepAlive 在底层 TCP 连接上开启 keepalive 探测。
// 没有它，节点断电或链路黑洞时内核要等默认的十几分钟重传超时才会报错，
// 期间面板会一直把死节点显示为"在线"。
func enableKeepAlive(c net.Conn) {
	if c == nil {
		return
	}
	var tcp *net.TCPConn
	switch v := c.(type) {
	case *net.TCPConn:
		tcp = v
	case *tls.Conn:
		if tc, ok := v.NetConn().(*net.TCPConn); ok {
			tcp = tc
		}
	}
	if tcp == nil {
		return
	}
	_ = tcp.SetKeepAlive(true)
	_ = tcp.SetKeepAlivePeriod(TCPKeepAlive)
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
