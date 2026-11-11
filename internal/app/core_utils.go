// utils.go — 通用工具：UUID/Salt/口令散列、客户端 IP、操作日志、版本号比较
//
// 安全相关约定：
//   - 转发头（XFF / CF-Connecting-IP）默认一律不可信，只有 RemoteAddr 命中
//     TrustedProxies 白名单时才解析，否则防爆破与日志 IP 都可被任意伪造。
//   - 日志字段统一清洗控制字符，避免日志成为前端注入的载体。

package app

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	argonTime    = 1
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
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
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// hashNewPassword 生成新版口令散列：argon2id，格式 "a2$<saltHex>$<hashHex>"。
func hashNewPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return "a2$" + hex.EncodeToString(salt) + "$" + hex.EncodeToString(key), nil
}

// verifyPassword 同时兼容三种历史格式，登录成功后由调用方自动升级为 argon2id。
func verifyPassword(stored, input string) bool {
	parts := strings.Split(stored, "$")
	switch {
	case len(parts) == 3 && parts[0] == "a2":
		salt, err := hex.DecodeString(parts[1])
		if err != nil {
			return false
		}
		want, err := hex.DecodeString(parts[2])
		if err != nil || len(want) < 16 {
			return false
		}
		got := argon2.IDKey([]byte(input), salt, argonTime, argonMemory, argonThreads, uint32(len(want)))
		return subtle.ConstantTimeCompare(got, want) == 1
	case len(parts) == 2:
		return subtle.ConstantTimeCompare([]byte(hashPassword(input, parts[0])), []byte(parts[1])) == 1
	case len(parts) == 1 && len(stored) == 32:
		return subtle.ConstantTimeCompare([]byte(md5Hash(input)), []byte(stored)) == 1
	}
	return false
}

func needsPasswordUpgrade(stored string) bool {
	return !strings.HasPrefix(stored, "a2$")
}

// hashPassword / md5Hash 仅用于校验旧版本遗留的口令格式，新代码请勿直接调用。
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

// setTrustedProxies 解析并原子替换可信代理网段列表。
func setTrustedProxies(spec string) {
	var nets []*net.IPNet
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			if _, n, err := net.ParseCIDR(part); err == nil {
				nets = append(nets, n)
			}
			continue
		}
		if ip := net.ParseIP(part); ip != nil {
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
	}
	trustedProxyNets.Store(nets)
}

func trustedProxy(remote string) bool {
	v := trustedProxyNets.Load()
	if v == nil {
		return false
	}
	ip := net.ParseIP(remote)
	if ip == nil {
		return false
	}
	for _, n := range v.([]*net.IPNet) {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// getClientIP 返回可用于限速与审计的客户端 IP。
// 只有 TCP 对端确实位于可信代理白名单内，才采信其携带的转发头。
func getClientIP(r *http.Request) string {
	if r == nil {
		return "System"
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	host = strings.Trim(host, "[]")

	if trustedProxy(host) {
		for _, header := range []string{"CF-Connecting-IP", "X-Forwarded-For"} {
			raw := r.Header.Get(header)
			if raw == "" {
				continue
			}
			for _, part := range strings.Split(raw, ",") {
				candidate := strings.Trim(strings.TrimSpace(part), "[]")
				if ip := net.ParseIP(candidate); ip != nil {
					return ip.String()
				}
			}
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return host
}

// isLoopbackRequest 判断请求是否来自本机（127.0.0.0/8 或 ::1）。
// 只看 TCP 层 RemoteAddr，绝不使用可被伪造的转发头做本机判定。
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

// cleanLogField 去掉控制字符并限长，日志内容后续可能被前端渲染。
func cleanLogField(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return ' '
		}
		return r
	}, s)
	if len(s) > 512 {
		s = s[:512]
	}
	return s
}

func addLog(r *http.Request, action, msg string) {
	ip := cleanLogField(getClientIP(r))
	now := time.Now().Format("01-02 15:04:05")
	category := categorizeLog(action)
	if db != nil {
		_, _ = db.Exec("INSERT INTO logs (time, ip, category, action, msg) VALUES (?,?,?,?,?)",
			now, ip, category, cleanLogField(action), cleanLogField(msg))
	}
}

func addSystemLog(ip, action, msg string) {
	now := time.Now().Format("01-02 15:04:05")
	category := categorizeLog(action)
	if db != nil {
		_, _ = db.Exec("INSERT INTO logs (time, ip, category, action, msg) VALUES (?,?,?,?,?)",
			now, cleanLogField(ip), category, cleanLogField(action), cleanLogField(msg))
	}
}

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

// safeServiceArg 校验将写入 systemd/OpenRC 单元的参数，拒绝引号、空白与 shell 元字符。
func safeServiceArg(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("._-:@/+", r):
		case r >= 0x80: // 允许中文节点名，但不含 ASCII 控制/元字符
		default:
			return false
		}
	}
	return true
}
