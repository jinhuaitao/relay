package app

import (
	"net/http"
	"strings"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"3.4.3", "3.4.2", 1},
		{"3.4.2", "3.4.3", -1},
		{"3.4.3", "3.4.3", 0},
		{"3.10.0", "3.9.9", 1},
		{"4.0", "3.99.99", 1},
		{"3.4.3-beta", "3.4.3", 0},
		{"3.4", "3.4.0", 0},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q,%q)=%d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestFormatBytes(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.00 KB"},
		{1024 * 1024, "1.00 MB"},
		{3 * 1024 * 1024 * 1024, "3.00 GB"},
	}
	for _, c := range cases {
		if got := formatBytes(c.in); got != c.want {
			t.Errorf("formatBytes(%d)=%q, want %q", c.in, got, c.want)
		}
	}
}

func TestVerifyPasswordBcrypt(t *testing.T) {
	h, err := hashPasswordBcrypt("s3cret!")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$2") {
		t.Fatalf("expected bcrypt hash, got %q", h)
	}
	if !verifyPassword(h, "s3cret!") {
		t.Error("bcrypt verify should succeed")
	}
	if verifyPassword(h, "wrong") {
		t.Error("bcrypt verify should fail for wrong password")
	}
}

func TestVerifyPasswordLegacyFormats(t *testing.T) {
	salt := "abcd1234"
	salted := salt + "$" + hashPassword("pw", salt)
	if !verifyPassword(salted, "pw") {
		t.Error("salted sha256 verify failed")
	}
	if verifyPassword(salted, "nope") {
		t.Error("salted sha256 accepted wrong password")
	}
	md5Stored := md5Hash("pw")
	if !verifyPassword(md5Stored, "pw") {
		t.Error("legacy md5 verify failed")
	}
	if verifyPassword("", "") {
		t.Error("empty stored hash must never match")
	}
}

func reqWithRemote(remote string, headers map[string]string) *http.Request {
	r := &http.Request{RemoteAddr: remote, Header: make(http.Header)}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestGetClientIPTrustBoundary(t *testing.T) {
	// Cloudflare 官方网段内的对端：采纳 CF-Connecting-IP
	r := reqWithRemote("104.16.1.2:443", map[string]string{"CF-Connecting-IP": "203.0.113.9"})
	if got := getClientIP(r); got != "203.0.113.9" {
		t.Errorf("CF peer: got %q", got)
	}

	// 公网直连（非 CF）：伪造的 CF-Connecting-IP / XFF 一律忽略
	r = reqWithRemote("198.51.100.7:5555", map[string]string{
		"CF-Connecting-IP": "203.0.113.9",
		"X-Forwarded-For":  "203.0.113.9",
	})
	if got := getClientIP(r); got != "198.51.100.7" {
		t.Errorf("public peer must ignore spoofed headers, got %q", got)
	}

	// 本机反代：采纳 XFF 第一段
	r = reqWithRemote("127.0.0.1:9000", map[string]string{"X-Forwarded-For": "203.0.113.9, 10.0.0.1"})
	if got := getClientIP(r); got != "203.0.113.9" {
		t.Errorf("loopback proxy: got %q", got)
	}

	// 内网反代同样可信
	r = reqWithRemote("192.168.1.10:9000", map[string]string{"X-Forwarded-For": "203.0.113.9"})
	if got := getClientIP(r); got != "203.0.113.9" {
		t.Errorf("private proxy: got %q", got)
	}

	// 非法头内容回退到 RemoteAddr
	r = reqWithRemote("127.0.0.1:9000", map[string]string{"X-Forwarded-For": "not-an-ip"})
	if got := getClientIP(r); got != "127.0.0.1" {
		t.Errorf("invalid header must fall back, got %q", got)
	}

	if got := getClientIP(nil); got != "System" {
		t.Errorf("nil request: got %q", got)
	}
}

func TestIsLoopbackRequest(t *testing.T) {
	if !isLoopbackRequest(reqWithRemote("127.0.0.1:1234", nil)) {
		t.Error("127.0.0.1 should be loopback")
	}
	if !isLoopbackRequest(reqWithRemote("[::1]:1234", nil)) {
		t.Error("::1 should be loopback")
	}
	// 伪造头不能把公网请求变成本机
	r := reqWithRemote("198.51.100.7:1234", map[string]string{"X-Forwarded-For": "127.0.0.1"})
	if isLoopbackRequest(r) {
		t.Error("spoofed XFF must not grant loopback")
	}
}

func TestTokenMatches(t *testing.T) {
	if !tokenMatches("abc123", "abc123") {
		t.Error("equal tokens must match")
	}
	if tokenMatches("abc123", "abc124") {
		t.Error("different tokens must not match")
	}
	if tokenMatches("", "") {
		t.Error("empty want must never match")
	}
}

func TestEqualHostAndSameOrigin(t *testing.T) {
	if !equalHost("panel.example.com:443", "PANEL.example.com") {
		t.Error("host compare should ignore port and case")
	}
	if equalHost("evil.com", "panel.example.com") {
		t.Error("different hosts must not match")
	}

	r := reqWithRemote("1.2.3.4:1", map[string]string{"Origin": "https://panel.example.com"})
	r.Host = "panel.example.com"
	if !isSameOrigin(r) {
		t.Error("matching origin should pass")
	}
	r.Header.Set("Origin", "https://evil.com")
	if isSameOrigin(r) {
		t.Error("cross origin must be rejected")
	}
	r.Header.Del("Origin")
	if !isSameOrigin(r) {
		t.Error("missing origin/referer falls back to SameSite cookie defense")
	}
}