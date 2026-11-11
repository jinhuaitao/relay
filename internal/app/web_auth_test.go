package app

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsSameOrigin(t *testing.T) {
	cases := []struct {
		name   string
		host   string
		origin string
		want   bool
	}{
		{"同源带端口", "panel.example.com:8888", "http://panel.example.com:8888", true},
		{"无 Origin 放行", "panel.example.com:8888", "", true},
		{"跨站拒绝", "panel.example.com:8888", "http://evil.example", false},
		{"同主机不同端口拒绝", "panel.example.com:8888", "http://panel.example.com:9999", false},
		{"HTTPS 默认端口", "panel.example.com", "https://panel.example.com", true},
		{"HTTPS 端口不一致拒绝", "panel.example.com:8443", "https://panel.example.com", false},
		{"非法 scheme 拒绝", "panel.example.com", "javascript:alert(1)", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/update_settings", nil)
			r.Host = c.host
			if c.origin != "" {
				r.Header.Set("Origin", c.origin)
			}
			if got := isSameOrigin(r); got != c.want {
				t.Fatalf("isSameOrigin(%q, host=%q)=%v, want %v", c.origin, c.host, got, c.want)
			}
		})
	}
}

func TestIsStateChangingCoversAllGetMutations(t *testing.T) {
	mutating := []string{"/toggle", "/delete", "/reset_traffic", "/delete_agent",
		"/gen_agent_token", "/update_agent", "/restart", "/update_sys", "/logout", "/2fa/generate"}
	for _, path := range mutating {
		r := httptest.NewRequest(http.MethodGet, path+"?id=1", nil)
		if !isStateChanging(r) {
			t.Errorf("GET %s 必须纳入 CSRF 校验", path)
		}
	}
	if isStateChanging(httptest.NewRequest(http.MethodGet, "/export_logs", nil)) {
		t.Error("只读 GET 不应视为状态变更")
	}
	if !isStateChanging(httptest.NewRequest(http.MethodPost, "/anything", nil)) {
		t.Error("所有非 GET 请求都应校验")
	}
}

func TestEqualHostIgnoresCaseButNotPort(t *testing.T) {
	if !equalHost("PANEL.Example.com:8888", "panel.example.com:8888", "http") {
		t.Error("主机名比较应忽略大小写")
	}
	if equalHost("panel.example.com:8888", "panel.example.com:9999", "http") {
		t.Error("端口不同不应视为同源")
	}
	if !equalHost("panel.example.com", "panel.example.com", "https") {
		t.Error("HTTPS 默认端口应视为一致")
	}
}
