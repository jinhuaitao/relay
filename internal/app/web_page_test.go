package app

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// TestHandleDashboardDoesNotLeakSecrets 验证模板能正常渲染，且任何凭据都不会
// 出现在返回给浏览器的 HTML 里（历史上曾把完整 AppConfig 注入模板）。
func TestHandleDashboardDoesNotLeakSecrets(t *testing.T) {
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldwd)

	oldDB, oldConf, oldTLS := db, config, isMasterTLS
	defer func() {
		if db != nil {
			_ = db.Close()
		}
		db, config, isMasterTLS = oldDB, oldConf, oldTLS
	}()

	initDB()
	config = AppConfig{
		WebUser: "admin", WebPass: "HASH-SECRET", AgentToken: "AGENT-SECRET",
		TgBotToken: "TG-SECRET", GithubClientSecret: "GH-SECRET",
		R2SecretKey: "R2-SECRET", R2AccessKey: "R2KEY-SECRET",
		BackupPassphrase: "BACKUP-SECRET", TwoFASecret: "2FA-SECRET",
		GithubClientID: "public-client-id", TrustedProxies: "10.0.0.0/8",
		IsSetup: true,
	}

	w := httptest.NewRecorder()
	handleDashboard(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("面板渲染失败，状态码 %d", w.Code)
	}
	body := w.Body.String()
	for _, secret := range []string{
		"HASH-SECRET", "AGENT-SECRET", "TG-SECRET", "GH-SECRET",
		"R2-SECRET", "R2KEY-SECRET", "BACKUP-SECRET", "2FA-SECRET",
	} {
		if strings.Contains(body, secret) {
			t.Errorf("面板 HTML 泄露了 %s", secret)
		}
	}
	for _, field := range []string{
		`name="backup_passphrase"`, `name="trusted_proxies"`,
		`/vendor/chart.umd.min.js`, `/vendor/remixicon.css`, `function esc(`,
	} {
		if !strings.Contains(body, field) {
			t.Errorf("面板 HTML 缺少 %s", field)
		}
	}
	if !strings.Contains(body, "public-client-id") || !strings.Contains(body, "10.0.0.0/8") {
		t.Error("非敏感配置项应正常回显")
	}
}

func TestHandleVendorServesOnlyWhitelistedAssets(t *testing.T) {
	for _, path := range []string{
		"/vendor/chart.umd.min.js", "/vendor/remixicon.css",
		"/vendor/fonts/remixicon.woff2", "/vendor/fonts/remixicon.woff",
	} {
		w := httptest.NewRecorder()
		handleVendor(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK || w.Body.Len() == 0 {
			t.Errorf("本地资源 %s 未正确返回 (code=%d, size=%d)", path, w.Code, w.Body.Len())
		}
	}
	for _, path := range []string{
		"/vendor/../go.mod", "/vendor/unknown.js", "/vendor/fonts/remixicon.eot",
	} {
		w := httptest.NewRecorder()
		handleVendor(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("路径 %s 应返回 404，实际 %d", path, w.Code)
		}
	}
}
