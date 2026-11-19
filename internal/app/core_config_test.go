package app

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newTestDB 用临时目录中的 SQLite 替换全局 db，测试结束自动还原。
func newTestDB(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	d, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(dbSchema); err != nil {
		t.Fatal(err)
	}
	old := db
	db = d
	t.Cleanup(func() {
		d.Close()
		db = old
	})
}

func snapshotConfig(t *testing.T) {
	t.Helper()
	mu.Lock()
	oldConf, oldRules := config, rules
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		config, rules = oldConf, oldRules
		mu.Unlock()
	})
}

func sampleRule(id string) LogicalRule {
	return LogicalRule{
		ID: id, Group: "g1", Note: "测试规则", EntryAgent: "entry", EntryPort: "8080",
		ExitAgent: "exit", TargetIP: "1.1.1.1,2.2.2.2", TargetPort: "443", Protocol: "both",
		BridgePort: "20000", TrafficLimit: 1024, SpeedLimit: 2048, LBStrategy: "fastest",
		TotalTx: 100, TotalRx: 200, Alert80: true,
	}
}

func TestRulePersistenceRoundTrip(t *testing.T) {
	newTestDB(t)
	snapshotConfig(t)

	rules = []LogicalRule{sampleRule("r1")}
	mu.Lock()
	saveConfigNoLock()
	mu.Unlock()

	rules = nil
	loadConfig()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	got := rules[0]
	want := sampleRule("r1")
	if got.ID != want.ID || got.Note != want.Note || got.BridgePort != want.BridgePort ||
		got.TotalTx != want.TotalTx || got.TotalRx != want.TotalRx ||
		got.LBStrategy != want.LBStrategy || got.Alert80 != want.Alert80 ||
		got.TrafficLimit != want.TrafficLimit || got.Protocol != want.Protocol {
		t.Errorf("round trip mismatch: %+v", got)
	}
}

func TestSingleRuleUpsertAndDelete(t *testing.T) {
	newTestDB(t)
	snapshotConfig(t)

	r := sampleRule("r1")
	mu.Lock()
	upsertRuleNoLock(r)
	r.Note = "改名"
	upsertRuleNoLock(r)
	mu.Unlock()

	rules = nil
	loadConfig()
	if len(rules) != 1 || rules[0].Note != "改名" {
		t.Fatalf("upsert must update in place, got %+v", rules)
	}

	mu.Lock()
	deleteRuleRowNoLock("r1")
	mu.Unlock()
	rules = nil
	loadConfig()
	if len(rules) != 0 {
		t.Fatalf("delete must remove the row, got %d rules", len(rules))
	}
}

func TestSaveConfigUpdatesTrafficOnly(t *testing.T) {
	newTestDB(t)
	snapshotConfig(t)

	rules = []LogicalRule{sampleRule("r1")}
	mu.Lock()
	upsertRuleNoLock(rules[0])
	rules[0].TotalTx = 999
	rules[0].Alert95 = true
	saveConfig()
	mu.Unlock()

	rules = nil
	loadConfig()
	if len(rules) != 1 || rules[0].TotalTx != 999 || !rules[0].Alert95 {
		t.Fatalf("traffic flush failed: %+v", rules)
	}
	if rules[0].Note != "测试规则" {
		t.Error("traffic flush must not touch structural columns")
	}
}

func TestSaveConfigNoLockPrunesStaleRows(t *testing.T) {
	newTestDB(t)
	snapshotConfig(t)

	rules = []LogicalRule{sampleRule("r1"), sampleRule("r2")}
	mu.Lock()
	saveConfigNoLock()
	rules = rules[:1]
	saveConfigNoLock()
	mu.Unlock()

	rules = nil
	loadConfig()
	if len(rules) != 1 || rules[0].ID != "r1" {
		t.Fatalf("stale row must be pruned, got %+v", rules)
	}
}

func TestValidateBackupDB(t *testing.T) {
	dir := t.TempDir()

	good := filepath.Join(dir, "good.db")
	d, err := sql.Open("sqlite", good)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(dbSchema); err != nil {
		t.Fatal(err)
	}
	d.Close()
	if err := validateBackupDB(good); err != nil {
		t.Errorf("valid backup rejected: %v", err)
	}

	bad := filepath.Join(dir, "bad.db")
	os.WriteFile(bad, []byte("this is not a database"), 0644)
	if err := validateBackupDB(bad); err == nil {
		t.Error("garbage file must be rejected")
	}

	partial := filepath.Join(dir, "partial.db")
	d, err = sql.Open("sqlite", partial)
	if err != nil {
		t.Fatal(err)
	}
	d.Exec("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT)")
	d.Close()
	if err := validateBackupDB(partial); err == nil || !strings.Contains(err.Error(), "rules") {
		t.Errorf("missing tables must be rejected, got %v", err)
	}
}

func TestPruneExpiredSessions(t *testing.T) {
	mu.Lock()
	sessions["test-expired"] = time.Now().Add(-time.Hour)
	sessions["test-live"] = time.Now().Add(time.Hour)
	mu.Unlock()
	defer func() {
		mu.Lock()
		delete(sessions, "test-expired")
		delete(sessions, "test-live")
		mu.Unlock()
	}()

	pruneExpiredSessions()

	mu.Lock()
	_, expired := sessions["test-expired"]
	_, live := sessions["test-live"]
	mu.Unlock()
	if expired {
		t.Error("expired session must be pruned")
	}
	if !live {
		t.Error("live session must survive")
	}
}

func TestGithubLoginIssuesState(t *testing.T) {
	snapshotConfig(t)
	mu.Lock()
	config.GithubClientID = "test-client-id"
	mu.Unlock()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/oauth/github/login", nil)
	handleGithubLogin(w, r)

	if w.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected 307, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "state=") {
		t.Errorf("authorize URL must carry state: %s", loc)
	}
	var stateCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "oauth_state" {
			stateCookie = c
		}
	}
	if stateCookie == nil || stateCookie.Value == "" || !stateCookie.HttpOnly {
		t.Fatal("oauth_state cookie must be set and HttpOnly")
	}
	if !strings.Contains(loc, url.QueryEscape(stateCookie.Value)) {
		t.Error("URL state must match cookie state")
	}
}

func TestGithubCallbackRejectsBadState(t *testing.T) {
	snapshotConfig(t)
	mu.Lock()
	config.GithubClientID = "test-client-id"
	config.GithubClientSecret = "secret"
	mu.Unlock()

	// 无 state cookie：直接拒绝，不发起任何外部请求
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/oauth/github/callback?code=x&state=attacker", nil)
	handleGithubCallback(w, r)
	if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "err=3") {
		t.Errorf("missing cookie must redirect err=3, got %d %s", w.Code, w.Header().Get("Location"))
	}

	// cookie 与 query state 不一致：同样拒绝
	w = httptest.NewRecorder()
	r = httptest.NewRequest("GET", "/oauth/github/callback?code=x&state=attacker", nil)
	r.AddCookie(&http.Cookie{Name: "oauth_state", Value: "legit"})
	handleGithubCallback(w, r)
	if !strings.Contains(w.Header().Get("Location"), "err=3") {
		t.Error("mismatched state must be rejected")
	}
}

func TestSetupRemoteRequiresToken(t *testing.T) {
	newTestDB(t)
	snapshotConfig(t)
	mu.Lock()
	config.IsSetup = false
	setupToken = "token1234567890ab"
	mu.Unlock()

	form := url.Values{"username": {"admin"}, "password": {"pw"}}

	// 远程无令牌：拒绝
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/setup", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "198.51.100.7:1234"
	handleSetup(w, r)
	if !strings.Contains(w.Body.String(), "初始化令牌不正确") {
		t.Errorf("remote setup without token must fail, got %s", w.Body.String())
	}
	mu.Lock()
	done := config.IsSetup
	mu.Unlock()
	if done {
		t.Fatal("setup must not complete without token")
	}

	// 远程携带正确令牌：成功
	form.Set("setup_token", "token1234567890ab")
	w = httptest.NewRecorder()
	r = httptest.NewRequest("POST", "/setup", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "198.51.100.7:1234"
	handleSetup(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("valid token must succeed, got %d: %s", w.Code, w.Body.String())
	}
	mu.Lock()
	done = config.IsSetup
	hash := config.WebPass
	mu.Unlock()
	if !done {
		t.Error("IsSetup must be true after valid setup")
	}
	if !strings.HasPrefix(hash, "$2") {
		t.Errorf("setup must store bcrypt hash, got %q", hash)
	}
}

func TestLoginUpgradesLegacyHash(t *testing.T) {
	newTestDB(t)
	snapshotConfig(t)
	mu.Lock()
	config.IsSetup = true
	config.WebUser = "admin"
	config.WebPass = md5Hash("oldpw")
	config.TwoFAEnabled = false
	mu.Unlock()

	form := url.Values{"username": {"admin"}, "password": {"oldpw"}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "198.51.100.7:1234"
	handleLogin(w, r)

	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Fatalf("legacy login must succeed, got %d %s", w.Code, w.Header().Get("Location"))
	}
	mu.Lock()
	hash := config.WebPass
	mu.Unlock()
	if !strings.HasPrefix(hash, "$2") {
		t.Errorf("legacy hash must be upgraded to bcrypt, got %q", hash)
	}
	if !verifyPassword(hash, "oldpw") {
		t.Error("upgraded hash must still verify the password")
	}
}