// auth.go — 认证与鉴权：登录限速、会话中间件、CSRF/同源校验、GitHub OAuth、2FA
//
// 由原单文件 main.go（AppVersion v3.3.6）按职责拆分而来，
// 代码逻辑、执行顺序与对外行为完全未改动（同一 package main）。

package app

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"github.com/pquerna/otp/totp"
	"html/template"
	"image/png"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

func checkLoginRateLimit(ip string) bool {
	if t, ok := blockUntil.Load(ip); ok {
		if time.Now().Before(t.(time.Time)) {
			return false
		}
		blockUntil.Delete(ip)
		loginAttempts.Delete(ip)
	}
	return true
}

func recordLoginFail(ip string) {
	v, _ := loginAttempts.LoadOrStore(ip, new(int64))
	count := atomic.AddInt64(v.(*int64), 1)
	if count >= 5 {
		blockUntil.Store(ip, time.Now().Add(15*time.Minute))
	}
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		setup := config.IsSetup
		mu.Unlock()
		if !setup {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		c, err := r.Cookie("sid")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		mu.Lock()
		exp, ok := sessions[c.Value]
		mu.Unlock()
		if !ok || time.Now().After(exp) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		// CSRF 防护：仅对"状态变更"请求校验 Origin/Referer 与本机 Host 一致。
		// 写操作（POST/PUT/DELETE）与通过 GET 触发变更的端点都需校验；
		// 只读 GET（仪表盘、下载等）放行，避免从书签/外链点入被误拦。
		if isStateChanging(r) && !isSameOrigin(r) {
			http.Error(w, "跨站请求已被拒绝", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// isStateChanging 判断请求是否会修改服务端状态。POST/PUT/DELETE 视为变更；
// 另外这几个通过 GET 触发写操作的端点也需走 CSRF 校验。
func isStateChanging(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return true
	}
	switch r.URL.Path {
	case "/toggle", "/delete", "/reset_traffic", "/delete_agent", "/gen_agent_token":
		return true
	}
	return false
}

// isSameOrigin 判断请求是否来自面板自身。Origin/Referer 缺失时放行
// （依赖 SameSite=Lax cookie 抵御跨站子资源/表单），存在时必须与本机 Host 匹配。
func isSameOrigin(r *http.Request) bool {
	raw := r.Header.Get("Origin")
	if raw == "" {
		raw = r.Header.Get("Referer")
	}
	if raw == "" {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return equalHost(u.Host, r.Host)
}

// equalHost 比较两个 host[:port] 的主机名部分是否相同（忽略端口与大小写）。
func equalHost(a, b string) bool {
	ha, _, _ := net.SplitHostPort(a)
	hb, _, _ := net.SplitHostPort(b)
	if ha == "" {
		ha = a
	}
	if hb == "" {
		hb = b
	}
	return strings.EqualFold(ha, hb)
}

func handleSetup(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	alreadySetup := config.IsSetup
	mu.Unlock()

	if alreadySetup {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == "POST" {
		mu.Lock()
		config.WebUser = r.FormValue("username")
		salt := generateSalt()
		pwdHash := hashPassword(r.FormValue("password"), salt)
		config.WebPass = salt + "$" + pwdHash
		config.AgentToken = generateUUID()
		if config.AgentTokens == nil {
			config.AgentTokens = make(map[string]string)
		}
		config.IsSetup = true
		saveConfigNoLock()
		mu.Unlock()
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	t, _ := template.New("s").Parse(setupHtml)
	t.Execute(w, nil)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		mu.Lock()
		isEnabled := config.TwoFAEnabled
		githubEnabled := config.GithubClientID != "" && config.GithubClientSecret != ""
		mu.Unlock()

		errCode := r.URL.Query().Get("err")
		errMsg := ""
		if errCode == "1" {
			errMsg = "账号或密码错误"
		}
		if errCode == "2" {
			errMsg = "2FA 动态码错误"
		}
		if errCode == "3" {
			errMsg = "GitHub 授权失败"
		}
		if errCode == "4" {
			errMsg = "该 GitHub 账号不在允许列表中"
		}

		t, _ := template.New("l").Parse(loginHtml)
		t.Execute(w, map[string]interface{}{
			"TwoFA":         isEnabled,
			"GithubEnabled": githubEnabled,
			"Error":         errMsg,
		})
		return
	}
	ip := getClientIP(r)
	if !checkLoginRateLimit(ip) {
		http.Error(w, "尝试次数过多", 429)
		return
	}
	mu.Lock()
	u, storedVal := config.WebUser, config.WebPass
	twoFAEnabled := config.TwoFAEnabled
	twoFASecret := config.TwoFASecret
	mu.Unlock()

	passMatch := false
	parts := strings.Split(storedVal, "$")
	if len(parts) == 2 {
		if r.FormValue("username") == u && hashPassword(r.FormValue("password"), parts[0]) == parts[1] {
			passMatch = true
		}
	} else if r.FormValue("username") == u && md5Hash(r.FormValue("password")) == storedVal {
		passMatch = true
	}

	if !passMatch {
		recordLoginFail(ip)
		addSystemLog(ip, "登录失败", "账号或密码错误")
		http.Redirect(w, r, "/login?err=1", http.StatusSeeOther)
		return
	}

	if twoFAEnabled {
		if !totp.Validate(r.FormValue("code"), twoFASecret) {
			recordLoginFail(ip)
			addSystemLog(ip, "登录失败", "2FA 动态码错误")
			http.Redirect(w, r, "/login?err=2", http.StatusSeeOther)
			return
		}
	}

	// 命中旧版无盐 MD5 口令则自动升级为加盐 SHA256，避免库泄露后被彩虹表秒破
	if !strings.Contains(storedVal, "$") {
		salt := generateSalt()
		newHash := salt + "$" + hashPassword(r.FormValue("password"), salt)
		mu.Lock()
		if config.WebUser == u {
			config.WebPass = newHash
			saveConfigNoLock()
		}
		mu.Unlock()
	}

	sid := make([]byte, 16)
	rand.Read(sid)
	sidStr := hex.EncodeToString(sid)
	mu.Lock()
	sessions[sidStr] = time.Now().Add(365 * 24 * time.Hour)
	mu.Unlock()

	// 登录成功，写入系统日志
	addLog(r, "登录成功", "账号密码登录")

	// 智能判断是否开启安全 Cookie
	secureCookie := isMasterTLS || r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: sidStr, Path: "/", HttpOnly: true, Secure: secureCookie, MaxAge: 31536000, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	addLog(r, "退出登录", "用户主动登出")
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func handleGithubLogin(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	clientID := config.GithubClientID
	mu.Unlock()

	if clientID == "" {
		http.Error(w, "GitHub OAuth 未配置", http.StatusInternalServerError)
		return
	}

	redirectURL := fmt.Sprintf("https://github.com/login/oauth/authorize?client_id=%s", clientID)
	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}

func handleGithubCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Redirect(w, r, "/login?err=3", http.StatusSeeOther)
		return
	}

	mu.Lock()
	clientID := config.GithubClientID
	clientSecret := config.GithubClientSecret
	allowedUsersStr := config.GithubAllowedUsers
	mu.Unlock()

	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("code", code)
	req, _ := http.NewRequest("POST", "https://github.com/login/oauth/access_token", strings.NewReader(form.Encode()))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		http.Redirect(w, r, "/login?err=3", http.StatusSeeOther)
		return
	}
	defer resp.Body.Close()

	var tokenData struct {
		AccessToken string `json:"access_token"`
	}
	json.NewDecoder(resp.Body).Decode(&tokenData)
	if tokenData.AccessToken == "" {
		http.Redirect(w, r, "/login?err=3", http.StatusSeeOther)
		return
	}

	userReq, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	userReq.Header.Set("Authorization", "Bearer "+tokenData.AccessToken)
	userReq.Header.Set("Accept", "application/json")

	userResp, err := client.Do(userReq)
	if err != nil {
		http.Redirect(w, r, "/login?err=3", http.StatusSeeOther)
		return
	}
	defer userResp.Body.Close()

	var userData struct {
		Login string `json:"login"`
	}
	json.NewDecoder(userResp.Body).Decode(&userData)

	allowedUsers := strings.Split(allowedUsersStr, ",")
	isAllowed := false
	for _, u := range allowedUsers {
		if strings.TrimSpace(u) != "" && strings.EqualFold(strings.TrimSpace(u), userData.Login) {
			isAllowed = true
			break
		}
	}

	if !isAllowed || userData.Login == "" {
		ip := getClientIP(r)
		recordLoginFail(ip)
		addSystemLog(ip, "登录失败", fmt.Sprintf("GitHub 账号 %s 不在允许列表", userData.Login))
		http.Redirect(w, r, "/login?err=4", http.StatusSeeOther)
		return
	}

	sid := make([]byte, 16)
	rand.Read(sid)
	sidStr := hex.EncodeToString(sid)

	mu.Lock()
	sessions[sidStr] = time.Now().Add(365 * 24 * time.Hour)
	mu.Unlock()

	addLog(r, "GitHub 登录", fmt.Sprintf("通过 GitHub 登录成功 (%s)", userData.Login))
	secureCookie := isMasterTLS || r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: sidStr, Path: "/", HttpOnly: true, Secure: secureCookie, MaxAge: 31536000, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handle2FAGenerate(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	u := config.WebUser
	mu.Unlock()
	key, _ := totp.Generate(totp.GenerateOpts{Issuer: "GoRelay-Pro", AccountName: u})
	var buf bytes.Buffer
	img, _ := qr.Encode(key.URL(), qr.M, qr.Auto)
	img, _ = barcode.Scale(img, 200, 200)
	png.Encode(&buf, img)
	resp := map[string]string{"secret": key.Secret(), "qr": "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())}
	json.NewEncoder(w).Encode(resp)
}

func handle2FAVerify(w http.ResponseWriter, r *http.Request) {
	var req struct{ Secret, Code string }
	json.NewDecoder(r.Body).Decode(&req)
	if totp.Validate(req.Code, req.Secret) {
		mu.Lock()
		config.TwoFASecret = req.Secret
		config.TwoFAEnabled = true
		saveConfigNoLock()
		mu.Unlock()
		json.NewEncoder(w).Encode(map[string]bool{"success": true})
	} else {
		json.NewEncoder(w).Encode(map[string]bool{"success": false})
	}
}

func handle2FADisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	mu.Lock()
	config.TwoFAEnabled = false
	config.TwoFASecret = ""
	saveConfigNoLock()
	mu.Unlock()
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}
