// auth.go — 认证与鉴权：登录限速、会话中间件、CSRF/同源校验、GitHub OAuth、2FA
//
// 加固点：
//   - 登出真正销毁服务端会话，会话 30 天过期；
//   - 口令升级为 argon2id，旧格式登录时自动迁移；
//   - GitHub OAuth 增加 state 防授权码注入；
//   - CSRF 白名单覆盖所有 GET 型变更端点；同源比较不再忽略端口。

package app

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"image/png"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"github.com/pquerna/otp/totp"
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
		if isStateChanging(r) && !isSameOrigin(r) {
			http.Error(w, "跨站请求已被拒绝", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// isStateChanging 判断请求是否会修改服务端状态。
// 历史遗留的一批 GET 型变更端点必须显式列出，否则同源校验会被绕过。
func isStateChanging(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return true
	}
	switch r.URL.Path {
	case "/toggle", "/delete", "/reset_traffic", "/delete_agent", "/gen_agent_token",
		"/update_agent", "/restart", "/update_sys", "/logout", "/2fa/generate":
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
	if err != nil || u.Host == "" {
		return false
	}
	if !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") {
		return false
	}
	return equalHost(u.Host, r.Host, u.Scheme)
}

// equalHost 同时比较主机名与端口（空端口按 scheme 的默认端口处理）。
// 旧实现忽略端口，导致同主机不同端口的页面也能发起跨站写请求。
func equalHost(originHost, reqHost, scheme string) bool {
	oh, op, err := net.SplitHostPort(originHost)
	if err != nil {
		oh, op = originHost, ""
	}
	rh, rp, err := net.SplitHostPort(reqHost)
	if err != nil {
		rh, rp = reqHost, ""
	}
	if !strings.EqualFold(strings.Trim(oh, "[]"), strings.Trim(rh, "[]")) {
		return false
	}
	defPort := "80"
	if strings.EqualFold(scheme, "https") {
		defPort = "443"
	}
	norm := func(p string) string {
		if p == "" {
			return defPort
		}
		return p
	}
	return norm(op) == norm(rp)
}

func tokenMatches(got, want string) bool {
	if want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func handleSetup(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	alreadySetup := config.IsSetup
	tk := setupToken
	mu.Unlock()

	if alreadySetup {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	needToken := !isLoopbackRequest(r)

	if r.Method == "POST" {
		if needToken && !tokenMatches(r.FormValue("setup_token"), tk) {
			addSystemLog(getClientIP(r), "初始化失败", "初始化令牌错误")
			t, _ := template.New("s").Parse(setupHtml)
			_ = t.Execute(w, map[string]interface{}{"NeedToken": true, "Error": "初始化令牌不正确，请查看服务端启动日志"})
			return
		}
		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")
		if username == "" || len(password) < 8 {
			t, _ := template.New("s").Parse(setupHtml)
			_ = t.Execute(w, map[string]interface{}{"NeedToken": needToken, "Error": "用户名不能为空，且密码至少 8 位"})
			return
		}
		pwdHash, err := hashNewPassword(password)
		if err != nil {
			http.Error(w, "初始化失败", http.StatusInternalServerError)
			return
		}

		mu.Lock()
		config.WebUser = username
		config.WebPass = pwdHash
		config.AgentToken = generateUUID()
		if config.AgentTokens == nil {
			config.AgentTokens = make(map[string]string)
		}
		config.IsSetup = true
		setupToken = ""
		saveConfigNoLock()
		mu.Unlock()
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	t, _ := template.New("s").Parse(setupHtml)
	_ = t.Execute(w, map[string]interface{}{"NeedToken": needToken, "Error": ""})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		mu.Lock()
		isEnabled := config.TwoFAEnabled
		githubEnabled := config.GithubClientID != "" && config.GithubClientSecret != ""
		mu.Unlock()

		errMsg := ""
		switch r.URL.Query().Get("err") {
		case "1":
			errMsg = "账号或密码错误"
		case "2":
			errMsg = "2FA 动态码错误"
		case "3":
			errMsg = "GitHub 授权失败"
		case "4":
			errMsg = "该 GitHub 账号不在允许列表中"
		}

		t, _ := template.New("l").Parse(loginHtml)
		_ = t.Execute(w, map[string]interface{}{
			"TwoFA":         isEnabled,
			"GithubEnabled": githubEnabled,
			"Error":         errMsg,
		})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := getClientIP(r)
	if !checkLoginRateLimit(ip) {
		http.Error(w, "尝试次数过多", http.StatusTooManyRequests)
		return
	}
	mu.Lock()
	u, storedVal := config.WebUser, config.WebPass
	twoFAEnabled := config.TwoFAEnabled
	twoFASecret := config.TwoFASecret
	mu.Unlock()

	passMatch := r.FormValue("username") == u && verifyPassword(storedVal, r.FormValue("password"))
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

	// 旧格式（无盐 MD5 / 加盐 SHA256）登录成功后原地升级为 argon2id。
	if needsPasswordUpgrade(storedVal) {
		if newHash, err := hashNewPassword(r.FormValue("password")); err == nil {
			mu.Lock()
			if config.WebUser == u && config.WebPass == storedVal {
				config.WebPass = newHash
				saveConfigNoLock()
			}
			mu.Unlock()
		}
	}

	sid := make([]byte, 24)
	_, _ = rand.Read(sid)
	sidStr := hex.EncodeToString(sid)
	mu.Lock()
	sessions[sidStr] = time.Now().Add(SessionTTL)
	mu.Unlock()

	addLog(r, "登录成功", "账号密码登录")

	secureCookie := isMasterTLS || r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: sidStr, Path: "/", HttpOnly: true, Secure: secureCookie, MaxAge: int(SessionTTL.Seconds()), SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	addLog(r, "退出登录", "用户主动登出")
	if c, err := r.Cookie("sid"); err == nil {
		mu.Lock()
		delete(sessions, c.Value)
		mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", Path: "/", HttpOnly: true, MaxAge: -1, SameSite: http.SameSiteLaxMode})
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

	stateBytes := make([]byte, 24)
	if _, err := rand.Read(stateBytes); err != nil {
		http.Error(w, "无法生成授权状态", http.StatusInternalServerError)
		return
	}
	state := hex.EncodeToString(stateBytes)
	mu.Lock()
	oauthStates[state] = time.Now().Add(OAuthStateTTL)
	mu.Unlock()

	redirectURL := fmt.Sprintf("https://github.com/login/oauth/authorize?client_id=%s&state=%s",
		url.QueryEscape(clientID), url.QueryEscape(state))
	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}

func handleGithubCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	mu.Lock()
	exp, ok := oauthStates[state]
	if ok {
		delete(oauthStates, state)
	}
	mu.Unlock()
	if state == "" || !ok || time.Now().After(exp) {
		http.Redirect(w, r, "/login?err=3", http.StatusSeeOther)
		return
	}

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
	_ = json.NewDecoder(resp.Body).Decode(&tokenData)
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
	_ = json.NewDecoder(userResp.Body).Decode(&userData)

	isAllowed := false
	for _, u := range strings.Split(allowedUsersStr, ",") {
		u = strings.TrimSpace(u)
		if u != "" && strings.EqualFold(u, userData.Login) {
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

	sid := make([]byte, 24)
	_, _ = rand.Read(sid)
	sidStr := hex.EncodeToString(sid)
	mu.Lock()
	sessions[sidStr] = time.Now().Add(SessionTTL)
	mu.Unlock()

	addLog(r, "GitHub 登录", fmt.Sprintf("通过 GitHub 登录成功 (%s)", userData.Login))
	secureCookie := isMasterTLS || r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: sidStr, Path: "/", HttpOnly: true, Secure: secureCookie, MaxAge: int(SessionTTL.Seconds()), SameSite: http.SameSiteLaxMode})
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
	_ = png.Encode(&buf, img)
	resp := map[string]string{"secret": key.Secret(), "qr": "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())}
	_ = json.NewEncoder(w).Encode(resp)
}

func handle2FAVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct{ Secret, Code string }
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "请求格式错误", http.StatusBadRequest)
		return
	}
	if totp.Validate(req.Code, req.Secret) {
		mu.Lock()
		config.TwoFASecret = req.Secret
		config.TwoFAEnabled = true
		saveConfigNoLock()
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
	} else {
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": false})
	}
}

func handle2FADisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	mu.Lock()
	config.TwoFAEnabled = false
	config.TwoFASecret = ""
	saveConfigNoLock()
	mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}
