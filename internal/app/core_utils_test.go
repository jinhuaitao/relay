package app

import (
	"net/http/httptest"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"3.4.3", "3.4.2", 1},
		{"3.4.2", "3.4.3", -1},
		{"3.4", "3.4.0", 0},
		{"3.10.0", "3.9.9", 1},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q,%q)=%d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestFormatBytes(t *testing.T) {
	if got := formatBytes(0); got != "0 B" {
		t.Errorf("formatBytes(0)=%q", got)
	}
	if got := formatBytes(1536); got != "1.50 KB" {
		t.Errorf("formatBytes(1536)=%q", got)
	}
}

func TestPasswordFormats(t *testing.T) {
	const pwd = "correct horse battery"
	modern, err := hashNewPassword(pwd)
	if err != nil {
		t.Fatal(err)
	}
	if !verifyPassword(modern, pwd) || verifyPassword(modern, "wrong") {
		t.Fatal("argon2id 校验失败")
	}
	if needsPasswordUpgrade(modern) {
		t.Fatal("argon2id 不应被标记为需升级")
	}

	salt := generateSalt()
	legacy := salt + "$" + hashPassword(pwd, salt)
	if !verifyPassword(legacy, pwd) || !needsPasswordUpgrade(legacy) {
		t.Fatal("加盐 SHA256 旧格式兼容失败")
	}
	if !verifyPassword(md5Hash(pwd), pwd) || !needsPasswordUpgrade(md5Hash(pwd)) {
		t.Fatal("MD5 旧格式兼容失败")
	}
	if verifyPassword("", pwd) || verifyPassword("garbage", pwd) {
		t.Fatal("非法散列不应通过校验")
	}
}

func TestGetClientIPTrustsOnlyConfiguredProxies(t *testing.T) {
	defer setTrustedProxies("")
	r := httptest.NewRequest("GET", "/login", nil)
	r.RemoteAddr = "203.0.113.9:12345"
	r.Header.Set("X-Forwarded-For", "198.51.100.7, 10.0.0.1")
	r.Header.Set("CF-Connecting-IP", "198.51.100.8")

	setTrustedProxies("")
	if got := getClientIP(r); got != "203.0.113.9" {
		t.Fatalf("默认必须忽略伪造转发头，得到 %q", got)
	}

	setTrustedProxies("203.0.113.0/24")
	if got := getClientIP(r); got != "198.51.100.8" {
		t.Fatalf("可信代理应优先使用 CF-Connecting-IP，得到 %q", got)
	}
	r.Header.Del("CF-Connecting-IP")
	if got := getClientIP(r); got != "198.51.100.7" {
		t.Fatalf("可信代理应解析 XFF 首项，得到 %q", got)
	}

	setTrustedProxies("10.0.0.0/8")
	if got := getClientIP(r); got != "203.0.113.9" {
		t.Fatalf("非可信代理仍应忽略转发头，得到 %q", got)
	}
}

func TestCleanLogField(t *testing.T) {
	if got := cleanLogField("a\x00b\nc"); got != "a b c" {
		t.Fatalf("控制字符未清洗: %q", got)
	}
}

func TestSafeServiceArg(t *testing.T) {
	for _, s := range []string{"node-01", "cn.节点", "127.0.0.1:9999", "a/b_c+d"} {
		if !safeServiceArg(s) {
			t.Errorf("合法参数被拒绝: %q", s)
		}
	}
	for _, s := range []string{"a\"b", "a b", "a$b", "a`b", "a;b", "", "a\nb"} {
		if safeServiceArg(s) {
			t.Errorf("危险参数被接受: %q", s)
		}
	}
}

func TestRuleValidation(t *testing.T) {
	good := LogicalRule{
		ID: "r1", Protocol: "tcp", EntryPort: "8080", TargetPort: "80",
		BridgePort: "20000", EntryAgent: "a", ExitAgent: "b",
		TargetIP: "1.2.3.4", LBStrategy: "random",
	}
	if err := validateRuleFields(&good); err != nil {
		t.Fatalf("合法规则被拒绝: %v", err)
	}
	cases := map[string]func(*LogicalRule){
		"协议":   func(r *LogicalRule) { r.Protocol = "sctp" },
		"端口":   func(r *LogicalRule) { r.EntryPort = "99999" },
		"目标":   func(r *LogicalRule) { r.TargetIP = "" },
		"策略":   func(r *LogicalRule) { r.LBStrategy = "evil" },
		"负限速":  func(r *LogicalRule) { r.SpeedLimit = -1 },
		"危险ID": func(r *LogicalRule) { r.ID = "x' onclick='alert(1)" },
	}
	for name, mutate := range cases {
		r := good
		mutate(&r)
		if err := validateRuleFields(&r); err == nil {
			t.Errorf("%s 未校验通过（应拒绝）", name)
		}
	}

	withoutBridge := good
	withoutBridge.BridgePort = ""
	imported, err := validateImportedRules([]LogicalRule{withoutBridge})
	if err != nil {
		t.Fatalf("导入规整失败: %v", err)
	}
	if !validPort(imported[0].BridgePort) {
		t.Fatalf("未自动生成合法 BridgePort: %q", imported[0].BridgePort)
	}
	dup := good
	if _, err := validateImportedRules([]LogicalRule{good, dup}); err == nil {
		t.Fatal("重复 ID 应被拒绝")
	}
}
