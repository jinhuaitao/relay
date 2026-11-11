package app

import (
	"sync"
	"time"
)

const (
	AppVersion = "v3.4.3"
	DBFile     = "data.db"
	WebPort    = ":8888"

	// 二进制一律从官方 GitHub Release 直连下载，不再经过任何第三方反向代理。
	// 自更新会强制校验同批发布的 checksums.txt，校验失败即放弃替换。
	DownloadURL     = "https://github.com/jinhuaitao/relay/releases/latest/download/relay"
	ChecksumsURL    = "https://github.com/jinhuaitao/relay/releases/latest/download/checksums.txt"
	GithubLatestAPI = "https://api.github.com/repos/jinhuaitao/relay/releases/latest"

	TCPKeepAlive    = 60 * time.Second
	UDPBufferSize   = 64 * 1024 // UDP 单包上限 65507，缓冲区必须够大，否则大包被静默截断
	CopyBufferSize  = 32 * 1024
	MaxLogEntries   = 200
	MaxLogRetention = 1000

	// 会话与 OAuth state 的有效期；两者都会在 30s 维护循环里被回收
	SessionTTL    = 30 * 24 * time.Hour
	OAuthStateTTL = 5 * time.Minute

	// 所有外部下载/上传都设上限，防止磁盘被打满
	MaxUploadSize = 64 << 20
	MaxUpdateSize = 200 << 20

	// 对 Agent 长连接的单次写超时，避免慢节点在持锁状态下拖死面板
	AgentWriteTimeout = 5 * time.Second

	// 备份加密格式：magic(10) | salt(16) | nonce(12) | ciphertext
	BackupMagic     = "GORELAYBK1"
	BackupSaltSize  = 16
	BackupNonceSize = 12
	BackupKeySize   = 32
	BackupExt       = ".db.enc"
)

var bufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, CopyBufferSize)
		return &b
	},
}

// udpBufPool 与 TCP 复制缓冲分开：UDP 报文不能被 32KB 截断。
var udpBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, UDPBufferSize)
		return &b
	},
}
