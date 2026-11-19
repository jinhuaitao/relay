package app

import (
	"sync"
	"time"
)

const (
	AppVersion      = "v3.4.3"
	DBFile          = "data.db"
	WebPort         = ":8888"
	DownloadURL     = "https://jht126.eu.org/https://github.com/jinhuaitao/relay/releases/latest/download/relay"
	GithubLatestAPI = "https://api.github.com/repos/jinhuaitao/relay/releases/latest"
	TCPKeepAlive    = 60 * time.Second
	// UDP 单包缓冲必须覆盖最大 UDP 数据报（65535 字节），
	// 否则 ReadFromUDP 会静默截断大包（QUIC / 游戏协议等）
	UDPBufferSize   = 64 * 1024
	CopyBufferSize  = 32 * 1024
	MaxLogEntries   = 200
	MaxLogRetention = 1000
)

var bufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, CopyBufferSize)
		return &b
	},
}

// udpBufPool 独立于 TCP 复制缓冲：UDP 收发路径需要 64KB 整包缓冲
var udpBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, UDPBufferSize)
		return &b
	},
}
