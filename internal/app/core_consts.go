package app

import (
	"sync"
	"time"
)

const (
	AppVersion      = "v3.3.8"
	DBFile          = "data.db"
	WebPort         = ":8888"
	DownloadURL     = "https://jht126.eu.org/https://github.com/jinhuaitao/relay/releases/latest/download/relay"
	GithubLatestAPI = "https://api.github.com/repos/jinhuaitao/relay/releases/latest"
	TCPKeepAlive    = 60 * time.Second
	UDPBufferSize   = 4 * 1024 * 1024
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
