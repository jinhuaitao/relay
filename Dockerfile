# ============================
# 第一阶段：构建 (Builder)
# ============================
FROM golang:1.23-alpine AS builder

# 设置工作目录
WORKDIR /src

# 复制源代码
COPY main.go main.go

# 初始化 Go Module 并且获取依赖
# 关键修改：
# 1. 先 init
# 2. 强制降低 modernc.org/sqlite 版本到 v1.33.1 (兼容纯 Go 编译的 SQLite)
# 3. 获取我们新引入的 autocert 证书库
# 4. 最后再运行 mod tidy 清理并下载其他依赖
RUN go mod init gorelay && \
    go get modernc.org/sqlite@v1.33.1 && \
    go get golang.org/x/crypto/acme/autocert && \
    go mod tidy

# 编译二进制文件
# CGO_ENABLED=0: 禁用 CGO (必须)
# -ldflags="-s -w": 去除符号表和调试信息，极限减小体积
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o app main.go

# ============================
# 第二阶段：运行 (Runner)
# ============================
FROM alpine:latest

# 设置工作目录
WORKDIR /app

# 安装基础证书和时区（对于访问 GitHub API 和 Let's Encrypt 签发极度重要）
RUN apk --no-cache add ca-certificates tzdata

# 从构建阶段复制编译好的二进制文件
COPY --from=builder /src/app ./gorelay

# 暴露必要的端口
# 80: Let's Encrypt 证书 HTTP 验证 & 自动跳转 HTTPS
# 443: Web 面板 HTTPS 访问端口
# 8888: 未配置域名时的默认 HTTP 面板端口
# 9999: Agent 默认通信端口
# 20000-25000: 动态分配的桥接转发端口池
EXPOSE 80 443 8888 9999 20000-25000

# 挂载卷
# 极度重要：保证 data.db 数据库和 certs 文件夹（存放真实 TLS 证书）不丢失
VOLUME ["/app"]

# 启动命令
ENTRYPOINT ["./gorelay"]
