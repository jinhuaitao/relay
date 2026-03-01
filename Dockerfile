# ============================
# 第一阶段：构建 (Builder)
# ============================
FROM golang:1.23-alpine AS builder

# 【关键修复 1】设置国内 Go 代理，解决下载依赖超时报错的问题
ENV GOPROXY=https://goproxy.cn,direct
# 提前声明编译环境变量
ENV CGO_ENABLED=0 
ENV GOOS=linux

# 【关键修复 2】安装 git 工具，防止某些模块拉取时报错
RUN apk add --no-cache git

# 设置工作目录
WORKDIR /src

# 复制源代码
COPY main.go main.go

# 初始化并下载依赖 (已包含新加的 autocert)
RUN go mod init gorelay && \
    go get modernc.org/sqlite@v1.33.1 && \
    go get golang.org/x/crypto/acme/autocert && \
    go mod tidy

# 编译二进制文件
# -ldflags="-s -w": 去除符号表和调试信息，极限减小体积
RUN go build -ldflags="-s -w" -o app main.go

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
