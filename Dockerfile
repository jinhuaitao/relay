# ============================
# 第一阶段：构建 (Builder)
# ============================
FROM golang:1.23-alpine AS builder

# 设置工作目录
WORKDIR /src

# 1. 安装必要的构建依赖 (git 是 go get 下载源码必须的)
RUN apk add --no-cache git

# 2. 设置 GOPROXY 代理 (完美解决国内拉取依赖超时导致 exit code 1 的问题)
ENV GOPROXY=https://goproxy.cn,direct

# 复制源代码
COPY main.go main.go

# 初始化 Go Module 并下载依赖
RUN go mod init gorelay && \
    go get modernc.org/sqlite@v1.33.1 && \
    go get golang.org/x/crypto/acme/autocert && \
    go mod tidy

# 编译二进制文件
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
EXPOSE 80 443 8888 9999 20000-25000

# 挂载卷：保证 data.db 数据库和 certs 文件夹不丢失
VOLUME ["/app"]

# 启动命令
ENTRYPOINT ["./gorelay"]
