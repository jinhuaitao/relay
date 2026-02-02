# ============================
# 第一阶段：构建 (Builder)
# ============================
FROM golang:1.23-alpine AS builder

# 设置工作目录
WORKDIR /src

# 复制源代码
COPY main.go main.go

# 初始化 Go Module
# 关键修改：
# 1. 先 init
# 2. 强制降低 modernc.org/sqlite 版本到 v1.33.1 (兼容 Go 1.23)
# 3. 最后再运行 mod tidy 下载其他依赖
RUN go mod init gorelay && \
    go get modernc.org/sqlite@v1.33.1 && \
    go mod tidy

# 编译二进制文件
# CGO_ENABLED=0: 禁用 CGO (必须)
# -ldflags="-s -w": 减小体积
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o app main.go

# ============================
# 第二阶段：运行 (Runner)
# ============================
FROM alpine:latest

# 设置工作目录
WORKDIR /app

# 安装基础证书和时区
RUN apk --no-cache add ca-certificates tzdata

# 从构建阶段复制编译好的二进制文件
COPY --from=builder /src/app ./gorelay

# 暴露端口
EXPOSE 8888 9999 20000-25000

# 挂载卷
VOLUME ["/app"]

# 启动命令
ENTRYPOINT ["./gorelay"]
