# ============================
# 第一阶段：构建 (Builder)
# ============================
# 【提速魔法】：强制使用 GitHub 服务器原生的速度跑编译器
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder

# 引入自动识别的目标架构变量 (amd64 或 arm64)
ARG TARGETARCH

# 设置工作目录
WORKDIR /src

# 安装必要的构建依赖 
RUN apk add --no-cache git

# 复制依赖清单（利用 Docker 层缓存，源码变更时无需重新下载依赖）
COPY go.mod go.sum ./

# 设置 GOPROXY 代理
ENV GOPROXY=https://goproxy.cn,direct

# 预下载 Go Module 依赖
RUN go mod download

# 复制源码：根目录入口 + internal 实现包（含 go:embed 的前端资源）
COPY main.go ./
COPY internal ./internal

# 编译二进制文件 (使用宿主机的全速编译器，输出 TARGETARCH 指定的格式)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -ldflags="-s -w" -o app .

# ============================
# 第二阶段：运行 (Runner)
# ============================
# 到了运行阶段，Docker 会自动拉取目标架构的 alpine (比如 arm64 版)
FROM alpine:latest

# 设置工作目录
WORKDIR /app

# 安装基础证书和时区
RUN apk --no-cache add ca-certificates tzdata

# 从构建阶段复制编译好的二进制文件
COPY --from=builder /src/app ./gorelay

# 暴露必要的端口
EXPOSE 80 443 8888 9999 20000-25000

# 挂载卷
VOLUME ["/app"]

# 启动命令
ENTRYPOINT ["./gorelay"]
