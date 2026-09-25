============================
第一阶段：构建 (Builder)
============================
【提速魔法】：强制使用 GitHub 服务器原地的速度跑编译器
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder

引入自动识别的目标架构变量 (amd64 或 arm64)
ARG TARGETARCH

设置工作目录
WORKDIR /src

安装必要的构建依赖
RUN apk add --no-cache git

设置 GOPROXY 代理
ENV GOPROXY=https://goproxy.cn,direct

复制源代码
COPY main.go main.go

初始化 Go Module 并下载依赖
RUN go mod init gorelay &&
go get modernc.org/sqlite@v1.33.1 &&
go get golang.org/x/crypto/acme/autocert@v0.55.0 &&
# 【修复】钉死 x/time 版本：否则 go mod tidy 会拉最新的 v0.16.0，
# 它的 go.mod 声明 go 1.26.0，超出 golang:1.25-alpine 镜像，导致构建失败 (exit 1)。
# v0.15.0 声明 go 1.25.0，与本镜像完全兼容。
go get golang.org/x/time/rate@v0.15.0 &&
go mod tidy

编译二进制文件 (使用宿主机的全速编译器，输出 TARGETARCH 指定的格式)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -ldflags="-s -w" -o app main.go

============================
第二阶段：运行 (Runner)
============================
到了运行阶段，Docker 会自动拉取目标架构的 alpine (比如 arm64 版)
FROM alpine:latest

设置工作目录
WORKDIR /app

安装基础证书和时区
RUN apk --no-cache add ca-certificates tzdata

从构建阶段复制编译好的二进制文件
COPY --from=builder /src/app ./gorelay

暴露必要的端口
EXPOSE 80 443 8888 9999 20000-25000

挂载卷
VOLUME ["/app"]

启动命令
ENTRYPOINT ["./gorelay"]
