# ============================
# 第一阶段：构建 (Builder)
# ============================
# 固定 Go 次版本，与 go.mod 的 go 1.25.6 对齐
FROM --platform=$BUILDPLATFORM golang:1.25.6-alpine AS builder

ARG TARGETARCH

WORKDIR /src

RUN apk add --no-cache git

COPY go.mod go.sum ./

# 默认用官方模块代理；国内构建可用 --build-arg 覆盖
ENV GOPROXY=https://proxy.golang.org,direct

RUN go mod download

COPY main.go ./
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -ldflags="-s -w" -o app .

# ============================
# 第二阶段：运行 (Runner)
# ============================
FROM alpine:3.21

WORKDIR /app

RUN apk --no-cache add ca-certificates tzdata

COPY --from=builder /src/app ./gorelay

# 20000-50000 覆盖规则自动分配的 BridgePort（20000-49999）
EXPOSE 80 443 8888 9999 20000-50000

VOLUME ["/app"]

ENTRYPOINT ["./gorelay"]
