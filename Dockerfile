# ==========================================
# 阶段 1: 编译后端静态二进制
# ==========================================
FROM golang:1.22-alpine AS builder

ARG TARGETOS=linux
ARG TARGETARCH

WORKDIR /build

# 复制 Go 源码（纯 Go 标准库，零外部依赖）
COPY go-web/ ./

# 静态多架构编译（内嵌单页 Web 资源）
RUN CGO_ENABLED=0 GOOS=${TARGETOS} ${TARGETARCH:+GOARCH=${TARGETARCH}} \
    go build -trimpath -ldflags="-s -w" -o /build/cfip-opt ./cmd/cfip-opt

# ==========================================
# 阶段 2: 极简纯净生产镜像 (~14.6MB)
# ==========================================
FROM alpine:3.20

WORKDIR /app

# 从构建层拷贝二进制文件
COPY --from=builder /build/cfip-opt /app/cfip-opt

# 声明环境变量默认配置
ENV CFIP_DATA=/data \
    CFIP_LISTEN=0.0.0.0:8787 \
    CFIP_ALLOWED_CIDRS=0.0.0.0/0,::/0 \
    TZ=Asia/Shanghai

VOLUME ["/data"]
EXPOSE 8787

# 使用 alpine 内置 wget 探针做容器健康检查
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8787/healthz || exit 1

ENTRYPOINT ["/app/cfip-opt"]
