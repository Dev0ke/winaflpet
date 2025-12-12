# 使用具体版本号的 Tag，而不是 SHA256 Hash，以支持多架构自动切换
# 建议指定具体的 Go 版本，例如 1.21-alpine，以保证稳定性
FROM golang:1.23-alpine AS builder

# --- 1. 设置环境变量 ---
ENV GO111MODULE=on \
    GOPROXY=https://goproxy.cn,direct \
    USER=winaflpet \
    UID=10001

# --- 2. 安装系统依赖 ---
# 替换为中科大源
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories && \
    apk update && \
    apk add --no-cache git ca-certificates tzdata gnuplot libc-dev gcc && \
    update-ca-certificates && \
    adduser --disabled-password \
            --gecos "" \
            --home "/nonexistent" \
            --shell "/sbin/nologin" \
            --no-create-home \
            --uid "${UID}" "${USER}"

# --- 3. 优先下载 Go 依赖 (利用缓存) ---
WORKDIR /tmp/winaflpet/server
COPY server/go.mod server/go.sum ./
RUN go mod download

# --- 4. 拷贝源代码并编译 ---
COPY . /tmp/winaflpet/

ARG BUILD_VER
ARG BUILD_REV
ARG BUILD_DATE

LABEL org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.vcs-url="https://github.com/sgabe/winaflpet.git" \
      org.label-schema.vcs-ref=$BUILD_REV \
      org.label-schema.schema-version="1.0.0-rc1"

# 编译
# 注意：如果你在 M1 Mac 上编译并希望部署到 Linux 服务器(x86)，
# 你可能需要显式加上 GOARCH=amd64。如果只是本地跑，保持默认即可。
RUN CGO_ENABLED=1 CGO_CFLAGS="-D_LARGEFILE64_SOURCE" GOOS=linux go build \
        -ldflags="-X main.BuildVer=$BUILD_VER -X main.BuildRev=$BUILD_REV -w -s -extldflags '-static'" -a \
        -o /tmp/winaflpet/winaflpet .

# --- Stage 2: 运行时镜像 ---
# 同样使用 Tag 替代 Hash
FROM alpine:latest

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories && \
    apk update && \
    apk add --no-cache curl gnuplot

COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

COPY --from=builder --chown=winaflpet:winaflpet /tmp/winaflpet/server/public /opt/winaflpet/public
COPY --from=builder /tmp/winaflpet/server/templates /opt/winaflpet/templates
COPY --from=builder /tmp/winaflpet/winaflpet /opt/winaflpet/

HEALTHCHECK --start-period=1m \
  CMD curl --silent --fail -X POST http://127.0.0.1:4141/ping || exit 1

VOLUME /data
EXPOSE 4141
WORKDIR /opt/winaflpet
USER winaflpet:winaflpet

ENTRYPOINT ["/opt/winaflpet/winaflpet"]