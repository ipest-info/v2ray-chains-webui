FROM golang:1.24-alpine AS build
# 境内构建可传入 --build-arg GOPROXY=https://goproxy.cn,direct
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=$GOPROXY CGO_ENABLED=0
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -tags timetzdata -trimpath -ldflags="-s -w" -o /v2ray-chains-webui .

FROM alpine:3.20
# acme.sh 申请证书需要 curl 和 openssl
RUN apk add --no-cache curl openssl ca-certificates
COPY --from=build /v2ray-chains-webui /usr/local/bin/v2ray-chains-webui
VOLUME /data
EXPOSE 8080 8443
ENTRYPOINT ["/usr/local/bin/v2ray-chains-webui", "-data", "/data"]
CMD ["-listen", ":8080", "-https-listen", ":8443"]
