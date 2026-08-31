# syntax=docker/dockerfile:1.7

FROM golang:1.26-bookworm AS builder

WORKDIR /app

ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}

RUN apt-get update && apt-get install -y --no-install-recommends build-essential git && rm -rf /var/lib/apt/lists/*

COPY go.mod go.sum ./

RUN --mount=type=cache,id=cliproxyapi-gomod,target=/go/pkg/mod \
    --mount=type=tmpfs,target=/tmp,size=4294967296 \
    go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown

RUN --mount=type=cache,id=cliproxyapi-gomod,target=/go/pkg/mod \
    --mount=type=cache,id=cliproxyapi-gobuild,target=/root/.cache/go-build \
    --mount=type=tmpfs,target=/tmp,size=4294967296 \
    CGO_ENABLED=1 GOOS=linux go build -buildvcs=false -ldflags="-s -w -X 'main.Version=${VERSION}' -X 'main.Commit=${COMMIT}' -X 'main.BuildDate=${BUILD_DATE}'" -o ./CLIProxyAPI ./cmd/server/

FROM debian:bookworm

RUN apt-get update && apt-get install -y --no-install-recommends tzdata ca-certificates && rm -rf /var/lib/apt/lists/*

RUN mkdir /CLIProxyAPI

COPY --from=builder ./app/CLIProxyAPI /CLIProxyAPI/CLIProxyAPI

COPY config.example.yaml /CLIProxyAPI/config.example.yaml

WORKDIR /CLIProxyAPI

EXPOSE 8317

ENV TZ=Asia/Shanghai

RUN cp /usr/share/zoneinfo/${TZ} /etc/localtime && echo "${TZ}" > /etc/timezone

CMD ["./CLIProxyAPI"]
