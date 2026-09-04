# Build stage
FROM golang:1.26.6-alpine AS builder

WORKDIR /app

# gcc/musl-dev are required: PKCS#11 support goes through cgo.
RUN apk add --no-cache git ca-certificates gcc musl-dev

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

# Statically linked so the runtime image needs no libc matching, while still
# keeping cgo for the PKCS#11 bindings.
RUN CGO_ENABLED=1 GOOS=linux go build \
    -ldflags="-s -w -linkmode external -extldflags '-static' \
    -X github.com/sirosfoundation/siros-wrpac-tool/cmd/siros-wrpac-tool/cmd.Version=${VERSION} \
    -X github.com/sirosfoundation/siros-wrpac-tool/cmd/siros-wrpac-tool/cmd.Commit=${COMMIT} \
    -X github.com/sirosfoundation/siros-wrpac-tool/cmd/siros-wrpac-tool/cmd.BuildTime=${BUILD_DATE}" \
    -o siros-wrpac-tool ./cmd/siros-wrpac-tool

# Runtime stage
FROM alpine:3.24

WORKDIR /data

# softhsm is included so a deployment can be exercised end to end without a real
# HSM. For a production token, mount the vendor's PKCS#11 module instead and
# point --pkcs11-module at it.
RUN apk add --no-cache ca-certificates softhsm

COPY --from=builder /app/siros-wrpac-tool /usr/local/bin/siros-wrpac-tool

RUN mkdir -p /data/deployment /data/clients \
    && adduser -D -u 1000 wrpac \
    && chown -R wrpac:wrpac /data
USER wrpac

# deployment holds the CA and register; clients is the git-managed spec repo.
VOLUME ["/data/deployment", "/data/clients"]

EXPOSE 8080

ENTRYPOINT ["siros-wrpac-tool"]
CMD ["serve", "-d", "/data/deployment", "--addr", "0.0.0.0:8080"]
