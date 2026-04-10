# Frontend build stage
FROM node:20-alpine AS frontend

WORKDIR /web

# Copy frontend dependency files
COPY web/package.json web/package-lock.json ./

# Install frontend dependencies
RUN npm ci

# Copy frontend source
COPY web/ .

# Build frontend (outputs to ../pkg/web/dist via vite config,
# but we override outDir here since the Go source tree isn't mounted)
RUN npx vite build --outDir /frontend-dist --emptyOutDir

# Go build stage
FROM golang:1.25-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Copy built frontend assets into the embed directory
COPY --from=frontend /frontend-dist ./pkg/web/dist

# Build arguments for version info
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-s -w \
        -X github.com/lucientong/wormhole/pkg/version.Version=${VERSION} \
        -X github.com/lucientong/wormhole/pkg/version.Commit=${COMMIT} \
        -X github.com/lucientong/wormhole/pkg/version.BuildTime=${BUILD_TIME}" \
    -o /wormhole ./cmd/wormhole

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN adduser -D -g '' wormhole

# Copy binary from builder
COPY --from=builder /wormhole /usr/local/bin/wormhole

# Switch to non-root user
USER wormhole

# Expose ports
# 7000: Tunnel connections from clients
# 80: HTTP traffic
# 443: HTTPS traffic (optional)
# 7001: Admin API
EXPOSE 7000 80 443 7001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget -q -O /dev/null http://localhost:7001/health || exit 1

# Default command (server mode)
ENTRYPOINT ["wormhole"]
CMD ["server"]
