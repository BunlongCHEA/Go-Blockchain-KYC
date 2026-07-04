# ==================== Build Stage ====================
FROM golang:1.25.7-alpine3.23 AS builder

# Automatically set by buildx to match --platform (e.g. arm64 for the Pi 5).
# Hardcoding GOARCH=amd64 here previously caused "exec format error" on the Pi.
ARG TARGETARCH

# # Install build dependencies
# RUN apk add --no-cache git ca-certificates tzdata

# Install build dependencies (apk update+upgrade first to pull patched libssl3/libcrypto3 — CVE-2026-31789)
RUN apk update && apk upgrade --no-cache && \
    apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build \
    -ldflags="-w -s -X main.Version=1.0.0 -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o /app/kyc-blockchain \
    main.go

# ==================== Production Stage ====================
FROM alpine:3.23.3

# Install runtime dependencies (apk update+upgrade first to pull patched libssl3/libcrypto3 — CVE-2026-31789)
# The explicit pin is a safety net in case the mirror snapshot at build time
# hasn't rolled the "latest" alias forward yet; drop it once base image >= 3.23.4.
RUN apk update && apk upgrade --no-cache && \
    apk add --no-cache \
      ca-certificates \
      tzdata \
      "libssl3>=3.5.6-r0" \
      "libcrypto3>=3.5.6-r0"

# Create non-root user
RUN addgroup -g 1000 appgroup && \
    adduser -u 1000 -G appgroup -s /bin/sh -D appuser

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/kyc-blockchain .

# Copy config template (will be overridden by ConfigMap)
COPY config.json.example ./config.json

# Create directories for keys and logs
RUN mkdir -p /app/keys /app/logs && \
    chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8080 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Run the application
ENTRYPOINT ["/app/kyc-blockchain"]