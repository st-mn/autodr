# Multi-stage build for small image size
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod ./
RUN go mod download

# Copy source code
COPY main.go ./

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags="-w -s" -o wazuh-agent .

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 wazuh && \
    adduser -D -u 1000 -G wazuh wazuh

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/wazuh-agent .

# Copy default config
COPY config.example.json /app/config.json

# Change ownership
RUN chown -R wazuh:wazuh /app

USER wazuh

# Expose any necessary ports (if needed)
# EXPOSE 1514

ENTRYPOINT ["./wazuh-agent"]
CMD ["/app/config.json"]
