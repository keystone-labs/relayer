ARG GO_VERSION=1.23.0
FROM golang:${GO_VERSION}-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make gcc musl-dev

# Set working directory
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Add this line before make build
RUN go mod tidy

# Build the application
RUN make build

# Create config directory
RUN mkdir -p /app/config

# Final stage
FROM alpine:latest

RUN apk add --no-cache ca-certificates

WORKDIR /app

# Copy binary and config
COPY --from=0 /app/bin/relayer .
COPY --from=0 /app/config ./config

# Create necessary directories
RUN mkdir -p /app/logs \
    && mkdir -p /app/data

# Set environment variables
ENV CONFIG_FILE=/app/config/config.yaml
ENV LOG_FILE=/app/logs/relayer.log

# Expose API and metrics ports
EXPOSE 3000 9090

# Run the application
CMD ["./relayer", "--config", "/app/config/config.yaml"]
