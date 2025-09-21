FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install dependencies
RUN apk add --no-cache git

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o fail2ban-haproxy .

# Final stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata
WORKDIR /root/

# Copy the binary from builder stage
COPY --from=builder /app/fail2ban-haproxy .

# Copy config file
COPY tests-ressources/config.yaml .

# Create directory for logs
RUN mkdir -p /var/log/fail2ban-haproxy

# Expose SPOA port
EXPOSE 12345

# Expose syslog port
EXPOSE 514/udp

CMD ["./fail2ban-haproxy"]

