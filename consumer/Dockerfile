# Use a lightweight Go base image
FROM golang:1.21-alpine AS builder

# Set working directory
WORKDIR /app

# Copy source code
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build the Go app
RUN go build -o consumer main.go

# Create a minimal final image
FROM alpine:latest
WORKDIR /root/

# Copy built binary
COPY --from=builder /app/consumer .

# Expose required port
EXPOSE 8080

# Start the app
CMD ["./consumer"]
