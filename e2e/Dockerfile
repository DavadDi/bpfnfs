# Use the official Golang image as the base image
FROM golang:1.20 AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy the rest of the application code
COPY . .

# Build the Go application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o nfs-mock nfs-mock.go


# 最终阶段
FROM alpine:latest

# 设置工作目录
WORKDIR /app

# 从构建阶段复制二进制文件
COPY --from=builder /app/nfs-mock .

# 设置入口点运行应用
ENTRYPOINT ["./nfs-mock"]