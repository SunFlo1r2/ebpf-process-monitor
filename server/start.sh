#!/bin/bash

# eBPF 进程监控后端服务器启动脚本

echo "Starting eBPF Process Monitor Server..."

# 检查是否存在可执行文件
if [ ! -f "./server" ]; then
    echo "Server binary not found. Building..."
    go build -o server main.go
fi

# 启动服务器
./server