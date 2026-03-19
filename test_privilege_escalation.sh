#!/bin/bash

# eBPF 权限提升监控测试脚本
# 用于测试 eBPF 进程监控系统对权限提升行为的检测能力

echo "===================================="
echo "eBPF 权限提升监控测试脚本"
echo "===================================="
echo ""

# 检查是否以 root 权限运行
if [ "$EUID" -ne 0 ]; then
    echo "错误：此脚本需要 root 权限运行"
    echo "请使用: sudo $0"
    exit 1
fi

# 检查是否已经启动了 server
if ! pgrep -f "server/server" > /dev/null; then
    echo "启动 server..."
    cd /home/ubuntu/ebpf-process-monitor/server
    nohup ./server > server.log 2>&1 &
    SERVER_PID=$!
    echo "Server PID: $SERVER_PID"
    sleep 2
else
    echo "Server 已经在运行"
fi

# 检查是否已经启动了 agent
if ! pgrep -f "agent/agent" > /dev/null; then
    echo "启动 agent..."
    cd /home/ubuntu/ebpf-process-monitor/agent
    nohup ./agent > agent.log 2>&1 &
    AGENT_PID=$!
    echo "Agent PID: $AGENT_PID"
    sleep 2
else
    echo "Agent 已经在运行"
fi

echo ""
echo "等待系统稳定..."
sleep 3

echo ""
echo "===================================="
echo "开始测试场景"
echo "===================================="

# 测试 1: sudo su
echo ""
echo "测试 1: sudo su (应该触发权限提升)"
echo "命令: sudo -u ubuntu -s"
echo ""
sudo -u ubuntu -s echo "Testing sudo escalation"

sleep 2

# 测试 2: 执行 SUID 程序
echo ""
echo "测试 2: 执行 SUID 程序 (应该被检测到)"
echo "命令: /usr/bin/passwd"
echo ""
if [ -x /usr/bin/passwd ]; then
    echo "尝试执行 passwd (不实际修改密码)"
    /usr/bin/passwd --help > /dev/null 2>&1
else
    echo "警告: /usr/bin/passwd 不存在或不可执行"
fi

sleep 2

# 测试 3: 尝试写入 /etc/passwd (模拟攻击)
echo ""
echo "测试 3: 尝试写入敏感文件 (应该被检测到)"
echo "警告: 这是一个模拟测试，不会实际写入文件"
echo ""
# 只是测试监控，不实际写入
echo "尝试写入 /etc/passwd (模拟)" > /dev/null

sleep 2

# 测试 4: 普通用户执行命令 (不应该触发告警)
echo ""
echo "测试 4: 普通用户执行命令 (不应该触发告警)"
echo "命令: ls -la"
echo ""
ls -la /tmp

sleep 2

echo ""
echo "===================================="
echo "测试完成"
echo "===================================="
echo ""
echo "查看 agent 日志:"
echo "  tail -f /home/ubuntu/ebpf-process-monitor/agent/agent.log"
echo ""
echo "查看 server 日志:"
echo "  tail -f /home/ubuntu/ebpf-process-monitor/server/server.log"
echo ""
echo "访问 Web 界面:"
echo "  http://localhost:8080"
echo ""
echo "停止监控:"
echo "  killall agent server"
echo ""