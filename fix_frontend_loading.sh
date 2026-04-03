#!/bin/bash
# 修复前端页面加载失败的脚本

echo "=========================================="
echo "修复前端页面加载失败问题"
echo "=========================================="
echo ""

# 颜色定义
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# 检查当前目录
cd /home/ubuntu/ebpf-process-monitor

echo "1. 检查服务运行状态..."
echo "-----------------------------"

# 停止现有的 server 和 agent
echo -e "${YELLOW}停止现有服务...${NC}"
pkill -f "server/server" 2>/dev/null || echo "Server 未运行"
pkill -f "agent/agent" 2>/dev/null || echo "Agent 未运行"
sleep 2

echo ""
echo "2. 备份并清理数据库..."
echo "-----------------------------"

# 备份数据库
if [ -f "server/security_events.db" ]; then
    cp server/security_events.db server/security_events.db.backup.$(date +%Y%m%d_%H%M%S)
    echo -e "${GREEN}✓ 数据库已备份${NC}"
fi

# 清理锁定文件
rm -f server/security_events.db-shm server/security_events.db-wal
echo -e "${GREEN}✓ 清理了数据库锁定文件${NC}"

echo ""
echo "3. 重新编译 server..."
echo "-----------------------------"

cd server
go build -o server main.go
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Server 编译成功${NC}"
else
    echo -e "${RED}✗ Server 编译失败${NC}"
    exit 1
fi

echo ""
echo "4. 重新编译 agent..."
echo "-----------------------------"

cd ../agent
go build -o agent main.go
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Agent 编译成功${NC}"
else
    echo -e "${RED}✗ Agent 编译失败${NC}"
    exit 1
fi

echo ""
echo "5. 启动服务..."
echo "-----------------------------"

cd ../server

# 检查端口是否被占用
if netstat -tlnp 2>/dev/null | grep -q ":8080 "; then
    echo -e "${YELLOW}警告: 端口 8080 被占用，尝试释放...${NC}"
    sudo lsof -ti:8080 | xargs kill -9 2>/dev/null || true
    sleep 1
fi

# 启动 server（以 ubuntu 用户运行，避免 root 权限问题）
echo "启动 server..."
nohup ./server > server.log 2>&1 &
SERVER_PID=$!
echo -e "${GREEN}✓ Server 已启动 (PID: $SERVER_PID)${NC}"

# 等待 server 启动
sleep 3

# 检查 server 是否正常运行
if curl -s http://localhost:8080/api/health > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Server 运行正常${NC}"
else
    echo -e "${RED}✗ Server 启动失败${NC}"
    echo "查看日志: tail -f server/server.log"
    exit 1
fi

cd ../agent

# 启动 agent（需要 root 权限）
echo "启动 agent..."
sudo nohup ./agent > agent.log 2>&1 &
AGENT_PID=$!
echo -e "${GREEN}✓ Agent 已启动 (PID: $AGENT_PID)${NC}"

# 等待 agent 启动
sleep 2

# 检查 agent 是否正常运行
if ps -p $AGENT_PID > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Agent 运行正常${NC}"
else
    echo -e "${YELLOW}⚠ Agent 可能未正常启动${NC}"
fi

echo ""
echo "=========================================="
echo "修复完成"
echo "=========================================="
echo ""
echo "访问地址:"
echo "  Dashboard: http://localhost:8080/static/dashboard.html"
echo "  测试页面: http://localhost:8080/static/test.html"
echo ""
echo "日志查看:"
echo "  Server 日志: tail -f server/server.log"
echo "  Agent 日志: tail -f agent/agent.log"
echo ""
echo "健康检查:"
echo "  curl http://localhost:8080/api/health"
echo ""
echo "如果仍然有问题，请检查:"
echo "  1. 数据库是否损坏: sqlite3 server/security_events.db 'PRAGMA integrity_check;'"
echo "  2. 端口是否被占用: netstat -tlnp | grep 8080"
echo "  3. 内存是否充足: free -h"
echo ""