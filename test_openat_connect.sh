#!/bin/bash
# 专门测试 OPENAT 和 CONNECT 事件的脚本

set -e

echo "=========================================="
echo "OPENAT 和 CONNECT 事件测试"
echo "=========================================="
echo ""

# 颜色定义
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo "1. === OPENAT 事件测试 ==="
echo "--------------------------"

echo -e "${YELLOW}[OPENAT] 使用 sudo 读取 /etc/passwd${NC}"
sudo cat /etc/passwd > /dev/null
sleep 1

echo -e "${YELLOW}[OPENAT] 使用 sudo 读取 /etc/hosts${NC}"
sudo cat /etc/hosts > /dev/null
sleep 1

echo -e "${YELLOW}[OPENAT] 使用 sudo 读取 /etc/group${NC}"
sudo cat /etc/group > /dev/null
sleep 1

if [ -d /etc/ssh ]; then
    echo -e "${RED}[OPENAT] 使用 sudo 访问 SSH 配置目录${NC}"
    sudo ls -la /etc/ssh > /dev/null
    sleep 1
fi

echo ""
echo "2. === CONNECT 事件测试 ==="
echo "---------------------------"

if command -v nc > /dev/null 2>&1; then
    echo -e "${YELLOW}[CONNECT] 使用 sudo 连接到端口 22${NC}"
    sudo timeout 2 nc -z 127.0.0.1 22 2>/dev/null || echo "端口22不可用"
    sleep 1

    echo -e "${YELLOW}[CONNECT] 使用 sudo 连接到端口 80${NC}"
    sudo timeout 2 nc -z 127.0.0.1 80 2>/dev/null || echo "端口80不可用"
    sleep 1

    echo -e "${RED}[CONNECT] 使用 sudo 连接到端口 4444${NC}"
    sudo timeout 2 nc -z 127.0.0.1 4444 2>/dev/null || echo "端口4444不可用"
    sleep 1

    echo -e "${RED}[CONNECT] 使用 sudo 连接到端口 5555${NC}"
    sudo timeout 2 nc -z 127.0.0.1 5555 2>/dev/null || echo "端口5555不可用"
    sleep 1
fi

if command -v curl > /dev/null 2>&1; then
    echo -e "${YELLOW}[CONNECT] 使用 sudo curl 建立连接${NC}"
    sudo curl -s --connect-timeout 2 http://127.0.0.1:80 > /dev/null 2>&1 || echo "连接失败"
    sleep 1
fi

echo ""
echo "=========================================="
echo "测试完成"
echo "=========================================="
echo ""
echo "请检查 Dashboard 或数据库查看事件："
echo "  http://localhost:8080/static/dashboard.html"
echo "  数据库: /home/ubuntu/ebpf-process-monitor/security_events.db"
echo ""
echo "查询命令："
echo "  sqlite3 /home/ubuntu/ebpf-process-monitor/security_events.db \"SELECT event_type, COUNT(*) FROM security_events GROUP BY event_type;\""
echo ""

exit 0