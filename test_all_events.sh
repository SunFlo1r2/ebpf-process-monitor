#!/bin/bash
# 综合事件测试脚本
# 触发高、中、低风险事件，SETUID事件，EXECVE事件，Connect事件和OPENAT事件

set -e

echo "=========================================="
echo "eBPF 综合事件测试脚本"
echo "=========================================="
echo ""

# 颜色定义
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# 检查是否以root运行
if [ "$EUID" -eq 0 ]; then
    echo -e "${RED}警告: 请不要以root用户运行此脚本${NC}"
    echo "使用普通用户运行以正确测试权限提升检测"
    exit 1
fi

echo "1. === 低风险事件测试 ==="
echo "------------------------"

# 低风险：普通用户执行常规命令
echo -e "${BLUE}[LOW] 执行普通命令（ls）${NC}"
ls /tmp > /dev/null
sleep 0.5

# 低风险：普通用户读取非敏感文件
echo -e "${BLUE}[LOW] 读取普通文件${NC}"
cat /etc/hostname > /dev/null
sleep 0.5

# 低风险：普通用户的文件操作
echo -e "${BLUE}[LOW] 创建临时文件${NC}"
echo "test" > /tmp/test_file_$$
sleep 0.5

echo ""
echo "2. === 中风险事件测试 ==="
echo "------------------------"

# 中风险：读取 /etc/hosts
echo -e "${YELLOW}[MEDIUM] 访问 /etc/hosts${NC}"
cat /etc/hosts > /dev/null
sleep 0.5

# 中风险：连接到非常规端口（如果nc可用）
if command -v nc > /dev/null 2>&1; then
    echo -e "${YELLOW}[MEDIUM] 连接到非常规端口 12345${NC}"
    timeout 1 nc -z 127.0.0.1 12345 2>/dev/null || true
    sleep 0.5
fi

# 中风险：root用户执行的高风险程序（需要在子进程中模拟）
echo -e "${YELLOW}[MEDIUM] 模拟root执行程序（需要sudo）${NC}"
if command -v sudo > /dev/null 2>&1; then
    sudo -n id 2>/dev/null || echo "需要sudo密码，跳过此测试"
    sleep 0.5
fi

echo ""
echo "3. === 高风险事件测试 ==="
echo "------------------------"

# 高风险：sudo命令（如果可用）
if command -v sudo > /dev/null 2>&1; then
    echo -e "${RED}[HIGH] 执行 sudo 命令${NC}"
    echo "测试sudo命令..."
    sleep 0.5
fi

# 高风险：访问 /etc/sudoers
echo -e "${RED}[HIGH] 访问 /etc/sudoers${NC}"
if [ -r /etc/sudoers ]; then
    sudo cat /etc/sudoers > /dev/null 2>&1 || true
fi
sleep 0.5

# 高风险：访问 /etc/shadow
echo -e "${RED}[HIGH] 尝试访问 /etc/shadow${NC}"
sudo cat /etc/shadow > /dev/null 2>&1 || true
sleep 0.5

# 高风险：访问 crontab 相关文件
echo -e "${RED}[HIGH] 访问 /etc/crontab${NC}"
sudo cat /etc/crontab > /dev/null 2>&1 || true
sleep 0.5

# 高风险：反向shell模拟（shell进程的网络连接）
if command -v nc > /dev/null 2>&1; then
    echo -e "${RED}[HIGH] 模拟反向shell（bash + nc）${NC}"
    # 在后台启动一个nc监听器，限制运行时间
    (timeout 2 nc -l 12345 > /dev/null 2>&1) &
    NC_PID=$!
    sleep 0.3

    # bash进程连接到该端口
    echo "" | timeout 1 nc 127.0.0.1 12345 > /dev/null 2>&1 || true
    sleep 0.5

    # 清理
    kill $NC_PID 2>/dev/null || true
    sleep 0.2
fi

echo ""
echo "4. === SETUID事件测试 ==="
echo "-------------------------"

# SETUID：使用sudo提升权限
if command -v sudo > /dev/null 2>&1; then
    echo -e "${RED}[SETUID] 使用 sudo 提升权限${NC}"
    sudo id
    sleep 0.5
fi

# SETUID：使用su提升权限（如果可用）
if command -v su > /dev/null 2>&1; then
    echo -e "${RED}[SETUID] 使用 su 提升权限${NC}"
    # 仅检查su是否可用，实际使用需要密码
    which su
    sleep 0.5
fi

echo ""
echo "5. === EXECVE事件测试 ==="
echo "-------------------------"

# EXECVE：执行setuid程序
echo -e "${YELLOW}[EXECVE] 执行 passwd 命令（setuid程序）${NC}"
if command -v passwd > /dev/null 2>&1; then
    # 仅执行但不修改密码
    which passwd
    sleep 0.5
fi

# EXECVE：执行其他setuid程序
echo -e "${YELLOW}[EXECVE] 执行 ping 命令（setuid程序）${NC}"
if command -v ping > /dev/null 2>&1; then
    ping -c 1 127.0.0.1 > /dev/null
    sleep 0.5
fi

# EXECVE：使用sudo执行命令
if command -v sudo > /dev/null 2>&1; then
    echo -e "${YELLOW}[EXECVE] 使用 sudo 执行命令${NC}"
    sudo ls /root > /dev/null 2>&1 || true
    sleep 0.5
fi

echo ""
echo "6. === OPENAT事件测试 ==="
echo "------------------------"

# OPENAT：读取 /etc/passwd（敏感文件）
echo -e "${YELLOW}[OPENAT] 读取 /etc/passwd${NC}"
cat /etc/passwd > /dev/null
sleep 0.5

# OPENAT：读取系统配置文件
echo -e "${YELLOW}[OPENAT] 读取系统配置文件${NC}"
cat /etc/hosts > /dev/null
sleep 0.5

# OPENAT：读取 /etc/group
echo -e "${YELLOW}[OPENAT] 读取 /etc/group${NC}"
cat /etc/group > /dev/null
sleep 0.5

# OPENAT：使用 sudo 访问 SSH 配置目录（root权限）
if [ -d /etc/ssh ]; then
    echo -e "${RED}[OPENAT] 使用 sudo 访问 SSH 配置目录${NC}"
    sudo ls -la /etc/ssh > /dev/null 2>&1
    sleep 0.5
fi

# OPENAT：使用 sudo 读取 /etc/passwd（root权限，确保触发）
echo -e "${RED}[OPENAT] 使用 sudo 读取 /etc/passwd${NC}"
sudo cat /etc/passwd > /dev/null 2>&1
sleep 0.5

echo ""
echo "7. === CONNECT事件测试 ==="
echo "-------------------------"

# CONNECT：使用 sudo 运行 nc 连接到常见端口（root权限）
if command -v nc > /dev/null 2>&1; then
    echo -e "${YELLOW}[CONNECT] 使用 sudo 连接到常见端口 22 (SSH)${NC}"
    sudo timeout 1 nc -z 127.0.0.1 22 2>/dev/null || echo "端口22不可用"
    sleep 0.5

    echo -e "${YELLOW}[CONNECT] 使用 sudo 连接到常见端口 80 (HTTP)${NC}"
    sudo timeout 1 nc -z 127.0.0.1 80 2>/dev/null || echo "端口80不可用"
    sleep 0.5

    echo -e "${RED}[CONNECT] 使用 sudo 连接到非常规端口 4444 (Metasploit)${NC}"
    sudo timeout 1 nc -z 127.0.0.1 4444 2>/dev/null || echo "端口4444不可用"
    sleep 0.5

    echo -e "${RED}[CONNECT] 使用 sudo 连接到非常规端口 5555 (ADB)${NC}"
    sudo timeout 1 nc -z 127.0.0.1 5555 2>/dev/null || echo "端口5555不可用"
    sleep 0.5
fi

# CONNECT：使用 sudo 运行 curl（root权限，确保触发）
if command -v curl > /dev/null 2>&1; then
    echo -e "${YELLOW}[CONNECT] 使用 sudo curl 建立连接${NC}"
    sudo curl -s --connect-timeout 1 http://127.0.0.1:80 > /dev/null 2>&1 || echo "连接失败"
    sleep 0.5
fi

echo ""
echo "=========================================="
echo "测试完成"
echo "=========================================="
echo ""
echo "请检查服务器端日志以确认事件是否被正确检测"
echo "日志位置: /home/ubuntu/ebpf-process-monitor/server.log"
echo ""
echo "你可以访问 Dashboard 查看事件："
echo "http://localhost:8080/static/dashboard.html"
echo ""

# 清理临时文件
rm -f /tmp/test_file_$$

exit 0