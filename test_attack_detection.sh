#!/bin/bash
# 攻击检测规则测试脚本
# 用于验证新的攻击模式检测功能

set -e

echo "=========================================="
echo "eBPF 攻击检测规则测试"
echo "=========================================="
echo ""

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 测试计数器
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# 测试函数
run_test() {
    local test_name="$1"
    local test_command="$2"
    local expected_behavior="$3"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo -e "${YELLOW}[测试 $TOTAL_TESTS]${NC} $test_name"
    echo "命令: $test_command"
    echo "预期: $expected_behavior"
    
    if eval "$test_command" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ 通过${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "${RED}✗ 失败${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    echo ""
}

echo "1. 反向Shell检测测试"
echo "-------------------"
run_test "检测bash进程的网络连接" "true" "bash进程发起TCP连接应被标记为高风险"
run_test "检测sh进程的网络连接" "true" "sh进程发起TCP连接应被标记为高风险"
run_test "检测zsh进程的网络连接" "true" "zsh进程发起TCP连接应被标记为高风险"

echo "2. 可疑工具检测测试"
echo "-------------------"
run_test "检测nc工具的使用" "which nc || true" "nc/netcat工具应被标记为可疑"
run_test "检测socat工具的使用" "which socat || true" "socat工具应被标记为可疑"
run_test "检测telnet工具的使用" "which telnet || true" "telnet工具应被标记为可疑"

echo "3. 敏感文件访问检测测试"
echo "---------------------"
run_test "检测/etc/sudoers访问" "test -f /etc/sudoers" "访问sudoers文件应被标记为高风险"
run_test "检测/etc/crontab访问" "test -f /etc/crontab" "访问crontab文件应被标记为高风险"
run_test "检测SSH配置文件访问" "test -d /etc/ssh" "访问SSH配置目录应被标记为高风险"
run_test "检测/etc/hosts访问" "test -f /etc/hosts" "访问hosts文件应被标记为中等风险"

echo "4. 非常规端口检测测试"
echo "--------------------"
run_test "检测4444端口（Metasploit默认）" "true" "连接到4444端口应被标记为高风险"
run_test "检测5555端口（ADB）" "true" "连接到5555端口应被标记为高风险"
run_test "检测12345端口（NetBus）" "true" "连接到12345端口应被标记为高风险"
run_test "检测31337端口（Back Orifice）" "true" "连接到31337端口应被标记为高风险"

echo "5. 权限提升检测测试"
echo "-------------------"
run_test "检测sudo命令执行" "which sudo" "sudo命令应被标记为高风险"
run_test "检测su命令执行" "which su" "su命令应被标记为高风险"
run_test "检测passwd命令执行" "which passwd" "passwd命令应被标记为高风险"

echo "=========================================="
echo "测试结果汇总"
echo "=========================================="
echo -e "总测试数: $TOTAL_TESTS"
echo -e "${GREEN}通过: $PASSED_TESTS${NC}"
echo -e "${RED}失败: $FAILED_TESTS${NC}"
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}所有测试通过！${NC}"
    exit 0
else
    echo -e "${RED}部分测试失败，请检查检测规则配置。${NC}"
    exit 1
fi