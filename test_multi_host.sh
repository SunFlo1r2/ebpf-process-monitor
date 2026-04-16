#!/bin/bash

# 多主机监控测试脚本
# 使用方法: ./test_multi_host.sh [options]
# 选项:
#   -c, --config <file>    配置文件路径（默认：hosts.conf）
#   -v, --verbose          显示详细输出
#   -h, --help             显示帮助信息

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 全局变量
CONFIG_FILE="hosts.conf"
VERBOSE=false
SERVER_URL=""
TEST_RESULTS=()
FAIL_COUNT=0
PASS_COUNT=0

# 打印函数
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}==========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}==========================================${NC}"
}

print_test() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

print_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    PASS_COUNT=$((PASS_COUNT + 1))
}

print_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    TEST_RESULTS+=("FAIL: $1")
}

# 解析命令行参数
while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            echo "多主机监控测试脚本"
            echo ""
            echo "使用方法: $0 [options]"
            echo ""
            echo "选项:"
            echo "  -c, --config <file>    配置文件路径（默认：hosts.conf）"
            echo "  -v, --verbose          显示详细输出"
            echo "  -h, --help             显示帮助信息"
            exit 0
            ;;
        *)
            print_error "未知参数: $1"
            echo "使用 $0 --help 查看帮助信息"
            exit 1
            ;;
    esac
done

# 检查配置文件
if [ ! -f "$CONFIG_FILE" ]; then
    print_error "配置文件不存在: $CONFIG_FILE"
    exit 1
fi

# 读取配置文件
print_header "读取配置"
HOSTS=()

while IFS='|' read -r field1 field2 field3 field4 || [ -n "$field1" ]; do
    [[ "$field1" =~ ^#.*$ ]] && continue
    [[ -z "$field1" ]] && continue

    if [[ "$field1" =~ ^server_url=(.*)$ ]]; then
        SERVER_URL="${BASH_REMATCH[1]}"
        SERVER_API="${SERVER_URL%/api/events}"
        print_info "服务器地址: $SERVER_API"
        continue
    fi

    AGENT_ID="$field1"
    SSH_HOST="$field2"
    SSH_PORT="${field3:-22}"
    SSH_USER="${field4:-root}"

    if [ -n "$AGENT_ID" ] && [ -n "$SSH_HOST" ]; then
        HOSTS+=("$AGENT_ID|$SSH_HOST|$SSH_PORT|$SSH_USER")
        print_info "添加主机: $AGENT_ID @ $SSH_HOST:$SSH_PORT"
    fi
done < "$CONFIG_FILE"

if [ ${#HOSTS[@]} -eq 0 ]; then
    print_error "没有找到任何主机配置"
    exit 1
fi

# 测试 1: 检查服务器是否运行
print_header "测试 1: 检查服务器状态"
print_test "检查服务器健康状态"

HEALTH_URL="${SERVER_API}/api/health"
if command -v curl &> /dev/null; then
    if curl -s -f "$HEALTH_URL" > /dev/null 2>&1; then
        print_pass "服务器运行正常"
        if [ "$VERBOSE" = true ]; then
            curl -s "$HEALTH_URL" | python3 -m json.tool 2>/dev/null || curl -s "$HEALTH_URL"
        fi
    else
        print_fail "服务器无法访问或未运行"
        exit 1
    fi
else
    print_warning "curl 未安装，跳过服务器检查"
fi

# 测试 2: 检查 SSH 连接
print_header "测试 2: 检查 SSH 连接"
for host_config in "${HOSTS[@]}"; do
    IFS='|' read -r AGENT_ID SSH_HOST SSH_PORT SSH_USER <<< "$host_config"
    print_test "检查 SSH 连接到 $AGENT_ID ($SSH_HOST:$SSH_PORT)"
    
    if ssh -p "$SSH_PORT" -o ConnectTimeout=5 -o StrictHostKeyChecking=no "${SSH_USER}@${SSH_HOST}" "echo 'SSH OK'" 2>/dev/null; then
        print_pass "$AGENT_ID SSH 连接正常"
    else
        print_fail "$AGENT_ID SSH 连接失败"
    fi
done

# 测试 3: 检查 Agent 服务状态
print_header "测试 3: 检查 Agent 服务状态"
for host_config in "${HOSTS[@]}"; do
    IFS='|' read -r AGENT_ID SSH_HOST SSH_PORT SSH_USER <<< "$host_config"
    print_test "检查 $AGENT_ID 的 Agent 服务状态"
    
    STATUS=$(ssh -p "$SSH_PORT" "${SSH_USER}@${SSH_HOST}" "systemctl is-active ebpf-monitor 2>/dev/null" || echo "unknown")
    
    if [ "$STATUS" = "active" ]; then
        print_pass "$AGENT_ID Agent 服务运行中"
    else
        print_fail "$AGENT_ID Agent 服务未运行 (状态: $STATUS)"
    fi
done

# 测试 4: 触发测试事件
print_header "测试 4: 触发测试事件"
for host_config in "${HOSTS[@]}"; do
    IFS='|' read -r AGENT_ID SSH_HOST SSH_PORT SSH_USER <<< "$host_config"
    print_test "在 $AGENT_ID 上触发测试事件"
    
    # 执行一些测试命令
    ssh -p "$SSH_PORT" "${SSH_USER}@${SSH_HOST}" << 'ENDSSH'
        # 创建测试进程
        sleep 1 &
        sleep 1 &
        sleep 1 &
        
        # 执行一些测试命令
        ls -la /tmp > /dev/null 2>&1
        cat /etc/hostname > /dev/null 2>&1
        
        # 等待一下让事件收集
        sleep 2
ENDSSH

    if [ $? -eq 0 ]; then
        print_pass "$AGENT_ID 测试事件触发成功"
    else
        print_fail "$AGENT_ID 测试事件触发失败"
    fi
done

# 等待事件到达服务器
print_info "等待事件到达服务器..."
sleep 5

# 测试 5: 验证事件收集
print_header "测试 5: 验证事件收集"
if command -v curl &> /dev/null; then
    print_test "从服务器获取事件统计"
    
    STATS_URL="${SERVER_API}/api/statistics"
    STATS_JSON=$(curl -s "$STATS_URL" 2>/dev/null)
    
    if [ -n "$STATS_JSON" ]; then
        print_pass "成功获取事件统计"
        
        if [ "$VERBOSE" = true ]; then
            echo "$STATS_JSON" | python3 -m json.tool 2>/dev/null || echo "$STATS_JSON"
        fi
        
        # 检查每个主机的 events_by_agent
        if command -v python3 &> /dev/null; then
            AGENT_COUNT=$(echo "$STATS_JSON" | python3 -c "import sys, json; data=json.load(sys.stdin); print(len(data.get('events_by_agent', {})))" 2>/dev/null || echo "0")
            
            if [ "$AGENT_COUNT" -gt 0 ]; then
                print_pass "检测到 $AGENT_COUNT 个 Agent 的事件"
            else
                print_warning "未检测到任何 Agent 的事件"
            fi
        fi
    else
        print_fail "无法获取事件统计"
    fi
    
    # 测试 6: 验证每个 Agent 的事件
    print_header "测试 6: 验证每个 Agent 的事件"
    for host_config in "${HOSTS[@]}"; do
        IFS='|' read -r AGENT_ID SSH_HOST SSH_PORT SSH_USER <<< "$host_config"
        print_test "查询 $AGENT_ID 的事件"
        
        EVENTS_URL="${SERVER_API}/api/events?agent_id=${AGENT_ID}&limit=5"
        EVENTS_JSON=$(curl -s "$EVENTS_URL" 2>/dev/null)
        
        if [ -n "$EVENTS_JSON" ]; then
            EVENT_COUNT=$(echo "$EVENTS_JSON" | python3 -c "import sys, json; data=json.load(sys.stdin); print(len(data) if isinstance(data, list) else 0)" 2>/dev/null || echo "0")
            
            if [ "$EVENT_COUNT" -gt 0 ]; then
                print_pass "$AGENT_ID 有 $EVENT_COUNT 条事件"
                
                if [ "$VERBOSE" = true ]; then
                    echo "$EVENTS_JSON" | python3 -m json.tool 2>/dev/null | head -20
                fi
            else
                print_warning "$AGENT_ID 暂无事件"
            fi
        else
            print_fail "无法查询 $AGENT_ID 的事件"
        fi
    done
else
    print_warning "curl 未安装，跳过事件验证"
fi

# 测试 7: 检查 Agent 日志
print_header "测试 7: 检查 Agent 日志"
for host_config in "${HOSTS[@]}"; do
    IFS='|' read -r AGENT_ID SSH_HOST SSH_PORT SSH_USER <<< "$host_config"
    print_test "检查 $AGENT_ID 的 Agent 日志"
    
    LOG_CHECK=$(ssh -p "$SSH_PORT" "${SSH_USER}@${SSH_HOST}" "tail -10 /opt/ebpf-monitor/logs/agent.log 2>/dev/null | grep -i 'error' || echo 'no_errors'" 2>/dev/null)
    
    if [ "$LOG_CHECK" = "no_errors" ]; then
        print_pass "$AGENT_ID Agent 日志正常"
    else
        print_warning "$AGENT_ID Agent 日志中发现错误"
        if [ "$VERBOSE" = true ]; then
            ssh -p "$SSH_PORT" "${SSH_USER}@${SSH_HOST}" "tail -20 /opt/ebpf-monitor/logs/agent.log"
        fi
    fi
done

# 生成测试报告
print_header "测试报告"
echo ""
echo "总测试数: $((PASS_COUNT + FAIL_COUNT))"
echo -e "${GREEN}通过: $PASS_COUNT${NC}"
echo -e "${RED}失败: $FAIL_COUNT${NC}"
echo ""

if [ $FAIL_COUNT -gt 0 ]; then
    echo "失败项目:"
    for result in "${TEST_RESULTS[@]}"; do
        echo "  - $result"
    done
    echo ""
fi

# 建议
print_header "建议"
if [ $FAIL_COUNT -eq 0 ]; then
    echo "✓ 所有测试通过！多主机监控系统运行正常。"
else
    echo "✗ 部分测试失败，请检查以下内容："
    echo "  1. 服务器是否正常运行"
    echo "  2. 网络连接是否正常"
    echo "  3. Agent 服务是否已启动"
    echo "  4. 防火墙规则是否正确配置"
    echo ""
    echo "建议执行以下命令："
    echo "  # 检查服务器日志"
    echo "  tail -f server.log"
    echo ""
    echo "  # 检查 Agent 日志"
    echo "  ssh root@host 'tail -f /opt/ebpf-monitor/logs/agent.log'"
    echo ""
    echo "  # 重新部署失败的主机"
    echo "  sudo ./install_agent.sh <agent_id> <server_url>"
fi

echo ""
echo "访问 Web 仪表板查看详细信息："
echo "  $SERVER_API"

# 返回退出码
if [ $FAIL_COUNT -gt 0 ]; then
    exit 1
else
    exit 0
fi