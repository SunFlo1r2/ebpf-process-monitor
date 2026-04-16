#!/bin/bash

# 多主机一键部署脚本
# 使用方法: ./deploy_multi_host.sh [options]
# 选项:
#   -c, --config <file>    配置文件路径（默认：hosts.conf）
#   -h, --help             显示帮助信息

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# 默认配置
CONFIG_FILE="hosts.conf"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# 解析命令行参数
while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        -h|--help)
            echo "多主机一键部署脚本"
            echo ""
            echo "使用方法: $0 [options]"
            echo ""
            echo "选项:"
            echo "  -c, --config <file>    配置文件路径（默认：hosts.conf）"
            echo "  -h, --help             显示帮助信息"
            echo ""
            echo "示例:"
            echo "  $0                                    # 使用默认配置文件"
            echo "  $0 -c custom_hosts.conf              # 使用自定义配置文件"
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
    print_info "请先创建配置文件，参考 hosts.conf 示例"
    exit 1
fi

# 读取配置文件
print_header "读取配置文件"
SERVER_URL=""
HOSTS=()

while IFS='|' read -r field1 field2 field3 field4 || [ -n "$field1" ]; do
    # 跳过注释和空行
    [[ "$field1" =~ ^#.*$ ]] && continue
    [[ -z "$field1" ]] && continue

    # 解析服务器地址
    if [[ "$field1" =~ ^server_url=(.*)$ ]]; then
        SERVER_URL="${BASH_REMATCH[1]}"
        print_info "服务器地址: $SERVER_URL"
        continue
    fi

    # 解析主机配置
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

if [ -z "$SERVER_URL" ]; then
    print_error "未配置服务器地址"
    exit 1
fi

# 获取本机 IP（用于显示）
LOCAL_IP=$(hostname -I | awk '{print $1}')
print_info "本机 IP: $LOCAL_IP"
print_info "将要部署到 ${#HOSTS[@]} 台主机"

# 确认部署
echo ""
read -p "是否开始部署？(y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    print_info "部署已取消"
    exit 0
fi

# 准备部署包
print_header "准备部署包"
TEMP_DIR=$(mktemp -d)
print_info "创建临时目录: $TEMP_DIR"

# 复制必要文件
print_info "复制文件到部署包..."
mkdir -p "$TEMP_DIR/kernel"
mkdir -p "$TEMP_DIR/agent"

cp "$SCRIPT_DIR/install_agent.sh" "$TEMP_DIR/"
cp "$SCRIPT_DIR/kernel/process_monitor.bpf.c" "$TEMP_DIR/kernel/"
cp "$SCRIPT_DIR/kernel/vmlinux.h" "$TEMP_DIR/kernel/"
cp "$SCRIPT_DIR/agent/main.go" "$TEMP_DIR/agent/"
cp "$SCRIPT_DIR/agent/go.mod" "$TEMP_DIR/agent/"
cp "$SCRIPT_DIR/agent/go.sum" "$TEMP_DIR/agent/"

# 创建打包脚本
cat > "$TEMP_DIR/package.sh" << 'EOF'
#!/bin/bash
cd /opt/ebpf-monitor
tar -czf /tmp/ebpf-monitor-deploy.tar.gz install_agent.sh kernel agent
EOF
chmod +x "$TEMP_DIR/package.sh"

# 打包
cd "$TEMP_DIR"
tar -czf ebpf-monitor-deploy.tar.gz install_agent.sh kernel agent
print_info "部署包已创建: $TEMP_DIR/ebpf-monitor-deploy.tar.gz"

# 部署到每台主机
SUCCESS_COUNT=0
FAIL_COUNT=0
FAILED_HOSTS=()

print_header "开始部署"

for host_config in "${HOSTS[@]}"; do
    IFS='|' read -r AGENT_ID SSH_HOST SSH_PORT SSH_USER <<< "$host_config"

    print_info "=========================================="
    print_info "部署到: $AGENT_ID @ $SSH_HOST:$SSH_PORT"
    print_info "=========================================="

    # 测试 SSH 连接
    if ! ssh -p "$SSH_PORT" -o ConnectTimeout=5 -o StrictHostKeyChecking=no "${SSH_USER}@${SSH_HOST}" "echo 'SSH连接成功'" 2>/dev/null; then
        print_error "SSH 连接失败，跳过此主机"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_HOSTS+=("$AGENT_ID ($SSH_HOST)")
        continue
    fi

    # 创建远程临时目录
    REMOTE_TEMP_DIR=$(ssh -p "$SSH_PORT" "${SSH_USER}@${SSH_HOST}" "mktemp -d")

    # 上传部署包
    print_info "上传部署包..."
    if ! scp -P "$SSH_PORT" "$TEMP_DIR/ebpf-monitor-deploy.tar.gz" "${SSH_USER}@${SSH_HOST}:${REMOTE_TEMP_DIR}/"; then
        print_error "上传失败"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_HOSTS+=("$AGENT_ID ($SSH_HOST)")
        ssh -p "$SSH_PORT" "${SSH_USER}@${SSH_HOST}" "rm -rf $REMOTE_TEMP_DIR"
        continue
    fi

    # 远程解压并安装
    print_info "远程安装..."
    ssh -p "$SSH_PORT" "${SSH_USER}@${SSH_HOST}" << ENDSSH
        set -e
        cd "$REMOTE_TEMP_DIR"
        tar -xzf ebpf-monitor-deploy.tar.gz
        
        # 执行安装
        if bash install_agent.sh "$AGENT_ID" "$SERVER_URL" 2>&1 | tee install.log; then
            echo "安装成功"
        else
            echo "安装失败"
            exit 1
        fi
        
        # 清理
        cd /
        rm -rf "$REMOTE_TEMP_DIR"
ENDSSH

    if [ $? -eq 0 ]; then
        print_info "$AGENT_ID 部署成功！"
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    else
        print_error "$AGENT_ID 部署失败"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_HOSTS+=("$AGENT_ID ($SSH_HOST)")
    fi

    echo ""
done

# 清理临时文件
print_info "清理临时文件..."
rm -rf "$TEMP_DIR"

# 显示部署结果
print_header "部署结果"
print_info "成功: $SUCCESS_COUNT 台"
print_info "失败: $FAIL_COUNT 台"

if [ $FAIL_COUNT -gt 0 ]; then
    echo ""
    print_error "失败的主机:"
    for host in "${FAILED_HOSTS[@]}"; do
        echo "  - $host"
    done
fi

# 显示管理命令
print_header "后续操作"
echo ""
echo "在服务器上查看所有主机的事件："
echo "  curl \"http://localhost:8080/api/events?limit=100\""
echo ""
echo "查看特定主机的事件："
for host_config in "${HOSTS[@]}"; do
    IFS='|' read -r AGENT_ID SSH_HOST SSH_PORT SSH_USER <<< "$host_config"
    echo "  curl \"http://localhost:8080/api/events?agent_id=$AGENT_ID&limit=10\""
done
echo ""
echo "在远程主机上管理 Agent："
echo "  查看 Agent 状态: systemctl status ebpf-monitor"
echo "  启动 Agent: systemctl start ebpf-monitor"
echo "  停止 Agent: systemctl stop ebpf-monitor"
echo "  重启 Agent: systemctl restart ebpf-monitor"
echo "  查看日志: tail -f /opt/ebpf-monitor/logs/agent.log"
echo ""

if [ $SUCCESS_COUNT -gt 0 ]; then
    print_info "多主机部署完成！"
else
    print_error "所有主机部署失败，请检查配置和网络连接"
    exit 1
fi