#!/bin/bash

# Agent 安装脚本 - 用于在虚拟机上部署监控 Agent
# 使用方法: sudo ./install_agent.sh <agent_id> <server_url>
# 示例: sudo ./install_agent.sh web-server-01 http://192.168.1.100:8080/api/events

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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

# 检查是否以 root 权限运行
if [ "$EUID" -ne 0 ]; then
    print_error "请使用 root 权限运行此脚本"
    print_info "使用方法: sudo $0 <agent_id> <server_url>"
    exit 1
fi

# 参数检查
if [ $# -lt 2 ]; then
    print_error "参数不足"
    print_info "使用方法: $0 <agent_id> <server_url>"
    print_info ""
    print_info "参数说明:"
    print_info "  agent_id:   Agent ID，用于标识这台主机（如：web-server-01）"
    print_info "  server_url: 服务器地址（如：http://192.168.1.100:8080/api/events）"
    print_info ""
    print_info "示例:"
    print_info "  $0 web-server-01 http://192.168.1.100:8080/api/events"
    exit 1
fi

AGENT_ID=$1
SERVER_URL=$2

print_info "开始安装 Agent..."
print_info "Agent ID: $AGENT_ID"
print_info "Server URL: $SERVER_URL"

# 检查 Go 环境
if ! command -v go &> /dev/null; then
    print_error "Go 未安装，正在安装..."
    apt-get update
    apt-get install -y golang-go
fi

# 检查编译器依赖
print_info "检查编译器依赖..."
if ! command -v clang &> /dev/null; then
    print_info "安装 clang..."
    apt-get install -y clang
fi

if ! command -v llvm &> /dev/null; then
    print_info "安装 llvm..."
    apt-get install -y llvm
fi

# 检查内核头文件
KERNEL_VERSION=$(uname -r)
print_info "内核版本: $KERNEL_VERSION"
if [ ! -f "/lib/modules/$KERNEL_VERSION/build/include/linux/bpf.h" ]; then
    print_info "安装内核头文件..."
    apt-get install -y linux-headers-$(uname -r)
fi

# 进入项目目录
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# 编译 eBPF 程序
print_info "编译 eBPF 程序..."
cd kernel
if [ ! -f "process_monitor.bpf.o" ]; then
    clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c process_monitor.bpf.c -o process_monitor.bpf.o
    print_info "eBPF 程序编译完成"
else
    print_info "eBPF 程序已存在，跳过编译"
fi
cd ..

# 编译 Agent
print_info "编译 Agent..."
cd agent
go build -o agent main.go
print_info "Agent 编译完成"
cd ..

# 创建安装目录
INSTALL_DIR="/opt/ebpf-monitor"
print_info "创建安装目录: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/logs"

# 复制文件
print_info "复制文件到安装目录..."
cp agent/agent "$INSTALL_DIR/"
cp agent/config.json "$INSTALL_DIR/"
cp kernel/process_monitor.bpf.o "$INSTALL_DIR/"

# 创建配置文件
print_info "生成配置文件..."
cat > "$INSTALL_DIR/agent.conf" << EOF
AGENT_ID=$AGENT_ID
SERVER_URL=$SERVER_URL
EOF

# 设置权限
print_info "设置文件权限..."
chmod +x "$INSTALL_DIR/agent"
chmod 644 "$INSTALL_DIR/config.json"
chmod 644 "$INSTALL_DIR/process_monitor.bpf.o"
chmod 644 "$INSTALL_DIR/agent.conf"

# 创建启动脚本
print_info "创建启动脚本..."
cat > "$INSTALL_DIR/start.sh" << 'EOF'
#!/bin/bash
cd /opt/ebpf-monitor
source ./agent.conf
nohup ./agent -id "$AGENT_ID" -server "$SERVER_URL" > logs/agent.log 2>&1 &
echo $! > logs/agent.pid
echo "Agent started with PID: $(cat logs/agent.pid)"
EOF
chmod +x "$INSTALL_DIR/start.sh"

# 创建停止脚本
print_info "创建停止脚本..."
cat > "$INSTALL_DIR/stop.sh" << 'EOF'
#!/bin/bash
PID_FILE="/opt/ebpf-monitor/logs/agent.pid"
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        kill "$PID"
        rm "$PID_FILE"
        echo "Agent stopped (PID: $PID)"
    else
        echo "Agent is not running"
        rm -f "$PID_FILE"
    fi
else
    echo "PID file not found, Agent may not be running"
fi
EOF
chmod +x "$INSTALL_DIR/stop.sh"

# 创建 systemd 服务（可选）
print_info "创建 systemd 服务..."
cat > /etc/systemd/system/ebpf-monitor.service << EOF
[Unit]
Description=EBPF Process Monitor Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/ebpf-monitor
ExecStart=/opt/ebpf-monitor/agent -id=$AGENT_ID -server=$SERVER_URL
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# 重载 systemd
systemctl daemon-reload

# 创建符号链接
ln -sf "$INSTALL_DIR/start.sh" /usr/local/bin/ebpf-monitor-start
ln -sf "$INSTALL_DIR/stop.sh" /usr/local/bin/ebpf-monitor-stop

print_info "=========================================="
print_info "Agent 安装完成！"
print_info "=========================================="
print_info ""
print_info "安装位置: $INSTALL_DIR"
print_info "Agent ID: $AGENT_ID"
print_info "Server URL: $SERVER_URL"
print_info ""
print_info "启动方式（选择一种）:"
print_info "  方式1（推荐）: systemctl start ebpf-monitor"
print_info "  方式2: ebpf-monitor-start"
print_info "  方式3: cd $INSTALL_DIR && ./start.sh"
print_info ""
print_info "停止方式:"
print_info "  方式1: systemctl stop ebpf-monitor"
print_info "  方式2: ebpf-monitor-stop"
print_info "  方式3: cd $INSTALL_DIR && ./stop.sh"
print_info ""
print_info "查看日志:"
print_info "  tail -f $INSTALL_DIR/logs/agent.log"
print_info ""
print_info "开机自启:"
print_info "  systemctl enable ebpf-monitor"
print_info ""
print_info "=========================================="

# 询问是否立即启动
read -p "是否立即启动 Agent？(y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_info "启动 Agent..."
    systemctl start ebpf-monitor
    sleep 2
    if systemctl is-active --quiet ebpf-monitor; then
        print_info "Agent 启动成功！"
        print_info "查看状态: systemctl status ebpf-monitor"
    else
        print_error "Agent 启动失败，请查看日志: $INSTALL_DIR/logs/agent.log"
    fi
fi