#!/bin/bash

# eBPF 风险等级测试脚本
# 用于测试系统的风险评级功能

echo "===================================="
echo "eBPF 风险等级测试脚本"
echo "===================================="
echo ""

# 检查是否以 root 权限运行
if [ "$EUID" -ne 0 ]; then
    echo "错误：此脚本需要 root 权限运行"
    echo "请使用: sudo $0"
    exit 1
fi

# 检查 server 是否运行
if ! curl -s http://localhost:8080/api/health > /dev/null 2>&1; then
    echo "警告：Server 未运行，请先启动 server"
    echo "启动命令：cd /home/ubuntu/ebpf-process-monitor/server && sudo -u ubuntu nohup ./server > server.log 2>&1 &"
    exit 1
fi

echo "✓ Server 运行正常"
echo ""

# 显示当前时间
echo "当前时间: $(date)"
echo "当前用户: $(whoami)"
echo ""

# ============================================
# 1. 触发高风险事件 (HIGH ≥ 35分)
# ============================================
echo "===================================="
echo "1. 触发高风险事件 (HIGH)"
echo "===================================="
echo ""

echo "测试 1.1: sudo 提权操作 (SETUID +30分)"
echo "命令: sudo -i"
sudo -i -c "echo '高风险：sudo 提权操作'" > /dev/null 2>&1
sleep 2

echo "测试 1.2: 执行 SUID 程序 passwd (EXECVE +15分)"
echo "命令: /usr/bin/passwd --help"
if [ -x /usr/bin/passwd ]; then
    /usr/bin/passwd --help > /dev/null 2>&1
else
    echo "警告: /usr/bin/passwd 不存在"
fi
sleep 2

echo "测试 1.3: sudo 执行敏感文件操作 (EXECVE +10分)"
echo "命令: sudo cat /etc/passwd"
sudo cat /etc/passwd > /dev/null 2>&1
sleep 2

echo "测试 1.4: sudo 提权 + 敏感操作 (组合 ≥ 35分)"
echo "命令: sudo su -c 'cat /etc/passwd'"
sudo su -c "cat /etc/passwd" > /dev/null 2>&1
sleep 2

echo "✓ 高风险事件触发完成"
echo ""
sleep 3

# ============================================
# 2. 触发中风险事件 (MEDIUM ≥ 15分)
# ============================================
echo "===================================="
echo "2. 触发中风险事件 (MEDIUM)"
echo "===================================="
echo ""

echo "测试 2.1: 执行高风险程序但无提权 (EXECVE +15分)"
echo "命令: /usr/bin/strace -h"
if [ -x /usr/bin/strace ]; then
    /usr/bin/strace -h > /dev/null 2>&1
else
    echo "警告: /usr/bin/strace 不存在"
fi
sleep 2

echo "测试 2.2: 执行网络相关程序 (EXECVE +15分)"
echo "命令: /usr/bin/ssh -V"
if [ -x /usr/bin/ssh ]; then
    /usr/bin/ssh -V > /dev/null 2>&1
else
    echo "警告: /usr/bin/ssh 不存在"
fi
sleep 2

echo "测试 2.3: 执行计划任务程序 (EXECVE +15分)"
echo "命令: /usr/bin/crontab -l"
/usr/bin/crontab -l > /dev/null 2>&1
sleep 2

echo "测试 2.4: sudo 执行普通程序 (EXECVE +15分)"
echo "命令: sudo ls /tmp"
sudo ls /tmp > /dev/null 2>&1
sleep 2

echo "✓ 中风险事件触发完成"
echo ""
sleep 3

# ============================================
# 3. 触发低风险事件 (LOW < 15分)
# ============================================
echo "===================================="
echo "3. 触发低风险事件 (LOW)"
echo "===================================="
echo ""

echo "测试 3.1: 普通用户执行常规命令 (低风险)"
echo "命令: ls -la"
ls -la /tmp > /dev/null 2>&1
sleep 2

echo "测试 3.2: 执行系统管理工具 (低风险)"
echo "命令: ps aux"
ps aux > /dev/null 2>&1
sleep 2

echo "测试 3.3: root 用户执行普通程序 (极低风险)"
echo "命令: cat /etc/hostname"
cat /etc/hostname > /dev/null 2>&1
sleep 2

echo "测试 3.4: 执行文件操作 (低风险)"
echo "命令: echo 'test' > /tmp/test_file"
echo 'test' > /tmp/test_file
sleep 2

echo "测试 3.5: 查看进程信息 (低风险)"
echo "命令: top -b -n 1"
top -b -n 1 > /dev/null 2>&1
sleep 2

echo "✓ 低风险事件触发完成"
echo ""
sleep 3

# ============================================
# 4. 查看测试结果
# ============================================
echo "===================================="
echo "4. 查看测试结果"
echo "===================================="
echo ""

echo "获取事件统计信息..."
curl -s http://localhost:8080/api/statistics | python3 -m json.tool
echo ""

echo "高风险事件（前5个）:"
curl -s "http://localhost:8080/api/high-risk-events?limit=5" | python3 -m json.tool
echo ""

echo "所有事件（前10个）:"
curl -s "http://localhost:8080/api/events?limit=10" | python3 -m json.tool
echo ""

# ============================================
# 5. 清理
# ============================================
echo "===================================="
echo "5. 清理测试文件"
echo "===================================="
echo ""

rm -f /tmp/test_file
echo "✓ 清理完成"
echo ""

# ============================================
# 6. 后续操作提示
# ============================================
echo "===================================="
echo "测试完成！"
echo "===================================="
echo ""
echo "后续操作："
echo ""
echo "1. 查看 agent 日志:"
echo "   tail -f /home/ubuntu/ebpf-process-monitor/agent/agent.log"
echo ""
echo "2. 查看 server 日志:"
echo "   tail -f /home/ubuntu/ebpf-process-monitor/server/server.log"
echo ""
echo "3. 访问 Web 界面:"
echo "   http://localhost:8080"
echo ""
echo "4. 获取特定风险等级的事件:"
echo "   高风险: curl 'http://localhost:8080/api/events?risk_level=HIGH'"
echo "   中风险: curl 'http://localhost:8080/api/events?risk_level=MEDIUM'"
echo "   低风险: curl 'http://localhost:8080/api/events?risk_level=LOW'"
echo ""
echo "5. 查看事件时间线（需要替换 event_id）:"
echo "   curl 'http://localhost:8080/api/timeline/privilege-escalation?event_id=XXX&time_window=5'"
echo ""
echo "6. 实时监控事件:"
echo "   watch -n 2 'curl -s http://localhost:8080/api/statistics | python3 -m json.tool'"
echo ""
echo "===================================="