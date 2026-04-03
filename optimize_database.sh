#!/bin/bash
# 优化 SQLite 数据库配置以减少锁定问题

echo "=========================================="
echo "优化 SQLite 数据库配置"
echo "=========================================="
echo ""

cd /home/ubuntu/ebpf-process-monitor/server

# 停止 server
echo "停止 server..."
pkill -f "server/server" 2>/dev/null
sleep 2

# 创建 SQL 优化脚本
cat > optimize_db.sql << 'EOF'
-- 启用 WAL 模式（Write-Ahead Logging）
PRAGMA journal_mode=WAL;

-- 增加 busy timeout
PRAGMA busy_timeout=5000;

-- 优化缓存
PRAGMA cache_size=-64000;

-- 启用临时存储在内存中
PRAGMA temp_store=MEMORY;

-- 同步模式设为 NORMAL（性能更好，安全性略低）
PRAGMA synchronous=NORMAL;

-- 优化锁模式
PRAGMA locking_mode=NORMAL;

-- 真空优化数据库
VACUUM;

-- 分析统计信息
ANALYZE;

-- 检查完整性
PRAGMA integrity_check;
EOF

echo "应用数据库优化..."
sqlite3 security_events.db < optimize_db.sql

if [ $? -eq 0 ]; then
    echo -e "\033[0;32m✓ 数据库优化成功\033[0m"
else
    echo -e "\033[0;31m✗ 数据库优化失败\033[0m"
    exit 1
fi

# 清理临时文件
rm -f optimize_db.sql

echo ""
echo "=========================================="
echo "优化完成"
echo "=========================================="
echo ""
echo "优化内容:"
echo "  ✓ 启用 WAL 模式（减少锁定）"
echo "  ✓ 增加 busy timeout（5秒）"
echo "  ✓ 优化缓存大小"
echo "  ✓ 同步模式设为 NORMAL"
echo "  ✓ 执行 VACUUM 和 ANALYZE"
echo ""
echo "现在请运行修复脚本启动服务:"
echo "  ./fix_frontend_loading.sh"
echo ""