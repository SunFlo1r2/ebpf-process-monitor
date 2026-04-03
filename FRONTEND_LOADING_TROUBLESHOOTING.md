# 前端页面加载失败故障排查指南

## 问题描述

前端页面（dashboard.html）经常加载失败，表现为：
- 页面一直显示加载中
- 统计数据无法显示
- WebSocket 连接失败
- API 请求超时

## 根本原因分析

### 1. 数据库锁定问题（最常见）⚠️

**症状**：
- Server 日志显示大量 "Failed to insert event into database: database is locked"
- API 请求超时
- 统计数据无法加载

**原因**：
- SQLite 是单写数据库，高并发时容易锁定
- Agent 发送事件频率高，超过数据库处理能力
- 读取和写入操作冲突

**解决方案**：

```bash
# 1. 优化数据库配置
cd /home/ubuntu/ebpf-process-monitor
./optimize_database.sh

# 2. 重启服务
./fix_frontend_loading.sh
```

### 2. WebSocket 连接问题

**症状**：
- Server 日志显示 "WebSocket upgrade error"
- 前端连接状态显示"未连接"
- 实时事件无法推送

**原因**：
- HTTP 代理未正确处理 WebSocket 升级
- 浏览器安全策略限制
- 网络连接问题

**解决方案**：

```bash
# 1. 检查服务器是否正常运行
curl http://localhost:8080/api/health

# 2. 使用修复后的前端页面
# 访问: http://localhost:8080/static/dashboard_fixed.html

# 3. 检查 WebSocket 连接
# 打开浏览器开发者工具 -> Network -> WS
# 查看连接状态
```

### 3. 服务器端口占用

**症状**：
- Server 日志显示 "listen tcp :8080: bind: address already in use"
- 服务无法启动

**解决方案**：

```bash
# 查找占用端口的进程
sudo lsof -i :8080

# 停止占用端口的进程
sudo kill -9 <PID>

# 或者使用修复脚本自动处理
./fix_frontend_loading.sh
```

### 4. Agent 与 Server 连接问题

**症状**：
- Agent 日志显示 "Failed to send event to server: connection refused"
- 事件无法发送到服务器

**解决方案**：

```bash
# 确保 Server 正在运行
ps aux | grep server

# 检查 Server 端口
netstat -tlnp | grep 8080

# 重启 Agent
pkill -f agent/agent
cd agent
sudo nohup ./agent > agent.log 2>&1 &
```

### 5. 数据库文件损坏

**症状**：
- Server 无法启动
- 查询操作失败

**解决方案**：

```bash
# 检查数据库完整性
sqlite3 server/security_events.db "PRAGMA integrity_check;"

# 如果发现问题，重建数据库
cd server
mv security_events.db security_events.db.corrupted
# Server 会自动创建新的数据库
```

## 快速修复步骤

### 方案 1: 使用自动化脚本（推荐）

```bash
cd /home/ubuntu/ebpf-process-monitor

# 1. 优化数据库
chmod +x optimize_database.sh
./optimize_database.sh

# 2. 重启服务
./fix_frontend_loading.sh

# 3. 访问修复后的前端
# http://localhost:8080/static/dashboard_fixed.html
```

### 方案 2: 手动修复

```bash
cd /home/ubuntu/ebpf-process-monitor

# 1. 停止所有服务
pkill -f "server/server"
pkill -f "agent/agent"

# 2. 备份数据库
cp server/security_events.db server/security_events.db.backup

# 3. 清理锁定文件
rm -f server/security_events.db-shm server/security_events.db-wal

# 4. 优化数据库
sqlite3 server/security_events.db << 'EOF'
PRAGMA journal_mode=WAL;
PRAGMA busy_timeout=5000;
PRAGMA synchronous=NORMAL;
VACUUM;
ANALYZE;
EOF

# 5. 重新编译
cd server
go build -o server main.go
cd ../agent
go build -o agent main.go

# 6. 启动服务
cd ../server
nohup ./server > server.log 2>&1 &
cd ../agent
sudo nohup ./agent > agent.log 2>&1 &

# 7. 等待启动
sleep 3

# 8. 检查服务状态
curl http://localhost:8080/api/health
```

## 长期优化建议

### 1. 减少事件频率

修改 Agent 配置，降低事件发送频率：

```go
// agent/main.go
var sendSemaphore = make(chan struct{}, 10) // 减少并发数从 50 到 10
```

### 2. 使用更强大的数据库

对于生产环境，建议使用 PostgreSQL 或 MySQL 替代 SQLite：

```go
// database.go
// 修改连接字符串
db, err := sql.Open("postgres", "host=localhost port=5432 user=monitor password=secret dbname=events sslmode=disable")
```

### 3. 添加缓存层

在 Server 中添加内存缓存，减少数据库查询：

```go
// main.go
type Server struct {
    statsCache      *EventStatistics
    statsCacheTime  time.Time
    cacheDuration   time.Duration = 30 * time.Second
}
```

### 4. 实现事件批处理

修改 Agent，批量发送事件：

```go
// agent/main.go
var eventBatch = make([]ProcessEvent, 0, 100)
var batchTimer = time.NewTimer(1 * time.Second)

func batchSendEvents() {
    if len(eventBatch) == 0 {
        return
    }
    
    jsonData, _ := json.Marshal(eventBatch)
    resp, err := httpClient.Post(serverURL, "application/json", bytes.NewBuffer(jsonData))
    // ...
}
```

### 5. 增加超时和重试机制

在前端和 Agent 中添加更完善的错误处理：

```javascript
// dashboard.html
async function fetchWithRetry(url, options = {}, maxRetries = 3) {
    for (let i = 0; i < maxRetries; i++) {
        try {
            const response = await fetch(url, {
                ...options,
                signal: AbortSignal.timeout(10000)
            });
            if (response.ok) return response;
        } catch (error) {
            if (i === maxRetries - 1) throw error;
            await new Promise(resolve => setTimeout(resolve, 1000 * (i + 1)));
        }
    }
}
```

## 监控和诊断

### 实时监控

```bash
# 监控 Server 日志
tail -f server/server.log | grep -E "(ERROR|database is locked)"

# 监控 Agent 日志
tail -f agent/agent.log

# 监控数据库锁定
watch -n 1 'sqlite3 server/security_events.db "PRAGMA database_list;"'

# 监控进程
watch -n 1 'ps aux | grep -E "server|agent"'
```

### 性能诊断

```bash
# 检查数据库大小
du -sh server/security_events.db

# 检查事件数量
sqlite3 server/security_events.db "SELECT COUNT(*) FROM security_events;"

# 检查慢查询
sqlite3 server/security_events.db "EXPLAIN QUERY PLAN SELECT * FROM security_events ORDER BY timestamp DESC LIMIT 100;"

# 检查索引使用情况
sqlite3 server/security_events.db "PRAGMA index_list('security_events');"
```

### 网络诊断

```bash
# 检查端口监听
netstat -tlnp | grep 8080

# 测试 HTTP API
curl -v http://localhost:8080/api/health

# 测试 WebSocket（使用 wscat）
wscat -c ws://localhost:8080/ws

# 检查防火墙
sudo ufw status
```

## 常见错误和解决方案

### 错误 1: "database is locked"

**解决方案**：
```bash
# 1. 停止所有写入进程
pkill -f agent/agent

# 2. 等待锁定释放
sleep 2

# 3. 运行数据库优化
./optimize_database.sh

# 4. 重启服务
./fix_frontend_loading.sh
```

### 错误 2: "WebSocket upgrade error"

**解决方案**：
```bash
# 1. 使用修复后的前端页面
# 访问: http://localhost:8080/static/dashboard_fixed.html

# 2. 检查服务器配置
# 确保 WebSocket 端点正确配置

# 3. 清除浏览器缓存
# 按 Ctrl+Shift+Delete 清除缓存
```

### 错误 3: "Failed to fetch"

**解决方案**：
```bash
# 1. 检查服务器是否运行
curl http://localhost:8080/api/health

# 2. 检查防火墙
sudo ufw allow 8080/tcp

# 3. 检查 CORS 配置
# 在 server/main.go 中添加 CORS 支持
```

### 错误 4: "Connection refused"

**解决方案**：
```bash
# 1. 确保 Server 正在运行
ps aux | grep server

# 2. 检查端口占用
netstat -tlnp | grep 8080

# 3. 重启服务
./fix_frontend_loading.sh
```

## 联系和支持

如果以上方法都无法解决问题，请提供以下信息：

1. Server 日志（最近 100 行）
2. Agent 日志（最近 100 行）
3. 浏览器控制台错误信息
4. 网络请求详情（F12 -> Network）
5. 系统信息：
   ```bash
   uname -a
   sqlite3 --version
   go version
   ```

## 相关文档

- README.md: 项目概述
- PRIVILEGE_MONITOR_GUIDE.md: 权限监控指南
- 答辩问答集.md: 技术问答
- 论文初稿.txt: 论文文档