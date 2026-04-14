# 多主机监控功能使用指南

## 功能说明

本系统支持多主机监控，通过为每个 Agent 分配唯一的 ID，可以同时监控多台服务器/主机，并在同一个仪表板中统一查看所有主机的事件。

## 快速开始

### 1. 启动服务器

```bash
cd server
go run .
```

### 2. 启动多个 Agent

使用提供的测试脚本一键启动多个 Agent：

```bash
cd /home/ubuntu/ebpf-process-monitor
./test_multi_agent.sh
```

这将启动 3 个 Agent，模拟不同的服务器：
- `web-server-01` - Web 服务器监控
- `database-server-01` - 数据库服务器监控
- `app-server-01` - 应用服务器监控

### 3. 访问仪表板

打开浏览器访问：http://localhost:8080

### 4. 按主机过滤事件

在仪表板的过滤器区域，使用 "Agent ID" 输入框：
- 输入 `web-server-01` 查看 Web 服务器的事件
- 输入 `database-server-01` 查看数据库服务器的事件
- 输入 `app-server-01` 查看应用服务器的事件
- 留空则显示所有主机的事件

## 手动启动 Agent

如果你想手动控制每个 Agent，可以使用命令行参数：

```bash
# 启动 Web 服务器监控 Agent
sudo ./agent -id web-server-01

# 启动数据库服务器监控 Agent
sudo ./agent -id database-server-01

# 启动应用服务器监控 Agent
sudo ./agent -id app-server-01
```

### 命令行参数

```
-id string
    Agent ID 用于标识不同的监控主机 (默认 "default")

-agent-id string
    Agent ID 用于标识不同的监控主机 (默认 "default")
```

两个参数功能相同，可以使用任一个。

## 停止所有 Agent

```bash
cd /home/ubuntu/ebpf-process-monitor
./stop_agents.sh
```

## 查看实时日志

```bash
# 查看 Web 服务器 Agent 日志
tail -f logs/web-server.log

# 查看数据库服务器 Agent 日志
tail -f logs/database-server.log

# 查看应用服务器 Agent 日志
tail -f logs/app-server.log
```

## API 使用示例

### 获取所有主机的事件
```bash
curl "http://localhost:8080/api/events?limit=10"
```

### 获取特定主机的事件
```bash
curl "http://localhost:8080/api/events?limit=10&agent_id=web-server-01"
```

### 获取所有主机的统计信息
```bash
curl "http://localhost:8080/api/statistics"
```

## 数据库验证

查询数据库中不同 Agent 的事件分布：

```bash
cd server
python3 -c "
import sqlite3
conn = sqlite3.connect('security_events.db')
cursor = conn.cursor()
cursor.execute('SELECT agent_id, COUNT(*) FROM security_events GROUP BY agent_id')
print('Agent ID 分布:')
for row in cursor.fetchall():
    print(f'  {row[0]}: {row[1]} 条事件')
conn.close()
"
```

## 答辩演示要点

1. **架构展示**：说明系统采用分布式 Agent-Server 架构，每个主机运行独立的 Agent
2. **统一监控**：展示所有主机的事件在同一个仪表板中统一显示
3. **按主机过滤**：演示如何查看特定主机的事件
4. **可扩展性**：说明可以轻松添加更多主机，只需部署新 Agent
5. **实际应用**：举例说明生产环境中的应用场景（前端、后端、数据库等不同类型服务器）

## 注意事项

1. eBPF 程序需要 root 权限才能加载，因此必须使用 `sudo` 运行 agent
2. 每个 Agent ID 必须唯一，避免重复
3. 服务器需要先启动，Agent 才能成功连接
4. Agent 会自动过滤自己产生的事件，避免无限循环
5. 建议为不同类型的服务器使用有意义的 Agent ID（如：web-01, db-01, app-01 等）

## 故障排查

### Agent 无法启动
- 检查是否有 root 权限（需要使用 sudo）
- 检查服务器是否正在运行
- 查看日志文件排查具体错误

### 看不到新 Agent 的事件
- 等待几秒钟，让 Agent 收集一些系统事件
- 检查 Agent 是否正常运行（`ps aux | grep agent`）
- 在仪表板中使用正确的 Agent ID 过滤

### 多个 Agent 显示相同的事件
- 确保每个 Agent 使用了不同的 `-id` 参数
- 检查 Agent 日志，确认启动时显示的 Agent ID