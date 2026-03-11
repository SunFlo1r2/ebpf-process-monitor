# eBPF 进程监控后端服务器

## 功能概述

后端服务器提供以下功能：

- **HTTP API**：接收和查询进程事件
- **WebSocket**：实时推送进程事件
- **内存存储**：存储最近 10000 个事件
- **健康检查**：监控服务器状态

## 快速开始

### 编译

```bash
go build -o server main.go
```

### 运行

```bash
./server
```

或使用启动脚本：

```bash
./start.sh
```

服务器将在 `http://localhost:8080` 启动。

## API 接口

### 1. 提交事件

**POST** `/api/events`

提交进程执行事件。

**请求体示例：**

```json
{
  "timestamp": 1678888888000000000,
  "pid": 12345,
  "ppid": 1234,
  "uid": 1000,
  "gid": 1000,
  "euid": 0,
  "egid": 0,
  "comm": "sudo",
  "filename": "/usr/bin/sudo",
  "is_privilege_escalation": true
}
```

**响应：**

```json
{"status": "success"}
```

### 2. 获取所有事件

**GET** `/api/events`

获取所有存储的事件。

**响应：**

```json
[
  {
    "timestamp": 1678888888000000000,
    "pid": 12345,
    "ppid": 1234,
    "uid": 1000,
    "gid": 1000,
    "euid": 0,
    "egid": 0,
    "comm": "sudo",
    "filename": "/usr/bin/sudo",
    "is_privilege_escalation": true
  }
]
```

### 3. 获取最近事件

**GET** `/api/events/recent/{limit}`

获取最近的 N 个事件。

**示例：**

```
GET /api/events/recent/100
```

### 4. 健康检查

**GET** `/api/health`

检查服务器状态。

**响应：**

```json
{
  "status": "healthy",
  "clients": 2,
  "events": 156
}
```

## WebSocket 连接

**URL：** `ws://localhost:8080/ws`

连接后将实时接收到所有进程事件。连接时会自动发送最近 100 个事件。

**JavaScript 客户端示例：**

```javascript
const ws = new WebSocket('ws://localhost:8080/ws');

ws.onmessage = function(event) {
  const data = JSON.parse(event.data);
  console.log('New event:', data);
};

ws.onerror = function(error) {
  console.error('WebSocket error:', error);
};
```

## 与 Agent 集成

要使 Agent 与服务器通信，需要修改 Agent 代码以发送数据到服务器端点。

修改 `agent/main.go`：

```go
// 在事件处理部分添加 HTTP 请求
eventData, _ := json.Marshal(event)
resp, err := http.Post("http://localhost:8080/api/events", "application/json", bytes.NewBuffer(eventData))
if err != nil {
    log.Printf("Failed to send event to server: %v", err)
} else {
    resp.Body.Close()
}
```

## 数据结构

### ProcessEvent

| 字段 | 类型 | 描述 |
|------|------|------|
| timestamp | uint64 | 时间戳（纳秒） |
| pid | uint32 | 进程 ID |
| ppid | uint32 | 父进程 ID |
| uid | uint32 | 用户 ID |
| gid | uint32 | 组 ID |
| euid | uint32 | 有效用户 ID |
| egid | uint32 | 有效组 ID |
| comm | string | 进程名称 |
| filename | string | 执行文件路径 |
| is_privilege_escalation | bool | 是否权限提升 |

## 配置

服务器默认配置：

- **监听地址**：`:8080`
- **最大事件数**：10000
- **WebSocket**：启用

## 依赖

- Go 1.24.0+
- github.com/gorilla/mux v1.8.1
- github.com/gorilla/websocket v1.5.1

## 测试

使用 curl 测试 API：

```bash
# 健康检查
curl http://localhost:8080/api/health

# 提交事件
curl -X POST http://localhost:8080/api/events \
  -H "Content-Type: application/json" \
  -d '{"timestamp": 1678888888000000000, "pid": 12345, "ppid": 1234, "uid": 1000, "gid": 1000, "euid": 0, "egid": 0, "comm": "sudo", "filename": "/usr/bin/sudo", "is_privilege_escalation": true}'

# 获取所有事件
curl http://localhost:8080/api/events

# 获取最近 50 个事件
curl http://localhost:8080/api/events/recent/50
```

## 后续改进

- [ ] 添加数据库持久化
- [ ] 实现事件过滤和搜索
- [ ] 添加认证和授权
- [ ] 支持配置文件
- [ ] 添加日志轮转
- [ ] 实现事件统计和聚合