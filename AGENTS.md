# eBPF 进程监控系统

## 项目概述

这是一个基于 eBPF 技术的进程监控系统，能够实时捕获系统中的进程执行事件，检测潜在的权限提升行为。项目采用客户端-服务器架构，包含 eBPF 内核模块、Go 代理、后端服务器和前端可视化界面。

## 架构设计

### 组件结构

```
eBPF-Process-Monitor/
├── agent/           # Go 代理程序
├── kernel/          # eBPF 内核代码
├── server/          # 后端服务器（待开发）
├── frontend/        # 前端可视化界面（待开发）
└── docs/            # 项目文档
```

### 数据流

1. **内核层**：eBPF 程序在 `sys_enter_execve` tracepoint 处捕获进程执行事件
2. **代理层**：Go 代理通过 ring buffer 读取 eBPF 事件
3. **服务层**：后端服务器接收并存储事件数据
4. **展示层**：前端界面实时展示进程监控信息

## 技术栈

### 内核层
- **语言**：C
- **框架**：eBPF
- **依赖**：
  - `vmlinux.h` - 内核类型定义
  - `bpf/bpf_helpers.h` - BPF 辅助函数
  - `bpf/bpf_tracing.h` - BPF 追踪功能

### 代理层
- **语言**：Go 1.24.0
- **主要依赖**：
  - `github.com/cilium/ebpf v0.10.0` - eBPF 库

### 服务层（待开发）
- 建议技术栈：Go/FastAPI/Node.js
- 数据库：PostgreSQL/InfluxDB

### 前端层（待开发）
- 建议技术栈：React/Vue/Svelte
- 实时通信：WebSocket

## 核心功能

### 已实现功能

#### 1. 进程执行监控
- 捕获所有 `execve` 系统调用
- 记录进程详细信息：
  - 时间戳
  - PID/PPID
  - UID/GID/EUID/EGID
  - 进程名称（comm）
  - 执行文件路径

#### 2. 权限提升检测
- 比较真实 UID 和有效 UID
- 自动标记潜在权限提升行为
- 在输出中高亮显示异常事件

#### 3. Ring Buffer 通信
- 使用高效的 ring buffer 机制传输事件
- 支持最大 256KB 的事件缓冲
- 优雅的信号处理和清理

### 待开发功能

#### 服务器端
- RESTful API 接口
- WebSocket 实时推送
- 事件数据持久化
- 历史数据查询
- 异常事件告警

#### 前端界面
- 实时进程列表
- 权限提升事件高亮
- 历史数据图表
- 进程树可视化
- 搜索和过滤功能

## 开发指南

### 环境要求

#### 内核开发
- Linux 内核 5.8+（支持 BPF ring buffer）
- clang + LLVM
- Linux 内核头文件
- bpftool

#### Go 开发
- Go 1.24.0+
- `github.com/cilium/ebpf` 库

### 编译 eBPF 程序

```bash
cd kernel
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c process_monitor.bpf.c -o process_monitor.bpf.o
```

### 编译 Go 代理

```bash
cd agent
go mod download
go build -o agent main.go
```

### 运行监控

```bash
# 需要 root 权限
sudo ./agent
```

### 运行测试

```bash
cd agent
go test ./...
```

## 事件数据结构

### 进程事件结构

```c
struct process_event {
    __u64 timestamp;           // 时间戳（纳秒）
    __u32 pid;                 // 进程 ID
    __u32 ppid;                // 父进程 ID
    __u32 uid;                 // 用户 ID
    __u32 gid;                 // 组 ID
    __u32 euid;                // 有效用户 ID
    __u32 egid;                // 有效组 ID
    char comm[16];             // 进程名称
    char filename[256];        // 执行文件路径
    __u8 is_privilege_escalation;  // 权限提升标志
};
```

### 输出格式

```
[时间戳] PID:xxx PPID:xxx UID:xxx->xxx Comm:xxx File:xxx [PRIVILEGE ESCALATION]
```

## 安全考虑

1. **权限要求**：运行需要 root 权限
2. **内核安全**：使用 `bpf_probe_read_kernel` 安全读取内核数据
3. **空指针检查**：所有指针读取前进行 NULL 检查
4. **内存安全**：使用 ring buffer 而非 perf event 提高安全性

## 性能优化

1. **Ring Buffer**：使用高性能 ring buffer 替代 perf event
2. **按需读取**：仅在事件发生时触发数据传输
3. **高效数据结构**：固定大小数组避免动态内存分配
4. **内联函数**：父进程 PID 获取使用内联优化

## 已知限制

1. **平台依赖**：仅支持 Linux 系统
2. **内核版本**：需要 5.8+ 内核支持 ring buffer
3. **文件名长度**：最大 256 字符
4. **进程名长度**：最大 15 字符（16 字节含 NULL 终止符）

## 未来改进

1. 支持更多系统调用监控（fork, clone, exit 等）
2. 添加进程树追踪功能
3. 支持容器环境监控
4. 添加规则引擎自定义告警
5. 实现机器学习异常检测
6. 支持分布式部署
7. 添加性能指标分析

## 贡献指南

1. Fork 项目
2. 创建特性分支
3. 提交更改
4. 推送到分支
5. 创建 Pull Request

## 许可证

本项目采用 GPL 许可证（与 eBPF 内核代码一致）
