# eBPF 进程监控与安全取证系统

## 📋 项目概述

基于 eBPF 技术的实时进程监控和安全取证系统，能够在内核层拦截和检测权限提升行为，提供完整的时间线重建功能，用于安全事件调查和取证分析。系统通过智能风险评级算法，自动识别高、中、低三个风险等级的安全事件。

## 🎯 核心功能

### 1. 实时权限提升监控
- **LSM 钩子监控**：在内核权限验证层拦截，比 tracepoint 更早捕获
- **多维度检测**：
  - `task_fix_setuid` - 权限变更监控
  - `file_permission` - 敏感文件写入监控
  - `execve` - 进程执行监控
- **支持场景**：
  - sudo su / sudo -i
  - setuid 系统调用
  - SUID 程序执行
  - 敏感文件写入

### 2. 提权事件时间线重建
- **完整活动回溯**：自动追踪提权进程过去 5-10 分钟的所有活动
- **追踪内容**：
  - ✅ 执行过的所有命令（EXECVE）
  - ✅ 访问过的文件和目录（OPENAT）
  - ✅ 建立的网络连接（CONNECT）
  - ✅ 端口绑定操作（BIND）
  - ✅ 进程退出记录（EXIT）
  - ✅ 系统调用序列

### 3. 智能风险评级
系统根据多种因素自动评估事件风险等级，分为高、中、低三个等级。

#### 风险等级分类

| 风险等级 | 评分范围 | 说明 |
|---------|---------|------|
| **HIGH（高风险）** | ≥ 25 分 | 权限提升操作、sudo/su 等提权命令 |
| **MEDIUM（中风险）** | 12-24 分 | root 用户直接执行的高风险程序 |
| **LOW（低风险）** | < 12 分 | 常规程序、root 用户执行的普通操作 |

#### 详细评分规则

**基础评分**

1. **权限提升检测**
   - 真正的权限提升（UID ≠ 0 → EUID = 0）：+20 分
   - 标记的权限提升但非真正提权：+3 分

2. **事件类型评分**
   - **EXECVE（类型 0）**：
     - 高风险程序：+15 分
     - 敏感路径访问：+10 分
   - **SETUID（类型 1）**：
     - 提升到 root（UID ≠ 0 → UID = 0）：+30 分
   - **FILE_WRITE（类型 2）**：
     - 写入 /etc/passwd 或 /etc/shadow：+35 分

3. **时间因素**
   - 非工作时间（22:00-06:00）：+5 分

**特殊规则**

4. **root 用户执行的程序（UID=0, EUID=0）**
   - **常规程序**（非高风险程序、非敏感路径）：风险评分 = 0（低风险）
   - **高风险程序**（ssh、strace、crontab 等）：风险评分 = 15（中风险）

5. **权限提升事件的额外加分**
   - **sudo/su 命令**：无论 UID 和 EUID 如何，直接设为 27 分（高风险）
   - **真正的权限提升** + **高风险程序**：设为 27 分（高风险）
   - **其他真正的权限提升**：设为 25 分（高风险）
   - **root 用户直接执行的高风险程序**：保持 15 分（中风险），不加分

#### 高风险程序列表

**权限管理类**
- `sudo` - 超级用户执行
- `su` - 切换用户
- `passwd` - 修改密码
- `chsh` - 修改 shell
- `chfn` - 修改用户信息

**计划任务类**
- `crontab` - 定时任务管理
- `at` - 一次性任务
- `batch` - 批处理任务

**远程访问类**
- `ssh` - SSH 客户端
- `scp` - 安全复制
- `sftp` - 安全文件传输

**系统管理类**
- `mount` - 挂载文件系统
- `umount` - 卸载文件系统
- `modprobe` - 加载内核模块
- `insmod` - 插入内核模块
- `rmmod` - 删除内核模块
- `iptables` - 防火墙规则
- `nft` - nftables 防火墙

**调试工具类**
- `strace` - 系统调用跟踪
- `ltrace` - 库函数跟踪
- `gdb` - GNU 调试器
- `perf` - 性能分析工具
- `tcpdump` - 网络抓包
- `wireshark` - 网络协议分析

#### 敏感路径列表

- `/etc/passwd` - 用户密码文件
- `/etc/shadow` - 加密密码文件
- `/etc/group` - 用户组文件
- `/etc/sudoers` - sudo 配置文件
- `/etc/crontab` - 系统定时任务
- `/etc/cron.*` - 定时任务目录
- `/root/` - root 用户主目录
- `/home/` - 用户主目录
- `/var/log/` - 系统日志目录

#### 评分示例

**高风险事件（≥25分）**

1. **sudo ls** - 评分：27
   - comm = "sudo"，直接设为 27 分

2. **su - root** - 评分：27
   - comm = "su"，直接设为 27 分

3. **普通用户 sudo cat /etc/passwd** - 评分：27
   - 真正的权限提升（UID ≠ 0 → EUID = 0）+20
   - 高风险程序 +15
   - 敏感路径 +10
   - 权限提升额外加分 = 27

4. **sudo strace ls** - 评分：27
   - comm = "sudo"，直接设为 27 分

5. **SETUID 提升到 root** - 评分：25
   - 真正的权限提升 +20
   - SETUID 事件 +5
   - 总分 = 25

**中风险事件（12-24分）**

1. **root 用户直接执行 ssh -V** - 评分：15
   - UID=0, EUID=0
   - 高风险程序 +15
   - 不加额外分（非真正权限提升）

2. **root 用户直接执行 strace -h** - 评分：15
   - UID=0, EUID=0
   - 高风险程序 +15
   - 不加额外分

3. **root 用户直接执行 crontab -l** - 评分：15
   - UID=0, EUID=0
   - 高风险程序 +15
   - 不加额外分

4. **非工作时间执行敏感操作** - 评分：20-24
   - 基础分 +15
   - 时间因素 +5
   - 可能的权限提升加分

**低风险事件（<12分）**

1. **root 用户执行 ls /tmp** - 评分：0
   - UID=0, EUID=0
   - 非高风险程序
   - 非敏感路径
   - 评分降至 0

2. **root 用户执行 cat /etc/hostname** - 评分：0
   - UID=0, EUID=0
   - 非高风险程序
   - 非敏感路径
   - 评分降至 0

3. **普通用户执行 ls** - 评分：0
   - UID=1000, EUID=1000
   - 非高风险程序
   - 无权限提升
   - 评分 = 0

4. **普通用户执行 ps aux** - 评分：0
   - UID=1000, EUID=1000
   - 非高风险程序
   - 无权限提升
   - 评分 = 0

### 4. 可视化仪表板
- **实时事件流**：WebSocket 实时推送
- **多视图展示**：卡片视图和表格视图
- **时间线可视化**：直观的事件时间轴
- **过滤和搜索**：按风险等级、事件类型、Agent ID 过滤
- **统计分析**：风险分布、事件类型分布

## 🏗️ 技术架构

### 系统组件

```
┌─────────────────────────────────────────────────────────┐
│                    用户空间应用层                         │
│  ┌──────────────┐          ┌──────────────┐            │
│  │   Agent      │──────────▶│   Server     │            │
│  │  (Go)        │  HTTP    │   (Go)       │            │
│  └──────────────┘          └──────────────┘            │
│         │                         │                    │
│         │ Ring Buffer             │ WebSocket          │
│         ▼                         ▼                    │
└─────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────┐
│                      内核空间                             │
│  ┌──────────────────────────────────────────────────┐   │
│  │           eBPF 程序 (process_monitor.bpf.c)       │   │
│  │                                                   │   │
│  │  ┌─────────────┐  ┌─────────────┐               │   │
│  │  │ trace_execve│  │trace_setuid │               │   │
│  │  │ trace_openat│  │trace_connect│               │   │
│  │  │ trace_bind  │  │ trace_exit  │               │   │
│  │  └─────────────┘  └─────────────┘               │   │
│  │                                                   │   │
│  │  ┌─────────────────────┐  ┌───────────────────┐ │   │
│  │  │ task_fix_setuid LSM │  │file_permission LSM│ │   │
│  │  └─────────────────────┘  └───────────────────┘ │   │
│  │                                                   │   │
│  │  ┌─────────────────────────────────────────────┐ │   │
│  │  │            Ring Buffer Map                   │ │   │
│  │  └─────────────────────────────────────────────┘ │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

### 技术栈

**内核层**
- 语言：C
- 框架：eBPF
- 依赖：vmlinux.h, bpf_helpers.h, bpf_tracing.h

**代理层**
- 语言：Go 1.24.0+
- 依赖：github.com/cilium/ebpf v0.10.0

**服务层**
- 语言：Go 1.24.0+
- 数据库：SQLite3
- Web框架：gorilla/mux, gorilla/websocket

**前端层**
- 框架：React 18（CDN）
- 实时通信：WebSocket

## 📦 安装部署

### 环境要求
- Linux 内核 5.8+（支持 BPF ring buffer）
- clang + LLVM
- Go 1.24.0+
- root 权限

### 编译步骤

```bash
# 1. 编译 eBPF 内核代码
cd kernel
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c process_monitor.bpf.c -o process_monitor.bpf.o

# 2. 复制到 agent 目录
cp process_monitor.bpf.o ../agent/

# 3. 编译 agent
cd ../agent
go build -o agent main.go

# 4. 编译 server
cd ../server
go build -o server .
```

### 启动服务

```bash
# 1. 启动 server
cd server
sudo -u ubuntu nohup ./server > server.log 2>&1 &
# 或使用 sudo 运行
sudo nohup ./server > server.log 2>&1 &

# 2. 启动 agent（需要 root 权限）
cd ../agent
sudo nohup ./agent > agent.log 2>&1 &
```

### 验证运行

```bash
# 检查 server
curl http://localhost:8080/api/health

# 检查日志
tail -f server/server.log
tail -f agent/agent.log

# 访问前端
http://localhost:8080/static/dashboard.html
```

## 🔌 API 接口

### 1. 事件提交
```
POST /api/events
Content-Type: application/json

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
  "is_privilege_escalation": true,
  "event_type": 1,
  "old_uid": 1000,
  "new_uid": 0,
  "src_addr": 0,
  "dst_addr": 0,
  "src_port": 0,
  "dst_port": 0,
  "protocol": 0,
  "exit_code": 0
}
```

### 2. 获取事件列表
```
GET /api/events?limit=100&offset=0&risk_level=HIGH&event_type=1&agent_id=default
```

参数说明：
- `limit`: 返回事件数量（默认 100）
- `offset`: 偏移量（默认 0）
- `risk_level`: 风险等级过滤（HIGH/MEDIUM/LOW）
- `event_type`: 事件类型过滤（0-6）
- `agent_id`: Agent ID 过滤

### 3. 获取最近事件
```
GET /api/events/recent/{limit}
```

### 4. 获取高风险事件
```
GET /api/high-risk-events?limit=100
```

### 5. 获取统计信息
```
GET /api/statistics
```

返回示例：
```json
{
  "total_events": 1000,
  "last_24_hours": 500,
  "risk_level_distribution": {
    "HIGH": 50,
    "MEDIUM": 150,
    "LOW": 800
  },
  "event_type_distribution": {
    "EXECVE": 900,
    "SETUID": 50,
    "FILE_WRITE": 20,
    "OPENAT": 15,
    "CONNECT": 10,
    "BIND": 3,
    "EXIT": 2
  }
}
```

### 6. 时间线重建
```
GET /api/timeline/reconstruct?pid=12345&time_window=10
```

参数说明：
- `pid`: 进程 ID
- `time_window`: 时间窗口（分钟，默认 10）

### 7. 提权事件时间线
```
GET /api/timeline/privilege-escalation?event_id=123&time_window=5
```

参数说明：
- `event_id`: 事件 ID
- `time_window`: 时间窗口（分钟，默认 5）

### 8. 健康检查
```
GET /api/health
```

返回示例：
```json
{
  "status": "healthy",
  "clients": 5,
  "events": 1000
}
```

### 9. WebSocket 实时推送
```
ws://localhost:8080/ws
```

连接成功后，服务器会实时推送新事件。

## 🎨 事件类型

| 类型 | 值 | 说明 | 追踪内容 |
|------|-----|------|----------|
| EXECVE | 0 | 进程执行 | 执行文件路径、命令参数 |
| SETUID | 1 | 权限变更 | UID 变更、新旧权限 |
| FILE_WRITE | 2 | 文件写入 | 目标文件路径、写入权限 |
| OPENAT | 3 | 文件打开 | 文件路径、访问模式 |
| CONNECT | 4 | 网络连接 | 目标 IP、端口、协议 |
| BIND | 5 | 端口绑定 | 绑定 IP、端口 |
| EXIT | 6 | 进程退出 | 退出代码 |

## 🧪 测试方法

### 使用测试脚本

项目提供了两个测试脚本：

1. **test_risk_levels.sh** - 测试风险等级功能
```bash
sudo ./test_risk_levels.sh
```

该脚本会自动触发各种风险等级的事件，包括：
- 高风险：sudo 操作、su 切换用户
- 中风险：root 用户执行高风险程序
- 低风险：常规命令执行

2. **test_privilege_escalation.sh** - 测试权限提升检测
```bash
sudo ./test_privilege_escalation.sh
```

### 手动触发不同风险等级事件

**触发高风险事件**

```bash
# 1. sudo 提权操作（评分 27）
sudo -i
sudo su
sudo ls /root
sudo cat /etc/passwd

# 2. su 切换用户（评分 27）
su - root
su ubuntu

# 3. sudo 执行高风险程序（评分 27）
sudo strace ls
sudo ssh -V
sudo crontab -l
```

**触发中风险事件**

```bash
# root 用户直接执行高风险程序（评分 15）
/usr/bin/ssh -V
/usr/bin/strace -h
/usr/bin/crontab -l
/usr/bin/passwd --help

# 注意：这些命令必须以 root 身份直接执行，而不是通过 sudo
```

**触发低风险事件**

```bash
# root 用户执行常规程序（评分 0）
ls -la /tmp
cat /etc/hostname
ps aux
top -b -n 1

# 普通用户执行任何程序（评分 0）
ls
pwd
whoami
```

### 测试时间线重建

```bash
# 1. 执行一系列命令
sudo echo "test1" > /tmp/test1
sleep 2
sudo cat /etc/passwd
sleep 2
sudo ls -la /root
sleep 2
sudo su - root

# 2. 获取事件ID
curl "http://localhost:8080/api/events?limit=1" | grep '"id"'

# 3. 查看时间线（替换 {event_id}）
curl "http://localhost:8080/api/timeline/privilege-escalation?event_id={event_id}&time_window=5"

# 4. 在前端界面点击"📊 查看时间线"按钮
```

### 验证风险等级

```bash
# 1. 查看统计信息
curl -s http://localhost:8080/api/statistics | python3 -m json.tool

# 2. 查看高风险事件
curl -s "http://localhost:8080/api/events?risk_level=HIGH" | python3 -m json.tool

# 3. 查看中风险事件
curl -s "http://localhost:8080/api/events?risk_level=MEDIUM" | python3 -m json.tool

# 4. 查看低风险事件
curl -s "http://localhost:8080/api/events?risk_level=LOW" | python3 -m json.tool
```

## 📊 数据结构

### ProcessEvent（内核事件）
```c
struct process_event {
    __u64 timestamp;           // 时间戳（纳秒）
    __u32 pid;                 // 进程 ID
    __u32 ppid;                // 父进程 ID
    __u32 uid;                 // 用户 ID
    __u32 gid;                 // 组 ID
    __u32 euid;                // 有效用户 ID
    __u32 egid;                // 有效组 ID
    __u32 old_uid;             // 原始 UID
    __u32 new_uid;             // 新 UID
    char comm[16];             // 进程名称
    char filename[256];        // 执行文件路径
    char filepath[256];        // 目标文件路径
    __u8 is_privilege_escalation;  // 权限提升标志
    __u8 event_type;           // 事件类型
    __u8 target_file_type;     // 目标文件类型
    
    // 网络连接相关
    __be32 src_addr;           // 源 IP 地址
    __be32 dst_addr;           // 目标 IP 地址
    __u16 src_port;            // 源端口
    __u16 dst_port;            // 目标端口
    __u8 protocol;             // 协议类型
    __u8 exit_code;            // 退出码
};
```

### ServerEvent（传输格式）
```json
{
  "timestamp": 1678888888000000000,
  "pid": 12345,
  "ppid": 1234,
  "uid": 1000,
  "gid": 1000,
  "euid": 0,
  "egid": 0,
  "old_uid": 1000,
  "new_uid": 0,
  "comm": "sudo",
  "filename": "/usr/bin/sudo",
  "filepath": "",
  "is_privilege_escalation": true,
  "event_type": 1,
  "target_file_type": 0,
  "src_addr": 0,
  "dst_addr": 0,
  "src_port": 0,
  "dst_port": 0,
  "protocol": 0,
  "exit_code": 0
}
```

### ProcessEventWithRisk（数据库事件）
```json
{
  "id": 1,
  "timestamp": 1678888888000000000,
  "pid": 12345,
  "ppid": 1234,
  "uid": 1000,
  "gid": 1000,
  "euid": 0,
  "egid": 0,
  "old_uid": 1000,
  "new_uid": 0,
  "comm": "sudo",
  "filename": "/usr/bin/sudo",
  "filepath": "",
  "is_privilege_escalation": true,
  "event_type": 1,
  "target_file_type": 0,
  "risk_level": "HIGH",
  "agent_id": "default",
  "created_at": "2026-03-20T15:00:00Z",
  "src_addr": 0,
  "dst_addr": 0,
  "src_port": 0,
  "dst_port": 0,
  "protocol": 0,
  "exit_code": 0
}
```

## 🔧 配置选项

### Server 配置
```json
{
  "server": {
    "address": ":8080",
    "read_timeout": 30,
    "write_timeout": 30,
    "idle_timeout": 120
  },
  "storage": {
    "max_events": 10000,
    "enable_persistence": true,
    "database_path": "./security_events.db"
  },
  "websocket": {
    "read_buffer_size": 1024,
    "write_buffer_size": 1024,
    "ping_interval": 30
  },
  "logging": {
    "level": "info",
    "enable_file_log": true,
    "log_file": "./server.log"
  },
  "risk_analysis": {
    "high_risk_threshold": 25,
    "medium_risk_threshold": 12,
    "deduplication_window": 300
  }
}
```

### eBPF 监控配置
- Ring Buffer 大小：256KB
- 文件路径最大长度：256 字符
- 进程名最大长度：16 字符
- 监控对象：root 权限进程或 SUID 程序

## 📈 性能指标

- **事件捕获延迟**：< 1ms
- **CPU 占用**：< 1%
- **内存占用**：< 10MB
- **事件吞吐量**：> 10000 events/s
- **Ring Buffer 大小**：256KB

## 🚨 限制和注意事项

1. **内核版本要求**：Linux 5.8+ (支持 BPF ring buffer)
2. **权限要求**：需要 root 权限运行 agent
3. **LSM 支持**：需要内核启用 LSM 支持
4. **编译器要求**：clang + LLVM
5. **数据库性能**：SQLite 适用于中小规模场景，大规模建议使用 PostgreSQL
6. **风险评分准确性**：评分算法基于启发式规则，可能存在误报或漏报

## 🔒 安全特性

1. **内核层拦截**：使用 LSM 钩子在内核权限验证层拦截，比用户空间监控更可靠
2. **实时检测**：所有检测都在事件发生时实时进行
3. **低性能开销**：使用 eBPF 和 ring buffer，对系统性能影响极小
4. **全面覆盖**：同时监控 tracepoint 和 LSM 钩子，确保不遗漏任何事件
5. **去重机制**：基于事件指纹的去重，避免重复记录
6. **智能风险评级**：多维度评估，自动识别安全威胁等级

## 📁 项目结构

```
ebpf-process-monitor/
├── agent/                    # Go 代理程序
│   ├── main.go              # 主程序
│   ├── process_monitor.bpf.o # eBPF 字节码
│   ├── go.mod               # Go 依赖管理
│   └── agent.log            # 运行日志
├── kernel/                   # eBPF 内核代码
│   ├── process_monitor.bpf.c # eBPF C 源码
│   ├── vmlinux.h            # 内核类型定义
│   └── process_monitor.bpf.o # 编译输出
├── server/                   # 后端服务器
│   ├── main.go              # 主程序
│   ├── database.go          # 数据库操作
│   ├── risk_analyzer.go     # 风险分析器
│   ├── schema.sql           # 数据库结构
│   ├── static/              # 前端静态文件
│   │   ├── dashboard.html   # 可视化仪表板
│   │   └── test.html        # 测试页面
│   ├── security_events.db   # SQLite 数据库
│   └── server.log           # 运行日志
├── docs/                     # 项目文档
├── test_privilege_escalation.sh  # 权限提升测试脚本
├── test_risk_levels.sh      # 风险等级测试脚本
└── README.md                 # 本文档
```

## 🐛 故障排查

### LSM 钩子附加失败
```bash
# 检查内核版本
uname -r

# 检查 LSM 支持
cat /proc/filesystems | grep securityfs

# 检查 BPF LSM
cat /sys/kernel/security/lsm
```

### 事件丢失
```bash
# 检查系统日志
dmesg | grep bpf

# 验证权限
确保以 root 运行 agent

# 增加 ring buffer 大小
修改 kernel/process_monitor.bpf.c 中的 max_entries
```

### 数据库写入失败
```bash
# 检查数据库文件权限
ls -la server/security_events.db

# 删除数据库重新创建
rm server/security_events.db
# 重启 server
```

### Server 启动失败
```bash
# 检查端口占用
netstat -tlnp | grep 8080

# 停止占用进程
sudo killall server

# 检查日志
tail -f server/server.log
```

### 风险等级不正确
```bash
# 1. 检查 agent 日志，查看捕获的事件
tail -f agent/agent.log

# 2. 检查事件详情
curl -s "http://localhost:8080/api/events?limit=1" | python3 -m json.tool

# 3. 验证 UID/EUID 值
# 真正的权限提升：UID != 0, EUID = 0
# root 用户直接执行：UID = 0, EUID = 0

# 4. 检查 comm 值
# sudo/su 命令会被识别为高风险

# 5. 重新编译 server（如果修改了评分规则）
cd server
go build -o server .
pkill server
nohup ./server > server.log 2>&1 &
```

## 🔄 维护和监控

### 日志管理
```bash
# 查看 agent 日志
tail -f agent/agent.log

# 查看 server 日志
tail -f server/server.log

# 日志轮转（建议使用 logrotate）
logrotate -f /etc/logrotate.d/ebpf-monitor
```

### 数据库维护
```bash
# 备份数据库
cp server/security_events.db server/security_events.db.backup

# 清理旧数据（保留最近 30 天）
sqlite3 server/security_events.db "DELETE FROM security_events WHERE created_at < datetime('now', '-30 days');"

# 优化数据库
sqlite3 server/security_events.db "VACUUM;"

# 查看数据库大小
du -sh server/security_events.db

# 查看表结构
sqlite3 server/security_events.db ".schema security_events"
```

### 性能监控
```bash
# 检查 CPU 使用率
top -p $(pgrep agent) -p $(pgrep server)

# 检查内存使用
ps aux | grep -E 'agent|server'

# 检查事件数量
curl -s http://localhost:8080/api/statistics

# 检查 WebSocket 连接数
curl -s http://localhost:8080/api/health
```

### 风险事件监控
```bash
# 实时监控高风险事件
watch -n 5 'curl -s "http://localhost:8080/api/events?risk_level=HIGH&limit=5" | python3 -m json.tool'

# 统计各风险等级事件数
watch -n 5 'curl -s http://localhost:8080/api/statistics | python3 -m json.tool'

# 查看最近的高风险事件
curl -s "http://localhost:8080/api/high-risk-events?limit=10" | python3 -m json.tool
```

## 🤝 贡献指南

1. Fork 项目
2. 创建特性分支：`git checkout -b feature/AmazingFeature`
3. 提交更改：`git commit -m 'Add some AmazingFeature'`
4. 推送到分支：`git push origin feature/AmazingFeature`
5. 创建 Pull Request

## 📄 许可证

本项目采用 GPL 许可证（与 eBPF 内核代码一致）

## 📞 联系和支持

如有问题或建议，请提交 Issue 或 Pull Request。

## 🙏 致谢

- eBPF 社区提供的优秀技术
- cilium/ebpf 库的开发者
- 所有贡献者

---

**版本**: 1.0.0  
**最后更新**: 2026-03-20  
**维护者**: eBPF 监控团队