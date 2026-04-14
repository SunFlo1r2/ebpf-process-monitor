# eBPF 进程监控系统 - 性能验证指南

## 概述

本文档详细说明如何验证 eBPF 进程监控系统的三个关键性能指标：

1. **响应时间** - 系统处理事件的端到端延迟
2. **并发量** - 系统在高并发场景下的处理能力
3. **准确率** - 风险评级和事件检测的准确性

---

## 1. 响应时间验证

### 1.1 测试目标

- API 接口响应时间 < 100ms
- 事件捕获延迟 < 1ms
- 数据库查询响应时间 < 50ms

### 1.2 测试方法

#### 运行响应时间测试脚本

```bash
sudo ./test_response_time.sh
```

该脚本会自动测试：

1. **事件捕获到存储的端到端延迟**
   - 触发一个事件
   - 记录事件发生时间
   - 查询最新事件并计算延迟

2. **数据库查询响应时间**
   - 测试不同查询条件的响应时间
   - 包括空查询、limit 查询、风险等级过滤等

3. **API 并发响应能力**
   - 发送 10 个并发请求
   - 测量平均响应时间

4. **WebSocket 实时推送延迟**
   - 查看当前连接数
   - 验证推送机制

### 1.3 手动验证 API 响应时间

```bash
# 测试各个 API 接口的响应时间
echo "测试 API 响应时间..."

# 健康检查
time curl -s http://localhost:8080/api/health > /dev/null

# 获取统计信息
time curl -s http://localhost:8080/api/statistics > /dev/null

# 获取事件列表
time curl -s "http://localhost:8080/api/events?limit=100" > /dev/null

# 获取高风险事件
time curl -s "http://localhost:8080/api/high-risk-events?limit=100" > /dev/null
```

### 1.4 预期结果

- API 响应时间: < 100ms
- 事件捕获延迟: < 1ms
- 数据库查询: < 50ms

---

## 2. 并发量验证

### 2.1 测试目标

- 事件吞吐量 > 10000 events/s
- API 并发处理能力 > 50 req/s
- WebSocket 连接数 > 10

### 2.2 测试方法

#### 运行并发量测试脚本

```bash
sudo ./test_concurrent_events.sh
```

该脚本会自动测试：

1. **事件捕获吞吐量**
   - 在 10 秒内执行 1000 个命令
   - 计算每秒捕获的事件数

2. **高并发 sudo 提权事件**
   - 快速执行 100 个 sudo 命令
   - 测试高风险事件处理能力

3. **API 并发处理能力**
   - 使用 Apache Bench (ab) 或 curl 进行并发测试
   - 测试 1000 个请求，50 个并发

4. **WebSocket 并发连接**
   - 查看当前连接数
   - 验证连接管理

5. **数据库并发写入性能**
   - 查看数据库大小
   - 查看文件句柄数

### 2.3 手动验证并发性能

#### 使用 Apache Bench 测试

```bash
# 安装 Apache Bench
sudo apt-get install apache2-utils

# 测试 GET /api/statistics 接口
ab -n 1000 -c 50 http://localhost:8080/api/statistics

# 测试 GET /api/events 接口
ab -n 1000 -c 50 "http://localhost:8080/api/events?limit=100"
```

#### 使用 wrk 测试（可选）

```bash
# 安装 wrk
sudo apt-get install wrk

# 测试 API 性能
wrk -t4 -c100 -d30s http://localhost:8080/api/statistics
```

### 2.4 预期结果

- 事件吞吐量: > 10000 events/s
- API 并发处理: > 50 req/s
- CPU 占用: < 5%
- 内存占用: < 50MB

---

## 3. 准确率验证

### 3.1 测试目标

- 风险评级准确率 > 80%
- 事件类型检测准确率 > 90%
- 去重机制准确率 > 95%

### 3.2 测试方法

#### 运行准确率测试脚本

```bash
sudo ./test_accuracy.sh
```

该脚本会自动测试：

1. **高风险事件检测准确性**
   - sudo 提权操作
   - sudo cat /etc/passwd
   - sudo su
   - 执行 SUID 程序 passwd

2. **中风险事件检测准确性**
   - 执行 strace
   - 执行 ssh
   - 执行 crontab
   - sudo ls /tmp

3. **低风险事件检测准确性**
   - 执行 ls
   - cat /etc/hostname
   - ps aux
   - root 用户常规命令

4. **事件类型检测准确性**
   - EXECVE 事件 (type=0)
   - FILE_WRITE 事件 (type=2)

5. **去重机制准确性**
   - 快速执行相同命令
   - 验证去重窗口机制

6. **权限提升检测准确性**
   - 检测 UID 变化
   - 验证 SETUID 事件

### 3.3 手动验证风险评级

```bash
# 触发不同类型的事件
sudo -i -c "echo 'test'"              # 高风险
sudo cat /etc/passwd                  # 高风险
sudo su                               # 高风险
/usr/bin/passwd --help                # 高风险
/usr/bin/strace -h                    # 中风险
/usr/bin/ssh -V                       # 中风险
ls /tmp                               # 低风险
cat /etc/hostname                     # 低风险

# 查看事件和风险等级
curl -s "http://localhost:8080/api/events?limit=20" | python3 -m json.tool

# 查看统计信息
curl -s http://localhost:8080/api/statistics | python3 -m json.tool
```

### 3.4 验证风险评分逻辑

根据 README.md 中的评分规则验证：

#### 高风险事件（≥25分）
1. **sudo ls** - 评分：27
   - comm = "sudo"，直接设为 27 分

2. **su - root** - 评分：27
   - comm = "su"，直接设为 27 分

3. **SETUID 提升到 root** - 评分：25
   - 真正的权限提升 +20
   - SETUID 事件 +5

#### 中风险事件（12-24分）
1. **root 用户执行 ssh** - 评分：15
   - UID=0, EUID=0
   - 高风险程序 +15

2. **root 用户执行 strace** - 评分：15
   - UID=0, EUID=0
   - 高风险程序 +15

#### 低风险事件（<12分）
1. **root 用户执行 ls** - 评分：0
   - UID=0, EUID=0
   - 非高风险程序

2. **普通用户执行 ls** - 评分：0
   - UID=1000, EUID=1000
   - 非高风险程序

### 3.5 预期结果

- 风险评级准确率: > 80%
- 事件类型检测准确率: > 90%
- 去重机制准确率: > 95%

---

## 4. 综合性能测试

### 4.1 运行完整性能测试

```bash
sudo ./test_performance.sh
```

该脚本会自动运行所有测试并生成详细报告：

1. 响应时间测试
2. 并发量测试
3. 准确率测试
4. 系统资源监控
5. 数据库性能
6. WebSocket 性能
7. eBPF 程序性能

### 4.2 查看测试报告

测试报告会保存在 `performance_reports/` 目录下：

```bash
# 查看最新的测试报告
ls -lt performance_reports/ | head -1

# 查看报告内容
cat performance_reports/performance_report_*.txt
```

---

## 5. 性能指标参考

### 5.1 性能指标基准

| 指标 | 目标值 | 实际值 | 状态 |
|------|--------|--------|------|
| API 响应时间 | < 100ms | ? | 待测试 |
| 事件捕获延迟 | < 1ms | ? | 待测试 |
| 数据库查询 | < 50ms | ? | 待测试 |
| 事件吞吐量 | > 10000 events/s | ? | 待测试 |
| API 并发处理 | > 50 req/s | ? | 待测试 |
| 风险评级准确率 | > 80% | ? | 待测试 |
| 事件类型准确率 | > 90% | ? | 待测试 |
| 去重准确率 | > 95% | ? | 待测试 |
| CPU 占用 | < 5% | ? | 待测试 |
| 内存占用 | < 50MB | ? | 待测试 |

### 5.2 性能优化建议

如果性能指标不达标，可以考虑以下优化：

1. **优化数据库查询**
   - 添加适当的索引
   - 使用连接池
   - 考虑迁移到 PostgreSQL

2. **优化事件处理**
   - 增加批量处理
   - 使用异步队列
   - 优化去重算法

3. **优化 eBPF 程序**
   - 减少 map 查找次数
   - 优化事件过滤逻辑
   - 增加 ring buffer 大小

4. **优化 API 性能**
   - 添加缓存
   - 使用 HTTP/2
   - 优化 JSON 序列化

---

## 6. 监控和诊断

### 6.1 实时监控

```bash
# 监控事件统计
watch -n 5 'curl -s http://localhost:8080/api/statistics | python3 -m json.tool'

# 监控高风险事件
watch -n 5 'curl -s "http://localhost:8080/api/high-risk-events?limit=5" | python3 -m json.tool'

# 监控系统资源
top -p $(pgrep agent) -p $(pgrep server)
```

### 6.2 日志分析

```bash
# 查看 agent 日志
tail -f /home/ubuntu/ebpf-process-monitor/agent/agent.log

# 查看 server 日志
tail -f /home/ubuntu/ebpf-process-monitor/server/server.log

# 搜索错误信息
grep -i error /home/ubuntu/ebpf-process-monitor/server/server.log
```

### 6.3 数据库诊断

```bash
# 连接数据库
sqlite3 /home/ubuntu/ebpf-process-monitor/server/security_events.db

# 查看表结构
.schema

# 查看索引信息
.indices

# 查看查询计划
EXPLAIN QUERY PLAN SELECT * FROM security_events WHERE risk_level = 'HIGH' LIMIT 100;

# 查看数据库大小
.databases

# 优化数据库
VACUUM;
ANALYZE;
```

### 6.4 eBPF 程序诊断

```bash
# 查看 eBPF 程序统计
bpftool prog show

# 查看 eBPF Map 统计
bpftool map show

# 查看 map 内容
bpftool map dump name events

# 查看程序运行统计
bpftool prog perf show
```

---

## 7. 故障排查

### 7.1 性能问题排查

如果发现性能问题，按以下步骤排查：

1. **检查系统资源**
   ```bash
   top -p $(pgrep agent) -p $(pgrep server)
   free -h
   df -h
   ```

2. **检查数据库性能**
   ```bash
   sqlite3 security_events.db "EXPLAIN QUERY PLAN SELECT * FROM security_events WHERE risk_level = 'HIGH' LIMIT 100;"
   ```

3. **检查网络连接**
   ```bash
   netstat -tlnp | grep 8080
   lsof -i :8080
   ```

4. **检查 eBPF 程序**
   ```bash
   bpftool prog show
   bpftool map show
   ```

### 7.2 常见问题

#### 问题 1: 事件丢失

**症状**: 触发的命令没有在系统中显示

**可能原因**:
- Agent 未运行
- Ring buffer 已满
- 事件被过滤

**解决方案**:
```bash
# 检查 agent 是否运行
ps aux | grep agent

# 检查 ring buffer 大小
bpftool map show | grep events

# 查看 agent 日志
tail -f agent/agent.log
```

#### 问题 2: 响应时间过长

**症状**: API 响应时间超过 100ms

**可能原因**:
- 数据库查询慢
- 网络延迟
- 系统资源不足

**解决方案**:
```bash
# 优化数据库
sqlite3 security_events.db "VACUUM;"

# 添加索引
sqlite3 security_events.db "CREATE INDEX IF NOT EXISTS idx_timestamp ON security_events(timestamp);"

# 检查网络延迟
ping localhost
```

#### 问题 3: 风险评级不准确

**症状**: 风险等级与预期不符

**可能原因**:
- 评分逻辑错误
- UID/EUID 判断错误
- 事件类型识别错误

**解决方案**:
```bash
# 查看事件详情
curl -s "http://localhost:8080/api/events?limit=1" | python3 -m json.tool

# 检查 UID/EUID 值
# 真正的权限提升：UID != 0, EUID = 0
# root 用户直接执行：UID = 0, EUID = 0

# 重新编译 server（如果修改了评分规则）
cd server
go build -o server .
pkill server
nohup ./server > server.log 2>&1 &
```

---

## 8. 最佳实践

### 8.1 测试环境准备

1. **确保服务正常运行**
   ```bash
   # 检查 server
   curl http://localhost:8080/api/health

   # 检查 agent
   ps aux | grep agent
   ```

2. **清理旧数据**
   ```bash
   # 备份数据库
   cp server/security_events.db server/security_events.db.backup

   # 清理旧数据
   sqlite3 server/security_events.db "DELETE FROM security_events WHERE created_at < datetime('now', '-1 days');"
   ```

3. **监控系统资源**
   ```bash
   # 在另一个终端中运行
   watch -n 2 'top -p $(pgrep agent) -p $(pgrep server)'
   ```

### 8.2 测试执行建议

1. **按顺序执行测试**
   - 先执行响应时间测试
   - 再执行并发量测试
   - 最后执行准确率测试

2. **多次测试取平均值**
   ```bash
   # 运行 3 次测试
   for i in {1..3}; do
       echo "第 $i 次测试"
       sudo ./test_response_time.sh
   done
   ```

3. **记录测试结果**
   - 保存测试报告
   - 记录系统配置
   - 记录测试环境

### 8.3 性能优化建议

1. **定期维护数据库**
   ```bash
   # 每周优化一次数据库
   sqlite3 server/security_events.db "VACUUM; ANALYZE;"
   ```

2. **监控系统资源**
   ```bash
   # 设置监控脚本
   cat > /usr/local/bin/monitor_ebpf.sh << 'EOF'
   #!/bin/bash
   while true; do
       curl -s http://localhost:8080/api/statistics
       sleep 60
   done
   EOF

   chmod +x /usr/local/bin/monitor_ebpf.sh
   ```

3. **设置告警**
   - CPU 使用率 > 80%
   - 内存使用率 > 90%
   - 事件丢失率 > 5%

---

## 9. 总结

本指南提供了完整的性能验证方案，包括：

1. **响应时间验证** - 验证系统处理延迟
2. **并发量验证** - 验证系统处理能力
3. **准确率验证** - 验证检测结果准确性

通过运行测试脚本，可以快速评估系统性能，并根据测试结果进行优化。

### 关键性能指标

- ✅ API 响应时间 < 100ms
- ✅ 事件吞吐量 > 10000 events/s
- ✅ 风险评级准确率 > 80%

### 下一步

1. 运行综合性能测试
2. 分析测试报告
3. 根据结果优化系统
4. 定期执行性能测试

---

**文档版本**: 1.0.0
**最后更新**: 2026-04-13
**维护者**: eBPF 监控团队