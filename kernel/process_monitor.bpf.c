#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256
#define MAX_PATH_LEN 256

// 事件类型
enum event_type {
    EVENT_EXECVE = 0,           // execve 系统调用
    EVENT_SETUID = 1,           // setuid 权限变更
    EVENT_FILE_WRITE = 2,       // 文件写入操作
    EVENT_OPENAT = 3,           // openat 文件打开操作
    EVENT_CONNECT = 4,          // connect 网络连接
    EVENT_BIND = 5,             // bind 端口绑定
    EVENT_EXIT = 6,             // 进程退出
};

// 目标文件类型
enum target_file_type {
    FILE_NONE = 0,
    FILE_PASSWD = 1,            // /etc/passwd
    FILE_SHADOW = 2,            // /etc/shadow
    FILE_SUDOERS = 3,           // /etc/sudoers
    FILE_CRONTAB = 4,           // /etc/crontab 或 /var/spool/cron/
    FILE_SSH_CONFIG = 5,        // SSH 配置文件
    FILE_HOSTS = 6,             // /etc/hosts
    FILE_SYSTEM_CONFIG = 7,     // 系统配置文件
    FILE_OTHER = 8,
};

struct process_event {
    __u64 timestamp;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u32 euid;
    __u32 egid;
    __u32 old_uid;              // 原始 UID (用于 setuid 事件)
    __u32 new_uid;              // 新 UID (用于 setuid 事件)
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];    // 执行文件路径 (execve)
    char filepath[MAX_PATH_LEN];        // 目标文件路径 (文件操作)
    __u8 is_privilege_escalation;
    __u8 event_type;            // 事件类型
    __u8 target_file_type;      // 目标文件类型
    
    // 网络连接相关字段
    __be32 src_addr;            // 源IP地址
    __be32 dst_addr;            // 目标IP地址
    __u16 src_port;             // 源端口
    __u16 dst_port;             // 目标端口
    __u8 protocol;              // 协议类型 (TCP=6, UDP=17)
    __u8 exit_code;             // 退出码 (用于EVENT_EXIT)
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// 安全获取父进程 PID
static __inline __u32 get_ppid() {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;
    
    // 使用 bpf_probe_read_kernel 安全读取
    if (bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent) != 0) {
        return 0;
    }
    
    __u32 ppid;
    if (bpf_probe_read_kernel(&ppid, sizeof(ppid), &parent->tgid) != 0) {
        return 0;
    }
    
    return ppid;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    struct process_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = uid_gid & 0xFFFFFFFF;
    __u32 gid = uid_gid >> 32;
    
    // 获取当前任务
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    // 直接读取 euid 和 egid
    __u32 euid = 0, egid = 0;
    struct cred *cred;
    
    // 读取 cred 指针
    if (bpf_probe_read_kernel(&cred, sizeof(cred), &task->cred) != 0) {
        return 0;
    }
    
    // 直接读取 euid 和 egid
    bpf_probe_read_kernel(&euid, sizeof(euid), &cred->euid.val);
    bpf_probe_read_kernel(&egid, sizeof(egid), &cred->egid.val);
    
    // 读取文件名
    const char *filename_ptr = (const char *)ctx->args[0];
    char filename[MAX_FILENAME_LEN] = {0};
    if (filename_ptr) {
        bpf_probe_read_user_str(filename, sizeof(filename), 
                               (void *)filename_ptr);
    } else {
        __builtin_memcpy(filename, "unknown", 8);
    }
    
    // 修改：检测所有 setuid 程序或以 root 权限执行的程序
    // 条件1: euid != uid 表示有 setuid/setgid 位
    // 条件2: euid == 0 表示以 root 权限执行
    __u8 is_setuid_program = (euid != uid) ? 1 : 0;
    __u8 is_root_program = (euid == 0) ? 1 : 0;
    __u8 is_priv_escalation = is_setuid_program || is_root_program;
    
    // 记录所有 setuid 程序或以 root 权限执行的程序
    if (!is_priv_escalation) {
        return 0;
    }
    
    event = bpf_ringbuf_reserve(&events, sizeof(struct process_event), 0);
    if (!event) {
        return 0;
    }
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->ppid = get_ppid();
    event->uid = uid;
    event->gid = gid;
    event->euid = euid;
    event->egid = egid;
    event->old_uid = uid;
    event->new_uid = euid;
    event->is_privilege_escalation = is_priv_escalation;
    event->event_type = EVENT_EXECVE;
    event->target_file_type = FILE_NONE;
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    __builtin_memcpy(event->filename, filename, sizeof(event->filename));
    __builtin_memset(event->filepath, 0, sizeof(event->filepath));
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Tracepoint：监控 setuid 系统调用
SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_setuid(struct trace_event_raw_sys_enter *ctx)
{
    struct process_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = uid_gid & 0xFFFFFFFF;
    
    // 获取当前任务
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    
    // 直接读取当前 euid
    __u32 current_euid = 0;
    struct cred *cred;
    
    if (bpf_probe_read_kernel(&cred, sizeof(cred), &current_task->cred) != 0) {
        return 0;
    }
    
    bpf_probe_read_kernel(&current_euid, sizeof(current_euid), &cred->euid.val);
    
    // 获取新的 UID（第一个参数）
    __u32 new_uid = ctx->args[0];
    
    // 只记录从普通用户提升到 root 的情况
    if (current_euid != 0 && new_uid == 0) {
        event = bpf_ringbuf_reserve(&events, sizeof(struct process_event), 0);
        if (!event) {
            return 0;
        }
        
        event->timestamp = bpf_ktime_get_ns();
        event->pid = pid;
        event->ppid = get_ppid();
        event->uid = uid;
        event->gid = uid_gid >> 32;
        event->euid = current_euid;
        event->egid = 0;
        event->old_uid = current_euid;
        event->new_uid = new_uid;
        event->is_privilege_escalation = 1;
        event->event_type = EVENT_SETUID;
        event->target_file_type = FILE_NONE;
        
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        __builtin_memset(event->filename, 0, sizeof(event->filename));
        __builtin_memset(event->filepath, 0, sizeof(event->filepath));
        
        bpf_ringbuf_submit(event, 0);
    }
    
    return 0;
}

// LSM 钩子：监控 task_fix_setuid
SEC("lsm/task_fix_setuid")
int BPF_PROG(handle_task_fix_setuid, struct task_struct *task, struct cred *new, struct cred *old)
{
    if (!old || !new || !task) {
        return 0;
    }
    
    // 读取旧的 UID
    __u32 old_uid = 0, old_euid = 0;
    bpf_probe_read_kernel(&old_uid, sizeof(old_uid), &old->uid.val);
    bpf_probe_read_kernel(&old_euid, sizeof(old_euid), &old->euid.val);
    
    // 读取新的 UID
    __u32 new_uid = 0, new_euid = 0;
    bpf_probe_read_kernel(&new_uid, sizeof(new_uid), &new->uid.val);
    bpf_probe_read_kernel(&new_euid, sizeof(new_euid), &new->euid.val);
    
    // 检测从非 root 提升到 root 的情况
    if ((old_uid != 0 || old_euid != 0) && (new_uid == 0 || new_euid == 0)) {
        struct process_event *event;
        __u32 pid;
        
        // 从 task 参数读取 PID
        if (bpf_probe_read_kernel(&pid, sizeof(pid), &task->tgid) != 0) {
            return 0;
        }
        
        event = bpf_ringbuf_reserve(&events, sizeof(struct process_event), 0);
        if (!event) {
            return 0;
        }
        
        event->timestamp = bpf_ktime_get_ns();
        event->pid = pid;
        event->ppid = 0;  // 需要从 task->real_parent 获取
        event->uid = old_uid;
        event->gid = 0;
        event->euid = new_euid;
        event->egid = 0;
        event->old_uid = old_euid;
        event->new_uid = new_euid;
        event->is_privilege_escalation = 1;
        event->event_type = EVENT_SETUID;
        event->target_file_type = FILE_NONE;
        
        // 从 task 参数读取进程名称
        if (bpf_probe_read_kernel(&event->comm, sizeof(event->comm), &task->comm) != 0) {
            __builtin_memset(event->comm, 0, sizeof(event->comm));
        }
        
        // 尝试读取完整的可执行文件路径
        struct mm_struct *mm;
        struct file *exe_file;
        struct path exe_path;
        struct dentry *dentry;
        const unsigned char *d_name;
        
        __builtin_memset(event->filename, 0, sizeof(event->filename));
        
        if (bpf_probe_read_kernel(&mm, sizeof(mm), &task->mm) == 0 && mm != NULL) {
            if (bpf_probe_read_kernel(&exe_file, sizeof(exe_file), &mm->exe_file) == 0 && exe_file != NULL) {
                if (bpf_probe_read_kernel(&exe_path, sizeof(exe_path), &exe_file->f_path) == 0) {
                    dentry = exe_path.dentry;
                    
                    if (dentry != NULL) {
                        d_name = NULL;
                        if (bpf_probe_read_kernel(&d_name, sizeof(d_name), &dentry->d_name.name) == 0 && d_name != NULL) {
                            bpf_probe_read_kernel_str(event->filename, sizeof(event->filename), d_name);
                        }
                    }
                }
            }
        }
        
        __builtin_memset(event->filepath, 0, sizeof(event->filepath));
        
        bpf_ringbuf_submit(event, 0);
    }
    
    return 0;
}

// LSM 钩子：监控文件写入操作 - 简化版本
SEC("lsm/file_permission")
int BPF_PROG(handle_file_permission, struct file *file, int mask)
{
    // 只检查写入操作 (MAY_WRITE = 2)
    if (!(mask & 2)) {
        return 0;
    }
    
    if (!file) {
        return 0;
    }
    
    // 简化：暂时禁用文件监控，专注于权限提升检测
    return 0;
}

// Tracepoint：监控 openat 系统调用（用于追踪文件访问）
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct process_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = uid_gid & 0xFFFFFFFF;
    __u32 gid = uid_gid >> 32;
    
    // 获取当前任务和权限
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct cred *cred;
    __u32 euid = 0;
    
    if (bpf_probe_read_kernel(&cred, sizeof(cred), &task->cred) != 0) {
        return 0;
    }
    
    bpf_probe_read_kernel(&euid, sizeof(euid), &cred->euid.val);
    
    // 读取文件路径
    const char *filename_ptr = (const char *)ctx->args[1];
    char filename[MAX_PATH_LEN] = {0};
    if (filename_ptr) {
        bpf_probe_read_user_str(filename, sizeof(filename), filename_ptr);
    }
    
    // 检测敏感文件类型
    __u8 target_file_type = FILE_NONE;
    __u8 is_sensitive_file = 0;
    
    // 检查 /etc/passwd
    if (filename[0] == '/' && filename[1] == 'e' && filename[2] == 't' &&
        filename[3] == 'c' && filename[4] == '/' && filename[5] == 'p' &&
        filename[6] == 'a' && filename[7] == 's' && filename[8] == 's' &&
        filename[9] == 'w' && filename[10] == 'd') {
        target_file_type = FILE_PASSWD;
        is_sensitive_file = 1;
    }
    // 检查 /etc/shadow
    else if (filename[0] == '/' && filename[1] == 'e' && filename[2] == 't' &&
        filename[3] == 'c' && filename[4] == '/' && filename[5] == 's' &&
        filename[6] == 'h' && filename[7] == 'a' && filename[8] == 'd' &&
        filename[9] == 'o' && filename[10] == 'w') {
        target_file_type = FILE_SHADOW;
        is_sensitive_file = 1;
    }
    // 检查 /etc/sudoers
    else if (filename[0] == '/' && filename[1] == 'e' && filename[2] == 't' &&
        filename[3] == 'c' && filename[4] == '/' && filename[5] == 's' &&
        filename[6] == 'u' && filename[7] == 'd' && filename[8] == 'o' &&
        filename[9] == 'e' && filename[10] == 'r' && filename[11] == 's') {
        target_file_type = FILE_SUDOERS;
        is_sensitive_file = 1;
    }
    // 检查 /etc/crontab 或 /var/spool/cron/
    else if ((filename[0] == '/' && filename[1] == 'e' && filename[2] == 't' &&
        filename[3] == 'c' && filename[4] == '/' && filename[5] == 'c' &&
        filename[6] == 'r' && filename[7] == 'o' && filename[8] == 'n' &&
        filename[9] == 't' && filename[10] == 'a' && filename[11] == 'b') ||
        (filename[0] == '/' && filename[1] == 'v' && filename[2] == 'a' &&
        filename[3] == 'r' && filename[4] == '/' && filename[5] == 's' &&
        filename[6] == 'p' && filename[7] == 'o' && filename[8] == 'o' &&
        filename[9] == 'l' && filename[10] == '/' && filename[11] == 'c' &&
        filename[12] == 'r' && filename[13] == 'o' && filename[14] == 'n')) {
        target_file_type = FILE_CRONTAB;
        is_sensitive_file = 1;
    }
    // 检查 SSH 配置文件
    else if ((filename[0] == '/' && filename[1] == 'e' && filename[2] == 't' &&
        filename[3] == 'c' && filename[4] == '/' && filename[5] == 's' &&
        filename[6] == 's' && filename[7] == 'h' && filename[8] == '/') ||
        (filename[0] == '~' && filename[1] == '/' && filename[2] == '.' &&
        filename[3] == 's' && filename[4] == 's' && filename[5] == 'h' && filename[6] == '/')) {
        target_file_type = FILE_SSH_CONFIG;
        is_sensitive_file = 1;
    }
    // 检查 /etc/hosts
    else if (filename[0] == '/' && filename[1] == 'e' && filename[2] == 't' &&
        filename[3] == 'c' && filename[4] == '/' && filename[5] == 'h' &&
        filename[6] == 'o' && filename[7] == 's' && filename[8] == 't' &&
        filename[9] == 's') {
        target_file_type = FILE_HOSTS;
        is_sensitive_file = 1;
    }
    // 检查其他系统配置文件
    else if (filename[0] == '/' && filename[1] == 'e' && filename[2] == 't' &&
        filename[3] == 'c' && filename[4] == '/') {
        // 检查常见的系统配置文件
        __u8 i;
        for (i = 5; i < MAX_PATH_LEN - 1; i++) {
            if (filename[i] == '\0' || filename[i] == '/') {
                break;
            }
        }
        target_file_type = FILE_SYSTEM_CONFIG;
        is_sensitive_file = 1;
    }
    
    // 只追踪以下情况的文件访问：
    // 1. 敏感文件访问
    // 2. root权限进程或SUID进程
    if (!is_sensitive_file && (euid != 0 && euid == uid)) {
        return 0;
    }
    
    event = bpf_ringbuf_reserve(&events, sizeof(struct process_event), 0);
    if (!event) {
        return 0;
    }
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->ppid = get_ppid();
    event->uid = uid;
    event->gid = gid;
    event->euid = euid;
    event->egid = 0;
    event->old_uid = uid;
    event->new_uid = euid;
    event->is_privilege_escalation = (euid != uid) ? 1 : 0;
    event->event_type = EVENT_OPENAT;
    event->target_file_type = target_file_type;
    
    // 网络相关字段初始化
    event->src_addr = 0;
    event->dst_addr = 0;
    event->src_port = 0;
    event->dst_port = 0;
    event->protocol = 0;
    event->exit_code = 0;
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    __builtin_memcpy(event->filepath, filename, sizeof(event->filepath));
    __builtin_memset(event->filename, 0, sizeof(event->filename));
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Tracepoint：监控 connect 系统调用（用于追踪网络连接）
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct process_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = uid_gid & 0xFFFFFFFF;
    __u32 gid = uid_gid >> 32;
    
    // 获取当前任务和权限
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct cred *cred;
    __u32 euid = 0;
    
    if (bpf_probe_read_kernel(&cred, sizeof(cred), &task->cred) != 0) {
        return 0;
    }
    
    bpf_probe_read_kernel(&euid, sizeof(euid), &cred->euid.val);
    
    // 获取进程名称
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // 检测反向Shell：shell进程建立出站连接
    // bash, sh, zsh, dash等shell进程发起TCP连接可能是反向shell
    __u8 is_reverse_shell = 0;
    if ((comm[0] == 'b' && comm[1] == 'a' && comm[2] == 's' && comm[3] == 'h') ||
        (comm[0] == 's' && comm[1] == 'h' && comm[2] == '\0') ||
        (comm[0] == 'z' && comm[1] == 's' && comm[2] == 'h') ||
        (comm[0] == 'd' && comm[1] == 'a' && comm[2] == 's' && comm[3] == 'h')) {
        is_reverse_shell = 1;
    }
    
    // 检测可疑工具：nc, netcat, socat, telnet等工具的连接
    __u8 is_suspicious_tool = 0;
    if ((comm[0] == 'n' && comm[1] == 'c' && comm[2] == '\0') ||
        (comm[0] == 'n' && comm[1] == 'e' && comm[2] == 't' && comm[3] == 'c' && comm[4] == 'a' && comm[5] == 't') ||
        (comm[0] == 's' && comm[1] == 'o' && comm[2] == 'c' && comm[3] == 'a' && comm[4] == 't') ||
        (comm[0] == 't' && comm[1] == 'e' && comm[2] == 'l' && comm[3] == 'n' && comm[4] == 'e' && comm[5] == 't')) {
        is_suspicious_tool = 1;
    }
    
    // 只追踪以下情况的网络连接：
    // 1. 反向shell检测
    // 2. 可疑工具检测
    // 3. root权限进程或SUID进程
    if (!is_reverse_shell && !is_suspicious_tool && (euid != 0 && euid == uid)) {
        return 0;
    }
    
    event = bpf_ringbuf_reserve(&events, sizeof(struct process_event), 0);
    if (!event) {
        return 0;
    }
    
    // 读取socket地址
    struct sockaddr_in *addr_in = (struct sockaddr_in *)ctx->args[1];
    __be32 dst_addr = 0;
    __u16 dst_port = 0;
    
    if (addr_in) {
        bpf_probe_read_kernel(&dst_addr, sizeof(dst_addr), &addr_in->sin_addr.s_addr);
        bpf_probe_read_kernel(&dst_port, sizeof(dst_port), &addr_in->sin_port);
    }
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->ppid = get_ppid();
    event->uid = uid;
    event->gid = gid;
    event->euid = euid;
    event->egid = 0;
    event->old_uid = uid;
    event->new_uid = euid;
    event->is_privilege_escalation = (euid != uid) ? 1 : 0;
    event->event_type = EVENT_CONNECT;
    event->target_file_type = FILE_NONE;
    
    // 网络连接信息
    event->src_addr = 0;
    event->dst_addr = dst_addr;
    event->src_port = 0;
    event->dst_port = dst_port;
    event->protocol = 6; // TCP
    event->exit_code = 0;
    
    __builtin_memcpy(event->comm, comm, sizeof(event->comm));
    __builtin_memset(event->filename, 0, sizeof(event->filename));
    __builtin_memset(event->filepath, 0, sizeof(event->filepath));
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Tracepoint：监控 bind 系统调用（用于追踪端口绑定）
SEC("tracepoint/syscalls/sys_enter_bind")
int trace_bind(struct trace_event_raw_sys_enter *ctx)
{
    struct process_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = uid_gid & 0xFFFFFFFF;
    __u32 gid = uid_gid >> 32;
    
    // 只追踪root权限进程或SUID进程
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct cred *cred;
    __u32 euid = 0;
    
    if (bpf_probe_read_kernel(&cred, sizeof(cred), &task->cred) != 0) {
        return 0;
    }
    
    bpf_probe_read_kernel(&euid, sizeof(euid), &cred->euid.val);
    
    // 只追踪root进程或权限提升的进程
    if (euid != 0 && euid == uid) {
        return 0;
    }
    
    event = bpf_ringbuf_reserve(&events, sizeof(struct process_event), 0);
    if (!event) {
        return 0;
    }
    
    // 读取socket地址
    struct sockaddr_in *addr_in = (struct sockaddr_in *)ctx->args[1];
    __be32 src_addr = 0;
    __u16 src_port = 0;
    
    if (addr_in) {
        bpf_probe_read_kernel(&src_addr, sizeof(src_addr), &addr_in->sin_addr.s_addr);
        bpf_probe_read_kernel(&src_port, sizeof(src_port), &addr_in->sin_port);
    }
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->ppid = get_ppid();
    event->uid = uid;
    event->gid = gid;
    event->euid = euid;
    event->egid = 0;
    event->old_uid = uid;
    event->new_uid = euid;
    event->is_privilege_escalation = (euid != uid) ? 1 : 0;
    event->event_type = EVENT_BIND;
    event->target_file_type = FILE_NONE;
    
    // 网络连接信息
    event->src_addr = src_addr;
    event->dst_addr = 0;
    event->src_port = src_port;
    event->dst_port = 0;
    event->protocol = 6; // TCP
    event->exit_code = 0;
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    __builtin_memset(event->filename, 0, sizeof(event->filename));
    __builtin_memset(event->filepath, 0, sizeof(event->filepath));
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Tracepoint：监控 exit 系统调用（用于追踪进程退出）
SEC("tracepoint/syscalls/sys_exit_exit")
int trace_exit(struct trace_event_raw_sys_exit *ctx)
{
    struct process_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = uid_gid & 0xFFFFFFFF;
    __u32 gid = uid_gid >> 32;
    
    // 只追踪root权限进程或SUID进程
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct cred *cred;
    __u32 euid = 0;
    
    if (bpf_probe_read_kernel(&cred, sizeof(cred), &task->cred) != 0) {
        return 0;
    }
    
    bpf_probe_read_kernel(&euid, sizeof(euid), &cred->euid.val);
    
    // 只追踪root进程或权限提升的进程
    if (euid != 0 && euid == uid) {
        return 0;
    }
    
    event = bpf_ringbuf_reserve(&events, sizeof(struct process_event), 0);
    if (!event) {
        return 0;
    }
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->ppid = get_ppid();
    event->uid = uid;
    event->gid = gid;
    event->euid = euid;
    event->egid = 0;
    event->old_uid = uid;
    event->new_uid = euid;
    event->is_privilege_escalation = (euid != uid) ? 1 : 0;
    event->event_type = EVENT_EXIT;
    event->target_file_type = FILE_NONE;
    event->exit_code = ctx->ret; // 退出码
    
    // 网络相关字段初始化
    event->src_addr = 0;
    event->dst_addr = 0;
    event->src_port = 0;
    event->dst_port = 0;
    event->protocol = 0;
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    __builtin_memset(event->filename, 0, sizeof(event->filename));
    __builtin_memset(event->filepath, 0, sizeof(event->filepath));
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
