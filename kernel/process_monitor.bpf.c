#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256

struct process_event {
    __u64 timestamp;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u32 euid;
    __u32 egid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    __u8 is_privilege_escalation;
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
    
    // 安全读取 cred
    struct cred *cred;
    if (bpf_probe_read_kernel(&cred, sizeof(cred), &task->cred) != 0) {
        return 0;  // 无法读取 cred，跳过
    }
    
    if (!cred) {
        return 0;  // cred 为 NULL，跳过
    }
    
    // 安全读取 euid 和 egid
    __u32 euid = 0, egid = 0;
    bpf_probe_read_kernel(&euid, sizeof(euid), &cred->euid.val);
    bpf_probe_read_kernel(&egid, sizeof(egid), &cred->egid.val);
    
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
    event->is_privilege_escalation = (euid != uid) ? 1 : 0;
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    // 读取文件名
    const char *filename_ptr = (const char *)ctx->args[0];
    if (filename_ptr) {
        bpf_probe_read_user_str(&event->filename, sizeof(event->filename), 
                               (void *)filename_ptr);
    } else {
        __builtin_memcpy(event->filename, "unknown", 8);
    }
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
