package main

import (
    "bytes"
    "context"
    "encoding/binary"
    "encoding/json"
    "errors"
    "fmt"
    "log"
    "net/http"
    "os"
    "os/signal"
    "strconv"
    "strings"
    "syscall"
    "sync"
    "time"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/ringbuf"
    "github.com/cilium/ebpf/rlimit"
)

type ProcessEvent struct {
    Timestamp             uint64
    Pid                   uint32
    Ppid                  uint32
    Uid                   uint32
    Gid                   uint32
    Euid                  uint32
    Egid                  uint32
    OldUid                uint32  // 原始 UID (用于 setuid 事件)
    NewUid                uint32  // 新 UID (用于 setuid 事件)
    Comm                  [16]byte
    Filename              [256]byte  // 执行文件路径 (execve)
    Filepath              [256]byte  // 目标文件路径 (文件操作)
    IsPrivilegeEscalation uint8
    EventType             uint8  // 事件类型
    TargetFileType        uint8  // 目标文件类型
}

// ServerEvent 用于发送到服务器的事件格式
type ServerEvent struct {
    Timestamp             uint64 `json:"timestamp"`
    Pid                   uint32 `json:"pid"`
    Ppid                  uint32 `json:"ppid"`
    Uid                   uint32 `json:"uid"`
    Gid                   uint32 `json:"gid"`
    Euid                  uint32 `json:"euid"`
    Egid                  uint32 `json:"egid"`
    OldUid                uint32 `json:"old_uid"`
    NewUid                uint32 `json:"new_uid"`
    Comm                  string `json:"comm"`
    Filename              string `json:"filename"`
    Filepath              string `json:"filepath"`
    IsPrivilegeEscalation bool   `json:"is_privilege_escalation"`
    EventType             uint8  `json:"event_type"`
    TargetFileType        uint8  `json:"target_file_type"`
}

const serverURL = "http://localhost:8080/api/events"

var httpClient = &http.Client{
    Timeout: 5 * time.Second,
}

var bootTime time.Time

// getBootTime 从 /proc/stat 获取系统启动时间
func getBootTime() (time.Time, error) {
    data, err := os.ReadFile("/proc/stat")
    if err != nil {
        return time.Time{}, err
    }

    lines := bytes.Split(data, []byte{'\n'})
    for _, line := range lines {
        if bytes.HasPrefix(line, []byte("btime")) {
            fields := bytes.Fields(line)
            if len(fields) >= 2 {
                bootSec, err := strconv.ParseInt(string(fields[1]), 10, 64)
                if err != nil {
                    return time.Time{}, err
                }
                return time.Unix(bootSec, 0), nil
            }
        }
    }

    return time.Time{}, fmt.Errorf("btime not found in /proc/stat")
}

// init 初始化系统启动时间
func init() {
    var err error
    bootTime, err = getBootTime()
    if err != nil {
        log.Printf("Warning: Failed to get boot time: %v", err)
        bootTime = time.Unix(0, 0)
    }
}

// formatTimestamp 将自系统启动以来的纳秒时间戳转换为易读的时间格式
func formatTimestamp(timestamp uint64) string {
    // timestamp 是自系统启动以来的纳秒数
    // 将其转换为真实的 Unix 时间戳
    realTime := bootTime.Add(time.Duration(timestamp) * time.Nanosecond)
    return realTime.Format("2006-01-02 15:04:05.000")
}

// sendEventToServer 将事件发送到服务器
func sendEventToServer(event *ProcessEvent) {
    // 将 boot time 转换为真实的 Unix 时间戳（纳秒）
    realTime := bootTime.Add(time.Duration(event.Timestamp) * time.Nanosecond)
    unixTimestampNs := uint64(realTime.UnixNano())

    serverEvent := ServerEvent{
        Timestamp:             unixTimestampNs,
        Pid:                   event.Pid,
        Ppid:                  event.Ppid,
        Uid:                   event.Uid,
        Gid:                   event.Gid,
        Euid:                  event.Euid,
        Egid:                  event.Egid,
        OldUid:                event.OldUid,
        NewUid:                event.NewUid,
        Comm:                  string(bytes.Trim(event.Comm[:], "\x00")),
        Filename:              string(bytes.Trim(event.Filename[:], "\x00")),
        Filepath:              string(bytes.Trim(event.Filepath[:], "\x00")),
        IsPrivilegeEscalation: event.IsPrivilegeEscalation == 1,
        EventType:             event.EventType,
        TargetFileType:        event.TargetFileType,
    }

    jsonData, err := json.Marshal(serverEvent)
    if err != nil {
        log.Printf("Failed to marshal event: %v", err)
        return
    }

    resp, err := httpClient.Post(serverURL, "application/json", bytes.NewBuffer(jsonData))
    if err != nil {
        log.Printf("Failed to send event to server: %v", err)
        return
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        log.Printf("Server returned status: %d", resp.StatusCode)
    }
}

func main() {
    if err := rlimit.RemoveMemlock(); err != nil {
        log.Fatal("Failed to remove memlock:", err)
    }

    // 加载 eBPF 程序
    spec, err := ebpf.LoadCollectionSpec("../kernel/process_monitor.bpf.o")
    if err != nil {
        log.Fatal("Failed to load eBPF spec:", err)
    }

    // 修复：旧版本 NewCollection 只需要一个参数
    coll, err := ebpf.NewCollection(spec)
    if err != nil {
        log.Fatalf("Failed to create collection: %v", err)
    }
    defer coll.Close()

    // 获取 eBPF 程序
    progExecve := coll.Programs["trace_execve"]
    if progExecve == nil {
        log.Fatal("Program trace_execve not found in collection")
    }

    progSetuid := coll.Programs["trace_setuid"]
    if progSetuid == nil {
        log.Fatal("Program trace_setuid not found in collection")
    }

    // 获取 LSM 钩子程序
    progTaskFixSetuid := coll.Programs["handle_task_fix_setuid"]
    if progTaskFixSetuid == nil {
        log.Fatal("Program handle_task_fix_setuid not found in collection")
    }

    progFilePermission := coll.Programs["handle_file_permission"]
    if progFilePermission == nil {
        log.Fatal("Program handle_file_permission not found in collection")
    }

    // 暂时禁用 openat 监控（存在权限问题）
    /*
    progOpenat := coll.Programs["trace_openat"]
    if progOpenat == nil {
        log.Fatal("Program trace_openat not found in collection")
    }
    */

    // 获取 events map
    eventsMap := coll.Maps["events"]
    if eventsMap == nil {
        log.Fatal("Map events not found in collection")
    }

    // 附加到 execve tracepoint
    tpExecve, err := link.Tracepoint("syscalls", "sys_enter_execve", progExecve, nil)
    if err != nil {
        log.Fatalf("Failed to attach tracepoint: %v", err)
    }
    defer tpExecve.Close()

    // 附加到 setuid tracepoint
    tpSetuid, err := link.Tracepoint("syscalls", "sys_enter_setuid", progSetuid, nil)
    if err != nil {
        log.Printf("Warning: Failed to attach setuid tracepoint: %v", err)
    } else {
        defer tpSetuid.Close()
    }

    // 附加到 LSM 钩子：task_fix_setuid
    linkTaskFixSetuid, err := link.AttachLSM(link.LSMOptions{
        Program: progTaskFixSetuid,
    })
    if err != nil {
        log.Printf("Warning: Failed to attach task_fix_setuid LSM hook: %v", err)
    } else {
        defer linkTaskFixSetuid.Close()
        log.Println("Successfully attached to task_fix_setuid LSM hook")
    }

    // 附加到 LSM 钩子：file_permission
    linkFilePermission, err := link.AttachLSM(link.LSMOptions{
        Program: progFilePermission,
    })
    if err != nil {
        log.Printf("Warning: Failed to attach file_permission LSM hook: %v", err)
    } else {
        defer linkFilePermission.Close()
        log.Println("Successfully attached to file_permission LSM hook")
    }

    // 附加到 openat tracepoint（暂时禁用，因为存在权限问题）
    /*
    tpOpenat, err := link.Tracepoint("syscalls", "sys_enter_openat", progOpenat, nil)
    if err != nil {
        log.Printf("Warning: Failed to attach openat tracepoint: %v", err)
    } else {
        defer tpOpenat.Close()
    }
    */

    log.Println("Successfully attached to tracepoints and LSM hooks")

    // 创建 ring buffer 读取器
    reader, err := ringbuf.NewReader(eventsMap)
    if err != nil {
        log.Fatal("Failed to create ringbuf reader:", err)
    }

    log.Println("Successfully started eBPF process monitor")

    ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
    defer cancel()

    var closeOnce sync.Once
    exitChan := make(chan struct{})

    doClose := func() {
        closeOnce.Do(func() {
            log.Println("Closing ring buffer...")
            reader.Close()
            close(exitChan)
        })
    }

    go func() {
        <-ctx.Done()
        log.Println("Received signal, exiting...")
        doClose()
    }()

    for {
        select {
        case <-exitChan:
            log.Println("Exiting read loop")
            return
        default:
        }

        record, err := reader.Read()
        if err != nil {
            if errors.Is(err, ringbuf.ErrClosed) {
                log.Println("Ring buffer closed, exiting")
                return
            }
            
            errStr := err.Error()
            if strings.Contains(errStr, "file already closed") ||
               strings.Contains(errStr, "epoll wait") ||
               strings.Contains(errStr, "bad file descriptor") {
                log.Println("Ring buffer closing, exiting")
                return
            }
            
            log.Printf("Reading from ring buffer: %v", err)
            continue
        }

        var event ProcessEvent
        if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
            log.Printf("Parsing event: %v", err)
            continue
        }

        // 发送事件到服务器
        go sendEventToServer(&event)

        privilegeStr := ""
        if event.IsPrivilegeEscalation == 1 {
            privilegeStr = " [PRIVILEGE ESCALATION]"
        }

        // 根据事件类型显示不同的信息
        var eventDesc string
        switch event.EventType {
        case 0: // EVENT_EXECVE
            eventDesc = fmt.Sprintf("EXECVE: %s", string(bytes.Trim(event.Filename[:], "\x00")))
        case 1: // EVENT_SETUID
            filename := string(bytes.Trim(event.Filename[:], "\x00"))
            if len(filename) > 0 {
                eventDesc = fmt.Sprintf("SETUID: %d -> %d | %s", event.OldUid, event.NewUid, filename)
            } else {
                eventDesc = fmt.Sprintf("SETUID: %d -> %d", event.OldUid, event.NewUid)
            }
        case 2: // EVENT_FILE_WRITE
            targetFile := string(bytes.Trim(event.Filepath[:], "\x00"))
            eventDesc = fmt.Sprintf("FILE_WRITE: %s", targetFile)
        default:
            eventDesc = "UNKNOWN"
        }

        fmt.Printf("[%s] PID:%d PPID:%d UID:%d EUID:%d Comm:%s %s%s\n",
            formatTimestamp(event.Timestamp),
            event.Pid,
            event.Ppid,
            event.Uid,
            event.Euid,
            string(bytes.Trim(event.Comm[:], "\x00")),
            eventDesc,
            privilegeStr)
    }
}
