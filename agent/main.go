package main

import (
    "bytes"
    "context"
    "encoding/binary"
    "errors"
    "fmt"
    "log"
    "os"
    "os/signal"
    "strings"
    "syscall"
    "sync"

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
    Comm                  [16]byte
    Filename              [256]byte
    IsPrivilegeEscalation uint8
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
    prog := coll.Programs["trace_execve"]
    if prog == nil {
        log.Fatal("Program trace_execve not found in collection")
    }

    // 获取 events map
    eventsMap := coll.Maps["events"]
    if eventsMap == nil {
        log.Fatal("Map events not found in collection")
    }

    // 关键：附加到 tracepoint
    tp, err := link.Tracepoint("syscalls", "sys_enter_execve", prog, nil)
    if err != nil {
        log.Fatalf("Failed to attach tracepoint: %v", err)
    }
    defer tp.Close()

    log.Println("Successfully attached to tracepoint sys_enter_execve")

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

        privilegeStr := ""
        if event.IsPrivilegeEscalation == 1 {
            privilegeStr = " [PRIVILEGE ESCALATION]"
        }

        fmt.Printf("[%d] PID:%d PPID:%d UID:%d->%d Comm:%s File:%s%s\n",
            event.Timestamp/1000000000,
            event.Pid,
            event.Ppid,
            event.Uid,
            event.Euid,
            string(bytes.Trim(event.Comm[:], "\x00")),
            string(bytes.Trim(event.Filename[:], "\x00")),
            privilegeStr)
    }
}
