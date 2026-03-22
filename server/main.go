package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

// ProcessEvent 表示一个进程执行事件
type ProcessEvent struct {
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
    
    // 网络连接相关字段
    SrcAddr               uint32 `json:"src_addr"`
    DstAddr               uint32 `json:"dst_addr"`
    SrcPort               uint16 `json:"src_port"`
    DstPort               uint16 `json:"dst_port"`
    Protocol              uint8  `json:"protocol"`
    ExitCode              uint8  `json:"exit_code"`
}
// EventStore 存储进程事件
type EventStore struct {
	mu     sync.RWMutex
	events []ProcessEvent
	limit  int // 最大存储事件数量
}

// Server 表示 HTTP 服务器
type Server struct {
	store                 *EventStore
	clients               map[*websocket.Conn]bool
	clientsMutex          sync.RWMutex
	upgrader              websocket.Upgrader
	broadcastChan         chan ProcessEvent
	db                    *Database
	riskAnalyzer          *RiskAnalyzer
	deduplicator          *EventDeduplicator
	forensicReportGenerator *ForensicReportGenerator
}

// NewEventStore 创建新的事件存储
func NewEventStore(limit int) *EventStore {
	return &EventStore{
		events: make([]ProcessEvent, 0, limit),
		limit:  limit,
	}
}

// AddEvent 添加事件到存储
func (s *EventStore) AddEvent(event ProcessEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.events = append(s.events, event)
	// 限制存储数量，超过时删除最旧的事件
	if len(s.events) > s.limit {
		s.events = s.events[1:]
	}
}

// GetEvents 获取所有事件
func (s *EventStore) GetEvents() []ProcessEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// 返回副本
	events := make([]ProcessEvent, len(s.events))
	copy(events, s.events)
	return events
}

// GetRecentEvents 获取最近 N 个事件
func (s *EventStore) GetRecentEvents(n int) []ProcessEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if n <= 0 {
		return []ProcessEvent{}
	}

	length := len(s.events)
	if n > length {
		n = length
	}

	// 返回最后 n 个事件的副本
	events := make([]ProcessEvent, n)
	copy(events, s.events[length-n:])
	return events
}

// NewServer 创建新的 HTTP 服务器
func NewServer(dbPath string) (*Server, error) {
	// 初始化数据库
	db, err := NewDatabase(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	return &Server{
		store:        NewEventStore(10000), // 存储最多 10000 个事件
		clients:      make(map[*websocket.Conn]bool),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // 允许所有来源
			},
		},
		broadcastChan:            make(chan ProcessEvent, 100),
		db:                       db,
		riskAnalyzer:             NewRiskAnalyzer(),
		deduplicator:             NewEventDeduplicator(),
		forensicReportGenerator:  NewForensicReportGenerator(db),
	}, nil
}

// handleEvents 处理事件提交
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var event ProcessEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 获取 Agent ID（从请求头或使用默认值）
	agentID := r.Header.Get("X-Agent-ID")
	if agentID == "" {
		agentID = "default"
	}

	// 生成事件指纹用于去重
	fingerprint := s.deduplicator.GenerateFingerprint(event)

	// 检查是否需要去重
	existingEvent, err := s.db.GetEventByFingerprint(fingerprint)
	if err == nil && existingEvent != nil {
		// 事件已存在，返回成功但不重复处理
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":      "success",
			"duplicate":   true,
			"event_id":    existingEvent.ID,
			"risk_level":  existingEvent.RiskLevel,
		})
		return
	}

	// 评估风险等级
	riskLevel := s.riskAnalyzer.Evaluate(event)

	// 存储到数据库
	if err := s.db.InsertEvent(event, riskLevel, fingerprint, agentID); err != nil {
		log.Printf("Failed to insert event into database: %v", err)
		// 即使数据库插入失败，也继续处理
	}

	// 添加到内存存储
	s.store.AddEvent(event)

	// 广播到所有 WebSocket 客户端
	s.broadcastChan <- event

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "success",
		"duplicate":  false,
		"risk_level": string(riskLevel),
	})
}

// handleGetEvents 处理获取事件请求
func (s *Server) handleGetEvents(w http.ResponseWriter, r *http.Request) {
	// 解析查询参数
	query := r.URL.Query()
	limit := 100
	offset := 0

	if limitStr := query.Get("limit"); limitStr != "" {
		if parsed, err := fmt.Sscanf(limitStr, "%d", &limit); err == nil && parsed == 1 && limit > 0 {
			if limit > 1000 {
				limit = 1000 // 限制最大返回数量
			}
		}
	}

	if offsetStr := query.Get("offset"); offsetStr != "" {
		if parsed, err := fmt.Sscanf(offsetStr, "%d", &offset); err == nil && parsed == 1 && offset >= 0 {
			// offset 已设置
		}
	}

	riskLevel := query.Get("risk_level")
	eventType := query.Get("event_type")
	agentID := query.Get("agent_id")

	// 从数据库查询事件
	events, err := s.db.GetEvents(limit, offset, riskLevel, eventType, agentID)
	if err != nil {
		log.Printf("Failed to get events from database: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(events)
}

// handleRecentEvents 处理获取最近事件请求
func (s *Server) handleRecentEvents(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	n := 100 // 默认 100 个事件
	if limit := vars["limit"]; limit != "" {
		var parsed int
		if _, err := fmt.Sscanf(limit, "%d", &parsed); err == nil && parsed > 0 {
			n = parsed
		}
	}

	events := s.store.GetRecentEvents(n)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(events)
}

// handleWebSocket 处理 WebSocket 连接
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}

	s.clientsMutex.Lock()
	s.clients[conn] = true
	s.clientsMutex.Unlock()

	// 发送最近 100 个事件
	recentEvents := s.store.GetRecentEvents(100)
	for _, event := range recentEvents {
		if err := conn.WriteJSON(event); err != nil {
			log.Printf("Error sending initial events: %v", err)
			break
		}
	}

	// 处理连接关闭
	defer func() {
		s.clientsMutex.Lock()
		delete(s.clients, conn)
		s.clientsMutex.Unlock()
		conn.Close()
	}()

	// 保持连接活跃
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

// broadcastEvents 广播事件到所有客户端
func (s *Server) broadcastEvents() {
	for event := range s.broadcastChan {
		s.clientsMutex.RLock()
		for client := range s.clients {
			if err := client.WriteJSON(event); err != nil {
				log.Printf("Error broadcasting to client: %v", err)
				client.Close()
				s.clientsMutex.RUnlock()
				s.clientsMutex.Lock()
				delete(s.clients, client)
				s.clientsMutex.Unlock()
				s.clientsMutex.RLock()
			}
		}
		s.clientsMutex.RUnlock()
	}
}

// handleHealth 健康检查端点
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "healthy",
		"clients": len(s.clients),
		"events":  len(s.store.GetEvents()),
	})
}

// handleStatistics 处理统计信息请求
func (s *Server) handleStatistics(w http.ResponseWriter, r *http.Request) {
	stats, err := s.db.GetEventStatistics()
	if err != nil {
		log.Printf("Failed to get statistics: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// handleHighRiskEvents 处理高风险事件查询
func (s *Server) handleHighRiskEvents(w http.ResponseWriter, r *http.Request) {
    query := r.URL.Query()
    limit := 100

    if limitStr := query.Get("limit"); limitStr != "" {
        if parsed, err := fmt.Sscanf(limitStr, "%d", &limit); err == nil && parsed == 1 && limit > 0 {
            if limit > 1000 {
                limit = 1000
            }
        }
    }

    // 查询高风险事件
    events, err := s.db.GetEvents(limit, 0, "HIGH", "", "")
    if err != nil {
        log.Printf("Failed to get high risk events: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(events)
}

// handleTimelineReconstruction 处理时间线重建请求
func (s *Server) handleTimelineReconstruction(w http.ResponseWriter, r *http.Request) {
    query := r.URL.Query()
    
    // 获取参数
    pidStr := query.Get("pid")
    timeWindow := 10 // 默认10分钟
    
    if timeWindowStr := query.Get("time_window"); timeWindowStr != "" {
        if parsed, err := fmt.Sscanf(timeWindowStr, "%d", &timeWindow); err == nil && parsed == 1 {
            if timeWindow < 1 {
                timeWindow = 1
            } else if timeWindow > 60 {
                timeWindow = 60
            }
        }
    }
    
    if pidStr == "" {
        http.Error(w, "Missing required parameter: pid", http.StatusBadRequest)
        return
    }
    
    var pid uint32
    if _, err := fmt.Sscanf(pidStr, "%d", &pid); err != nil {
        http.Error(w, "Invalid pid parameter", http.StatusBadRequest)
        return
    }
    
    // 计算时间范围
    endTime := time.Now()
    startTime := endTime.Add(-time.Duration(timeWindow) * time.Minute)
    
    // 查询该进程在指定时间范围内的所有事件
    events, err := s.db.GetProcessTimeline(pid, startTime.UnixNano(), endTime.UnixNano())
    if err != nil {
        log.Printf("Failed to get timeline: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }
    
    // 构建响应
    response := map[string]interface{}{
        "pid":         pid,
        "start_time":  startTime.Format(time.RFC3339),
        "end_time":    endTime.Format(time.RFC3339),
        "time_window": timeWindow,
        "total_events": len(events),
        "events":      events,
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

// handlePrivilegeEscalationTimeline 处理提权事件时间线重建
func (s *Server) handlePrivilegeEscalationTimeline(w http.ResponseWriter, r *http.Request) {
    query := r.URL.Query()
    
    // 获取参数
    eventIDStr := query.Get("event_id")
    timeWindow := 10 // 默认10分钟
    
    if timeWindowStr := query.Get("time_window"); timeWindowStr != "" {
        if parsed, err := fmt.Sscanf(timeWindowStr, "%d", &timeWindow); err == nil && parsed == 1 {
            if timeWindow < 1 {
                timeWindow = 1
            } else if timeWindow > 60 {
                timeWindow = 60
            }
        }
    }
    
    if eventIDStr == "" {
        http.Error(w, "Missing required parameter: event_id", http.StatusBadRequest)
        return
    }
    
    var eventID int
    if _, err := fmt.Sscanf(eventIDStr, "%d", &eventID); err != nil {
        http.Error(w, "Invalid event_id parameter", http.StatusBadRequest)
        return
    }
    
    // 查询指定的事件
    events, err := s.db.GetEventByID(eventID)
    if err != nil {
        log.Printf("Failed to get event: %v", err)
        http.Error(w, "Event not found", http.StatusNotFound)
        return
    }
    
    // 计算时间范围（提权事件发生前的时间段）
    eventTime := time.Unix(0, int64(events[0].Timestamp))
    startTime := eventTime.Add(-time.Duration(timeWindow) * time.Minute)
    endTime := eventTime
    
    // 查询该进程在指定时间范围内的所有事件
    timeline, err := s.db.GetProcessTimeline(events[0].Pid, startTime.UnixNano(), endTime.UnixNano())
    if err != nil {
        log.Printf("Failed to get timeline: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }
    
    // 构建响应
    response := map[string]interface{}{
        "escalation_event":  events[0],
        "pid":              events[0].Pid,
        "start_time":       startTime.Format(time.RFC3339),
        "escalation_time":  eventTime.Format(time.RFC3339),
        "time_window":      timeWindow,
        "total_events":     len(timeline),
        "timeline_events":  timeline,
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

// handleForensicReport 处理取证报告生成请求
func (s *Server) handleForensicReport(w http.ResponseWriter, r *http.Request) {
    query := r.URL.Query()
    
    // 获取参数
    eventIDStr := query.Get("event_id")
    format := ReportFormat(query.Get("format"))
    
    // 验证参数
    if eventIDStr == "" {
        http.Error(w, "Missing required parameter: event_id", http.StatusBadRequest)
        return
    }
    
    var eventID int
    if _, err := fmt.Sscanf(eventIDStr, "%d", &eventID); err != nil {
        http.Error(w, "Invalid event_id parameter", http.StatusBadRequest)
        return
    }
    
    // 设置默认格式为 JSON
    if format == "" {
        format = FormatJSON
    }
    
    // 验证格式
    if format != FormatText && format != FormatJSON && format != FormatMarkdown {
        http.Error(w, "Invalid format parameter. Supported formats: text, json, markdown", http.StatusBadRequest)
        return
    }
    
    // 生成报告
    report, err := s.forensicReportGenerator.GenerateReport(eventID, format)
    if err != nil {
        log.Printf("Failed to generate forensic report: %v", err)
        if err.Error() == "event not found" {
            http.Error(w, "Event not found", http.StatusNotFound)
        } else {
            http.Error(w, "Internal server error", http.StatusInternalServerError)
        }
        return
    }
    
    // 根据格式设置响应头
    switch format {
    case FormatJSON:
        w.Header().Set("Content-Type", "application/json")
    case FormatMarkdown:
        w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
        w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="forensic_report_%d.md"`, eventID))
    case FormatText:
        w.Header().Set("Content-Type", "text/plain; charset=utf-8")
        w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="forensic_report_%d.txt"`, eventID))
    }
    
    // 返回报告
    if format == FormatJSON {
        json.NewEncoder(w).Encode(report)
    } else {
        w.Write([]byte(report.(string)))
    }
}
// handleRoot 处理根路径，重定向到仪表板
func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/static/dashboard.html", http.StatusMovedPermanently)
}

func main() {
	// 创建服务器实例
	server, err := NewServer("./security_events.db")
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}
	defer server.db.Close()

	// 启动广播协程
	go server.broadcastEvents()

	// 创建路由
	r := mux.NewRouter()

	// 根路径重定向到仪表板
	r.HandleFunc("/", server.handleRoot).Methods("GET")

	// API 路由
	r.HandleFunc("/api/events", server.handleEvents).Methods("POST")
	r.HandleFunc("/api/events", server.handleGetEvents).Methods("GET")
	r.HandleFunc("/api/events/recent/{limit}", server.handleRecentEvents).Methods("GET")
	r.HandleFunc("/api/statistics", server.handleStatistics).Methods("GET")
	r.HandleFunc("/api/high-risk-events", server.handleHighRiskEvents).Methods("GET")
	r.HandleFunc("/api/timeline/reconstruct", server.handleTimelineReconstruction).Methods("GET")
	r.HandleFunc("/api/timeline/privilege-escalation", server.handlePrivilegeEscalationTimeline).Methods("GET")
	r.HandleFunc("/api/report/forensic", server.handleForensicReport).Methods("GET")
	r.HandleFunc("/api/health", server.handleHealth).Methods("GET")

	// WebSocket 路由
	r.HandleFunc("/ws", server.handleWebSocket)

	// 静态文件服务（用于前端）
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	// 启动服务器
	addr := ":8080"
	log.Printf("Server starting on %s", addr)
	log.Printf("Database: ./security_events.db")
	log.Fatal(http.ListenAndServe(addr, r))
}