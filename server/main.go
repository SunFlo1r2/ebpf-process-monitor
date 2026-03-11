package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"

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
	Comm                  string `json:"comm"`
	Filename              string `json:"filename"`
	IsPrivilegeEscalation bool   `json:"is_privilege_escalation"`
}

// EventStore 存储进程事件
type EventStore struct {
	mu     sync.RWMutex
	events []ProcessEvent
	limit  int // 最大存储事件数量
}

// Server 表示 HTTP 服务器
type Server struct {
	store         *EventStore
	clients       map[*websocket.Conn]bool
	clientsMutex  sync.RWMutex
	upgrader      websocket.Upgrader
	broadcastChan chan ProcessEvent
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
func NewServer() *Server {
	return &Server{
		store: NewEventStore(10000), // 存储最多 10000 个事件
		clients: make(map[*websocket.Conn]bool),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // 允许所有来源
			},
		},
		broadcastChan: make(chan ProcessEvent, 100),
	}
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

	// 添加到存储
	s.store.AddEvent(event)

	// 广播到所有 WebSocket 客户端
	s.broadcastChan <- event

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// handleGetEvents 处理获取事件请求
func (s *Server) handleGetEvents(w http.ResponseWriter, r *http.Request) {
	events := s.store.GetEvents()
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

func main() {
	server := NewServer()

	// 启动广播协程
	go server.broadcastEvents()

	// 创建路由
	r := mux.NewRouter()

	// API 路由
	r.HandleFunc("/api/events", server.handleEvents).Methods("POST")
	r.HandleFunc("/api/events", server.handleGetEvents).Methods("GET")
	r.HandleFunc("/api/events/recent/{limit}", server.handleRecentEvents).Methods("GET")
	r.HandleFunc("/api/health", server.handleHealth).Methods("GET")

	// WebSocket 路由
	r.HandleFunc("/ws", server.handleWebSocket)

	// 静态文件服务（用于前端）
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./static")))

	// 启动服务器
	addr := ":8080"
	log.Printf("Server starting on %s", addr)
	log.Fatal(http.ListenAndServe(addr, r))
}