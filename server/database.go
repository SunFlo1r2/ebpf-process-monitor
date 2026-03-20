package main

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Database 数据库操作封装
type Database struct {
	db *sql.DB
}

// NewDatabase 创建数据库连接
func NewDatabase(dbPath string) (*Database, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// 设置连接池参数
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	// 初始化数据库表
	if err := initSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize database schema: %w", err)
	}

	return &Database{db: db}, nil
}

// Close 关闭数据库连接
func (d *Database) Close() error {
	return d.db.Close()
}

// initSchema 初始化数据库表结构
func initSchema(db *sql.DB) error {
	// 读取 schema.sql 文件
	schema := `
	CREATE TABLE IF NOT EXISTS security_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp INTEGER NOT NULL,
		pid INTEGER NOT NULL,
		ppid INTEGER NOT NULL,
		uid INTEGER NOT NULL,
		gid INTEGER NOT NULL,
		euid INTEGER NOT NULL,
		egid INTEGER NOT NULL,
		old_uid INTEGER DEFAULT 0,
		new_uid INTEGER DEFAULT 0,
		comm TEXT NOT NULL,
		filename TEXT,
		filepath TEXT,
		is_privilege_escalation BOOLEAN DEFAULT 0,
		event_type INTEGER NOT NULL,
		target_file_type INTEGER DEFAULT 0,
		risk_level TEXT NOT NULL DEFAULT 'LOW',
		agent_id TEXT DEFAULT 'default',
		fingerprint TEXT UNIQUE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		
		-- 网络连接相关字段
		src_addr INTEGER DEFAULT 0,
		dst_addr INTEGER DEFAULT 0,
		src_port INTEGER DEFAULT 0,
		dst_port INTEGER DEFAULT 0,
		protocol INTEGER DEFAULT 0,
		exit_code INTEGER DEFAULT 0
	);

	CREATE INDEX IF NOT EXISTS idx_timestamp ON security_events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_risk_level ON security_events(risk_level);
	CREATE INDEX IF NOT EXISTS idx_event_type ON security_events(event_type);
	CREATE INDEX IF NOT EXISTS idx_agent_id ON security_events(agent_id);
	CREATE INDEX IF NOT EXISTS idx_fingerprint ON security_events(fingerprint);
	`

	_, err := db.Exec(schema)
	return err
}

// InsertEvent 插入事件到数据库
func (d *Database) InsertEvent(event ProcessEvent, riskLevel RiskLevel, fingerprint, agentID string) error {
	query := `
	INSERT INTO security_events (
		timestamp, pid, ppid, uid, gid, euid, egid, old_uid, new_uid,
		comm, filename, filepath, is_privilege_escalation, event_type,
		target_file_type, risk_level, agent_id, fingerprint,
		src_addr, dst_addr, src_port, dst_port, protocol, exit_code
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(fingerprint) DO UPDATE SET
		timestamp = excluded.timestamp,
		risk_level = excluded.risk_level,
		created_at = CURRENT_TIMESTAMP,
		src_addr = excluded.src_addr,
		dst_addr = excluded.dst_addr,
		src_port = excluded.src_port,
		dst_port = excluded.dst_port,
		protocol = excluded.protocol,
		exit_code = excluded.exit_code
	`

	_, err := d.db.Exec(query,
		event.Timestamp,
		event.Pid,
		event.Ppid,
		event.Uid,
		event.Gid,
		event.Euid,
		event.Egid,
		event.OldUid,
		event.NewUid,
		event.Comm,
		event.Filename,
		event.Filepath,
		event.IsPrivilegeEscalation,
		event.EventType,
		event.TargetFileType,
		string(riskLevel),
		agentID,
		fingerprint,
		event.SrcAddr,
		event.DstAddr,
		event.SrcPort,
		event.DstPort,
		event.Protocol,
		event.ExitCode,
	)

	return err
}

// GetEvents 获取事件列表
func (d *Database) GetEvents(limit, offset int, riskLevel, eventType, agentID string) ([]ProcessEventWithRisk, error) {
	query := `
	SELECT id, timestamp, pid, ppid, uid, gid, euid, egid, old_uid, new_uid,
		comm, filename, filepath, is_privilege_escalation, event_type,
		target_file_type, risk_level, agent_id, created_at,
		src_addr, dst_addr, src_port, dst_port, protocol, exit_code
	FROM security_events
	WHERE 1=1
	`
	args := []interface{}{}
	argIndex := 1

	// 添加过滤条件
	if riskLevel != "" {
		query += fmt.Sprintf(" AND risk_level = ?")
		args = append(args, riskLevel)
		argIndex++
	}

	if eventType != "" {
		query += fmt.Sprintf(" AND event_type = ?")
		args = append(args, eventType)
		argIndex++
	}

	if agentID != "" {
		query += fmt.Sprintf(" AND agent_id = ?")
		args = append(args, agentID)
		argIndex++
	}

	query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []ProcessEventWithRisk
	for rows.Next() {
		var event ProcessEventWithRisk
		var createdAt time.Time

		err := rows.Scan(
			&event.ID,
			&event.Timestamp,
			&event.Pid,
			&event.Ppid,
			&event.Uid,
			&event.Gid,
			&event.Euid,
			&event.Egid,
			&event.OldUid,
			&event.NewUid,
			&event.Comm,
			&event.Filename,
			&event.Filepath,
			&event.IsPrivilegeEscalation,
			&event.EventType,
			&event.TargetFileType,
			&event.RiskLevel,
			&event.AgentID,
			&createdAt,
			&event.SrcAddr,
			&event.DstAddr,
			&event.SrcPort,
			&event.DstPort,
			&event.Protocol,
			&event.ExitCode,
		)
		if err != nil {
			return nil, err
		}

		event.CreatedAt = createdAt.Format(time.RFC3339)
		events = append(events, event)
	}

	return events, nil
}

// GetEventByFingerprint 根据指纹获取事件
func (d *Database) GetEventByFingerprint(fingerprint string) (*ProcessEventWithRisk, error) {
	query := `
	SELECT id, timestamp, pid, ppid, uid, gid, euid, egid, old_uid, new_uid,
		comm, filename, filepath, is_privilege_escalation, event_type,
		target_file_type, risk_level, agent_id, created_at,
		src_addr, dst_addr, src_port, dst_port, protocol, exit_code
	FROM security_events
	WHERE fingerprint = ?
	`

	var event ProcessEventWithRisk
	var createdAt time.Time

	err := d.db.QueryRow(query, fingerprint).Scan(
		&event.ID,
		&event.Timestamp,
		&event.Pid,
		&event.Ppid,
		&event.Uid,
		&event.Gid,
		&event.Euid,
		&event.Egid,
		&event.OldUid,
		&event.NewUid,
		&event.Comm,
		&event.Filename,
		&event.Filepath,
		&event.IsPrivilegeEscalation,
		&event.EventType,
		&event.TargetFileType,
		&event.RiskLevel,
		&event.AgentID,
		&createdAt,
		&event.SrcAddr,
		&event.DstAddr,
		&event.SrcPort,
		&event.DstPort,
		&event.Protocol,
		&event.ExitCode,
	)

	if err != nil {
		return nil, err
	}

	event.CreatedAt = createdAt.Format(time.RFC3339)
	return &event, nil
}

// GetEventStatistics 获取事件统计信息
func (d *Database) GetEventStatistics() (*EventStatistics, error) {
	stats := &EventStatistics{}

	// 总事件数
	err := d.db.QueryRow("SELECT COUNT(*) FROM security_events").Scan(&stats.TotalEvents)
	if err != nil {
		return nil, err
	}

	// 按风险等级统计
	rows, err := d.db.Query(`
		SELECT risk_level, COUNT(*) as count
		FROM security_events
		GROUP BY risk_level
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats.RiskLevelDistribution = make(map[string]int)
	for rows.Next() {
		var level string
		var count int
		if err := rows.Scan(&level, &count); err != nil {
			return nil, err
		}
		stats.RiskLevelDistribution[level] = count
	}

	// 按事件类型统计
	rows, err = d.db.Query(`
		SELECT event_type, COUNT(*) as count
		FROM security_events
		GROUP BY event_type
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats.EventTypeDistribution = make(map[string]int)
	for rows.Next() {
		var eventType int
		var count int
		if err := rows.Scan(&eventType, &count); err != nil {
			return nil, err
		}
		var typeName string
		switch eventType {
		case 0:
			typeName = "EXECVE"
		case 1:
			typeName = "SETUID"
		case 2:
			typeName = "FILE_WRITE"
		case 3:
			typeName = "OPENAT"
		case 4:
			typeName = "CONNECT"
		case 5:
			typeName = "BIND"
		case 6:
			typeName = "EXIT"
		default:
			typeName = "UNKNOWN"
		}
		stats.EventTypeDistribution[typeName] = count
	}

	// 最近24小时事件数
	err = d.db.QueryRow(`
		SELECT COUNT(*) FROM security_events
		WHERE timestamp >= ?
	`, time.Now().Add(-24*time.Hour).UnixNano()).Scan(&stats.Last24Hours)
	if err != nil {
		return nil, err
	}

	return stats, nil
}

// GetProcessTimeline 获取指定进程在指定时间范围内的事件
func (d *Database) GetProcessTimeline(pid uint32, startTime, endTime int64) ([]ProcessEventWithRisk, error) {
	query := `
	SELECT id, timestamp, pid, ppid, uid, gid, euid, egid, old_uid, new_uid,
		comm, filename, filepath, is_privilege_escalation, event_type,
		target_file_type, risk_level, agent_id, created_at,
		src_addr, dst_addr, src_port, dst_port, protocol, exit_code
	FROM security_events
	WHERE pid = ? AND timestamp BETWEEN ? AND ?
	ORDER BY timestamp ASC
	`

	rows, err := d.db.Query(query, pid, startTime, endTime)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []ProcessEventWithRisk
	for rows.Next() {
		var event ProcessEventWithRisk
		var createdAt time.Time

		err := rows.Scan(
			&event.ID,
			&event.Timestamp,
			&event.Pid,
			&event.Ppid,
			&event.Uid,
			&event.Gid,
			&event.Euid,
			&event.Egid,
			&event.OldUid,
			&event.NewUid,
			&event.Comm,
			&event.Filename,
			&event.Filepath,
			&event.IsPrivilegeEscalation,
			&event.EventType,
			&event.TargetFileType,
			&event.RiskLevel,
			&event.AgentID,
			&createdAt,
			&event.SrcAddr,
			&event.DstAddr,
			&event.SrcPort,
			&event.DstPort,
			&event.Protocol,
			&event.ExitCode,
		)
		if err != nil {
			return nil, err
		}

		event.CreatedAt = createdAt.Format(time.RFC3339)
		events = append(events, event)
	}

	return events, nil
}

// GetEventByID 根据ID获取事件
func (d *Database) GetEventByID(eventID int) ([]ProcessEventWithRisk, error) {
	query := `
	SELECT id, timestamp, pid, ppid, uid, gid, euid, egid, old_uid, new_uid,
		comm, filename, filepath, is_privilege_escalation, event_type,
		target_file_type, risk_level, agent_id, created_at,
		src_addr, dst_addr, src_port, dst_port, protocol, exit_code
	FROM security_events
	WHERE id = ?
	`

	var event ProcessEventWithRisk
	var createdAt time.Time

	err := d.db.QueryRow(query, eventID).Scan(
		&event.ID,
		&event.Timestamp,
		&event.Pid,
		&event.Ppid,
		&event.Uid,
		&event.Gid,
		&event.Euid,
		&event.Egid,
		&event.OldUid,
		&event.NewUid,
		&event.Comm,
		&event.Filename,
		&event.Filepath,
		&event.IsPrivilegeEscalation,
		&event.EventType,
		&event.TargetFileType,
		&event.RiskLevel,
		&event.AgentID,
		&createdAt,
		&event.SrcAddr,
		&event.DstAddr,
		&event.SrcPort,
		&event.DstPort,
		&event.Protocol,
		&event.ExitCode,
	)

	if err != nil {
		return nil, err
	}

	event.CreatedAt = createdAt.Format(time.RFC3339)
	return []ProcessEventWithRisk{event}, nil
}

// ProcessEventWithRisk 包含风险等级的事件
type ProcessEventWithRisk struct {
	ID                      int       `json:"id"`
	Timestamp               uint64    `json:"timestamp"`
	Pid                     uint32    `json:"pid"`
	Ppid                    uint32    `json:"ppid"`
	Uid                     uint32    `json:"uid"`
	Gid                     uint32    `json:"gid"`
	Euid                    uint32    `json:"euid"`
	Egid                    uint32    `json:"egid"`
	OldUid                  uint32    `json:"old_uid"`
	NewUid                  uint32    `json:"new_uid"`
	Comm                    string    `json:"comm"`
	Filename                string    `json:"filename"`
	Filepath                string    `json:"filepath"`
	IsPrivilegeEscalation   bool      `json:"is_privilege_escalation"`
	EventType               uint8     `json:"event_type"`
	TargetFileType          uint8     `json:"target_file_type"`
	RiskLevel               string    `json:"risk_level"`
	AgentID                 string    `json:"agent_id"`
	CreatedAt               string    `json:"created_at"`
	
	// 网络连接相关字段
	SrcAddr                 uint32    `json:"src_addr"`
	DstAddr                 uint32    `json:"dst_addr"`
	SrcPort                 uint16    `json:"src_port"`
	DstPort                 uint16    `json:"dst_port"`
	Protocol                uint8     `json:"protocol"`
	ExitCode                uint8     `json:"exit_code"`
}

// EventStatistics 事件统计信息
type EventStatistics struct {
	TotalEvents            int            `json:"total_events"`
	Last24Hours            int            `json:"last_24_hours"`
	RiskLevelDistribution  map[string]int `json:"risk_level_distribution"`
	EventTypeDistribution  map[string]int `json:"event_type_distribution"`
}
