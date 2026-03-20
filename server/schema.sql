-- 安全事件表
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

-- 创建索引以提高查询性能
CREATE INDEX IF NOT EXISTS idx_timestamp ON security_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_risk_level ON security_events(risk_level);
CREATE INDEX IF NOT EXISTS idx_event_type ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_agent_id ON security_events(agent_id);
CREATE INDEX IF NOT EXISTS idx_fingerprint ON security_events(fingerprint);

-- 创建视图：高风险事件
CREATE VIEW IF NOT EXISTS high_risk_events AS
SELECT * FROM security_events WHERE risk_level = 'HIGH' ORDER BY timestamp DESC;

-- 创建视图：最近事件（最近1000条）
CREATE VIEW IF NOT EXISTS recent_events AS
SELECT * FROM security_events ORDER BY timestamp DESC LIMIT 1000;
