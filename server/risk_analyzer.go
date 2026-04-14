package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// RiskLevel 表示风险等级
type RiskLevel string

const (
	RiskNone   RiskLevel = "NONE"   // 无风险
	RiskLow    RiskLevel = "LOW"    // 低风险
	RiskMedium RiskLevel = "MEDIUM" // 中风险
	RiskHigh   RiskLevel = "HIGH"   // 高风险
)

// WhiteListConfig 白名单配置文件结构
type WhiteListConfig struct {
	Version    string   `json:"version"`
	Description string   `json:"description"`
	Whitelist  []string `json:"whitelist"`
	Patterns   []string `json:"patterns"`
}

// WhiteList 白名单管理器
type WhiteList struct {
	whitelist     map[string]bool // 精确匹配白名单
	patterns      []string        // 模式匹配白名单（支持通配符）
	mu            sync.RWMutex
	lastLoadTime  time.Time
	configPath    string
}

// NewWhiteList 创建白名单管理器
func NewWhiteList(configPath string) *WhiteList {
	wl := &WhiteList{
		whitelist: make(map[string]bool),
		patterns:  []string{},
		configPath: configPath,
	}
	
	// 尝试加载白名单配置
	if err := wl.Load(); err != nil {
		// 如果加载失败，使用默认白名单
		wl.loadDefaultWhitelist()
	}
	
	return wl
}

// Load 从配置文件加载白名单
func (wl *WhiteList) Load() error {
	wl.mu.Lock()
	defer wl.mu.Unlock()
	
	// 清空现有白名单
	wl.whitelist = make(map[string]bool)
	wl.patterns = []string{}
	
	// 如果配置文件不存在，返回错误
	if _, err := os.Stat(wl.configPath); os.IsNotExist(err) {
		return fmt.Errorf("whitelist config file not found: %s", wl.configPath)
	}
	
	// 读取配置文件
	data, err := os.ReadFile(wl.configPath)
	if err != nil {
		return fmt.Errorf("failed to read whitelist config: %w", err)
	}
	
	// 解析JSON
	var config WhiteListConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse whitelist config: %w", err)
	}
	
	// 加载精确匹配白名单
	for _, proc := range config.Whitelist {
		wl.whitelist[proc] = true
	}
	
	// 加载模式匹配白名单
	for _, pattern := range config.Patterns {
		wl.patterns = append(wl.patterns, pattern)
	}
	
	wl.lastLoadTime = time.Now()
	return nil
}

// loadDefaultWhitelist 加载默认白名单
func (wl *WhiteList) loadDefaultWhitelist() {
	defaultProcesses := []string{
		"systemd", "init", "bash", "sh", "zsh", "dash", "fish",
		"ls", "cd", "pwd", "cat", "grep", "sed", "awk", "sort",
		"uniq", "head", "tail", "less", "more", "cp", "mv",
		"rm", "mkdir", "rmdir", "touch", "chmod", "chown", "ps",
		"top", "htop", "df", "du", "free", "uptime", "date", "echo",
		"printf", "which", "whereis", "man", "help", "curl", "wget",
		"tar", "gzip", "gunzip", "zip", "unzip", "find", "locate",
		"nano", "vim", "vi", "emacs", "python", "python3", "node",
		"npm", "docker", "dockerd", "containerd", "sshd", "ssh-agent",
		"rsync", "scp", "sftp", "git", "svn", "hg", "make", "gcc",
		"g++", "clang", "clang++", "go", "java", "javac", "mvn",
		"gradle", "ping", "ping6", "traceroute", "nslookup", "dig",
		"host", "ip", "ifconfig", "route", "netstat", "ss", "journalctl",
		"systemctl", "service", "apt", "apt-get", "yum", "dnf", "pacman",
		"snap", "dpkg", "rpm", "cron", "crond", "at", "batch", "rsyslog",
		"syslog-ng", "logrotate", "postfix", "sendmail", "nginx", "apache2",
		"httpd", "mysql", "mysqld", "mariadb", "postgres", "postgresql",
		"mongodb", "redis", "redis-server", "memcached", "lighttpd", "caddy",
		"haproxy", "keepalived", "firewalld", "ufw", "iptables", "nft",
	}
	
	for _, proc := range defaultProcesses {
		wl.whitelist[proc] = true
	}
	
	// 默认模式
	wl.patterns = []string{
		"python*", "node*", "npm*", "java*", "mvn*", "gradle*",
		"go*", "ruby*", "gem*", "perl*", "php*", "composer*",
		"cargo*", "rustc*",
	}
}

// IsWhitelisted 检查进程是否在白名单中
func (wl *WhiteList) IsWhitelisted(comm string) bool {
	wl.mu.RLock()
	defer wl.mu.RUnlock()
	
	commLower := strings.ToLower(comm)
	
	// 首先检查精确匹配
	if wl.whitelist[commLower] {
		return true
	}
	
	// 检查模式匹配
	for _, pattern := range wl.patterns {
		if wl.matchPattern(commLower, pattern) {
			return true
		}
	}
	
	return false
}

// matchPattern 简单的通配符匹配
func (wl *WhiteList) matchPattern(text, pattern string) bool {
	pattern = strings.ToLower(pattern)
	text = strings.ToLower(text)
	
	// 如果模式以*结尾，检查前缀匹配
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(text, prefix)
	}
	
	// 如果模式以*开头，检查后缀匹配
	if strings.HasPrefix(pattern, "*") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(text, suffix)
	}
	
	// 如果模式包含*，检查包含匹配
	if strings.Contains(pattern, "*") {
		parts := strings.Split(pattern, "*")
		if len(parts) == 2 {
			return strings.HasPrefix(text, parts[0]) && strings.HasSuffix(text, parts[1])
		}
	}
	
	// 否则精确匹配
	return text == pattern
}

// Reload 重新加载白名单配置
func (wl *WhiteList) Reload() error {
	return wl.Load()
}

// RiskAnalyzer 负责事件风险评级
type RiskAnalyzer struct {
	whitelist *WhiteList
}

// NewRiskAnalyzer 创建风险分析器
func NewRiskAnalyzer() *RiskAnalyzer {
	// 获取白名单配置文件路径
	configPath := filepath.Join(".", "process_whitelist.json")
	
	return &RiskAnalyzer{
		whitelist: NewWhiteList(configPath),
	}
}

// Evaluate 评估事件的风险等级
func (ra *RiskAnalyzer) Evaluate(event ProcessEvent) RiskLevel {
	// 首先检查白名单：如果进程在白名单中，直接返回无风险
	if ra.whitelist != nil && ra.whitelist.IsWhitelisted(event.Comm) {
		return RiskNone
	}
	
	score := 0

	// 1. 检查是否是真正的权限提升（从普通用户提升到 root）
	// 条件：UID != 0 && EUID == 0
	isRealPrivilegeEscalation := (event.Uid != 0 && event.Euid == 0)

	if isRealPrivilegeEscalation {
		score += 20
	} else if event.IsPrivilegeEscalation {
		// 如果只是标记了权限提升，但不是从普通用户到root，给较低分数
		score += 3
	}

	// 2. 根据事件类型评分
	switch event.EventType {
	case 0: // EXECVE
		// 检查是否是敏感程序（只对高风险程序加分）
		if isHighRiskProgram(event.Comm) {
			score += 15
		}
		// 检查是否是敏感路径
		if isSensitivePath(event.Filename) {
			score += 10
		}
	case 1: // SETUID
		// SETUID 到 root 是高风险
		if event.NewUid == 0 && event.OldUid != 0 {
			score += 30
		}
	case 2: // FILE_WRITE
		// 写入敏感文件是高风险
		if event.TargetFileType == 1 || event.TargetFileType == 2 { // PASSWD or SHADOW
			score += 35
		}
	case 3: // OPENAT
		// 检查敏感文件访问
		if isSensitiveFileAccess(event.TargetFileType) {
			score += 20
		}
	case 4: // CONNECT
		// 检测反向Shell：shell进程建立出站连接
		if isReverseShell(event.Comm) {
			score += 40 // 反向Shell是极高风险
		}
		// 检测可疑工具
		if isSuspiciousTool(event.Comm) {
			score += 25
		}
		// 检测非标准端口连接
		if isUnusualPort(event.DstPort) {
			score += 15
		}
	case 5: // BIND
		// 绑定特权端口（<1024）是高风险
		if event.SrcPort > 0 && event.SrcPort < 1024 {
			score += 20
		}
	case 6: // EXIT
		// 检测异常退出码
		if event.ExitCode != 0 {
			score += 5
		}
	}

	// 3. 时间因素：非工作时间（晚上10点到早上6点）的事件风险更高
	now := time.Now()
	hour := now.Hour()
	if hour >= 22 || hour < 6 {
		score += 5
	}

	// 4. 特殊情况：root 用户执行的常规程序
	// 如果是 root 用户执行（UID=0, EUID=0），且不是真正的权限提升
	// 且不是高风险程序，则大幅降低风险评分
	if event.Uid == 0 && event.Euid == 0 && !isRealPrivilegeEscalation {
		if !isHighRiskProgram(event.Comm) && !isSensitivePath(event.Filename) && !isReverseShell(event.Comm) {
			// root 用户执行的常规程序，极低风险
			score = 0
		} else if isHighRiskProgram(event.Comm) {
			// root 用户执行的高风险程序，中等风险（15分）
			score = 15
		}
	}

	// 5. 如果被标记为权限提升，增加额外风险分数
	// 真正的权限提升（从普通用户到root）应该获得高风险评分
	if event.IsPrivilegeEscalation && score > 0 {
		// 特殊处理：如果 comm 是 sudo 或 su，直接设为高风险
		// 无论 UID 和 EUID 是什么值
		if event.Comm == "sudo" || event.Comm == "su" {
			// sudo/su 命令，高风险（27分）
			score = 27
		} else if isRealPrivilegeEscalation {
			// 其他真正的权限提升，高风险（25分）
			score = 25
		} else {
			// root 用户直接执行的其他高风险程序（已被标记为权限提升但不是真正的提升）
			// 在第4步已经设置为15分，这里保持不变，不加分
			// 15分在中风险范围内（12-24分）
		}
	}

	// 根据总分返回风险等级
	// 调整阈值，让分布更合理
	if score >= 25 {
		return RiskHigh
	} else if score >= 12 {
		return RiskMedium
	} else if score > 0 {
		return RiskLow
	}
	return RiskNone  // score为0，无风险
}

// isHighRiskProgram 检查是否是高风险程序
func isHighRiskProgram(comm string) bool {
	highRiskPrograms := []string{
		"sudo", "su", "passwd", "crontab",
		"ssh", "scp", "sftp",
		"mount", "umount", "modprobe", "insmod", "rmmod",
		"iptables", "nft",
		"strace", "gdb",
	}

	commLower := strings.ToLower(comm)
	for _, prog := range highRiskPrograms {
		if commLower == prog || strings.Contains(commLower, prog) {
			return true
		}
	}
	return false
}

// isSensitiveProgram 检查是否是敏感程序（保留用于其他用途）
func isSensitiveProgram(comm string) bool {
	sensitivePrograms := []string{
		"sudo", "su", "passwd", "chsh", "chfn",
		"crontab", "at", "batch", "ssh", "scp", "sftp",
		"mount", "umount", "modprobe", "insmod", "rmmod",
		"iptables", "nft", "tcpdump", "wireshark",
		"strace", "ltrace", "gdb", "perf",
	}

	commLower := strings.ToLower(comm)
	for _, prog := range sensitivePrograms {
		if strings.Contains(commLower, prog) {
			return true
		}
	}
	return false
}

// isSensitivePath 检查是否是敏感路径
func isSensitivePath(filename string) bool {
	if filename == "" {
		return false
	}

	// 只保留真正的敏感路径，不包括系统目录
	sensitivePaths := []string{
		"/etc/passwd", "/etc/shadow", "/etc/group",
		"/etc/sudoers", "/etc/crontab", "/etc/cron.",
		"/root/", "/home/", "/var/log/",
	}

	filenameLower := strings.ToLower(filename)
	for _, path := range sensitivePaths {
		if strings.Contains(filenameLower, path) {
			return true
		}
	}
	return false
}

// EventDeduplicator 负责事件去重
type EventDeduplicator struct {
	timeWindow time.Duration // 去重时间窗口
}

// NewEventDeduplicator 创建事件去重器
func NewEventDeduplicator() *EventDeduplicator {
	return &EventDeduplicator{
		timeWindow: time.Minute * 5, // 5分钟内相同事件去重
	}
}

// GenerateFingerprint 生成事件指纹（用于去重）
func (ed *EventDeduplicator) GenerateFingerprint(event ProcessEvent) string {
	// 使用事件的关键特征生成指纹
	data := fmt.Sprintf("%d-%d-%s-%d-%d-%s",
		event.EventType,
		event.Pid,
		event.Comm,
		event.Uid,
		event.Euid,
		event.Filename,
	)

	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// ShouldDeduplicate 判断是否应该去重
func (ed *EventDeduplicator) ShouldDeduplicate(event ProcessEvent, lastSeenTime time.Time) bool {
	// 如果上次看到的时间在时间窗口内，则去重
	return time.Since(lastSeenTime) < ed.timeWindow
}

// isReverseShell 检测是否是反向Shell
// shell进程建立出站连接可能是反向Shell攻击
func isReverseShell(comm string) bool {
	shellPatterns := []string{"bash", "sh", "zsh", "dash", "tcsh", "csh", "fish"}
	commLower := strings.ToLower(comm)
	
	for _, pattern := range shellPatterns {
		if commLower == pattern || strings.HasPrefix(commLower, pattern) {
			return true
		}
	}
	return false
}

// isSuspiciousTool 检测是否是可疑工具
// 这些工具可能被攻击者用于网络侦察或建立后门
func isSuspiciousTool(comm string) bool {
	suspiciousTools := []string{
		"nc", "netcat", "socat", "telnet", "ncat",
		"wget", "curl", "fetch", "lynx",
		"tftp", "ftp",
		"nc.traditional", "nc.openbsd",
	}
	commLower := strings.ToLower(comm)
	
	for _, tool := range suspiciousTools {
		if commLower == tool || strings.Contains(commLower, tool) {
			return true
		}
	}
	return false
}

// isUnusualPort 检测是否是非常规端口
// 检测连接到非常见端口（如4444, 5555, 6666, 12345等）的行为
func isUnusualPort(port uint16) bool {
	if port == 0 {
		return false
	}

	// 常见服务端口
	commonPorts := map[uint16]bool{
		21:   true,  // FTP
		22:   true,  // SSH
		23:   true,  // Telnet
		25:   true,  // SMTP
		53:   true,  // DNS
		80:   true,  // HTTP
		110:  true,  // POP3
		143:  true,  // IMAP
		443:  true,  // HTTPS
		3306: true,  // MySQL
		3389: true,  // RDP
		5432: true,  // PostgreSQL
		8080: true,  // HTTP Alt
	}

	// 检查是否是常见端口
	if commonPorts[port] {
		return false
	}

	// 检查是否是常见攻击使用的端口
	attackPorts := map[uint16]bool{
		4444: true,  // Metasploit默认
		5555: true,  // ADB
		6666: true,  // 常用攻击端口
		1234: true,  // 常用攻击端口
		12345: true, // NetBus
		31337: true, // Back Orifice
	}

	return attackPorts[port]
}

// isSensitiveFileAccess 检测是否访问敏感文件
func isSensitiveFileAccess(targetFileType uint8) bool {
	// 敏感文件类型（在eBPF代码中定义）
	// FILE_SUDOERS = 3, FILE_CRONTAB = 4, FILE_SSH_CONFIG = 5,
	// FILE_HOSTS = 6, FILE_SYSTEM_CONFIG = 7
	return targetFileType >= 3 && targetFileType <= 7
}
