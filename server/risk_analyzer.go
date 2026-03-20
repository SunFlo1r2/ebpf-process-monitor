package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// RiskLevel 表示风险等级
type RiskLevel string

const (
	RiskLow    RiskLevel = "LOW"
	RiskMedium RiskLevel = "MEDIUM"
	RiskHigh   RiskLevel = "HIGH"
)

// RiskAnalyzer 负责事件风险评级
type RiskAnalyzer struct{}

// NewRiskAnalyzer 创建风险分析器
func NewRiskAnalyzer() *RiskAnalyzer {
	return &RiskAnalyzer{}
}

// Evaluate 评估事件的风险等级
func (ra *RiskAnalyzer) Evaluate(event ProcessEvent) RiskLevel {
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
		if !isHighRiskProgram(event.Comm) && !isSensitivePath(event.Filename) {
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
	}
	return RiskLow
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
