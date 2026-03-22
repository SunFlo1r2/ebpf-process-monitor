package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ReportFormat 报告格式类型
type ReportFormat string

const (
	FormatText     ReportFormat = "text"
	FormatJSON     ReportFormat = "json"
	FormatMarkdown ReportFormat = "markdown"
)

// ForensicReport 表示取证报告
type ForensicReport struct {
	EventSummary      EventSummary      `json:"event_summary"`
	ProcessHistory    []ProcessEventWithRisk `json:"process_history"`
	RelatedProcesses  RelatedProcesses  `json:"related_processes"`
	Statistics        ProcessStatistics `json:"statistics"`
	AnalysisConclusion string            `json:"analysis_conclusion"`
	GeneratedAt       time.Time         `json:"generated_at"`
}

// EventSummary 事件概要
type EventSummary struct {
	Timestamp    string `json:"timestamp"`
	ProcessName  string `json:"process_name"`
	PID          uint32 `json:"pid"`
	User         string `json:"user"`
	UIDChange    string `json:"uid_change"`
	RiskLevel    string `json:"risk_level"`
}

// ForensicReportGenerator 取证报告生成器
type ForensicReportGenerator struct {
	db *Database
}

// NewForensicReportGenerator 创建取证报告生成器
func NewForensicReportGenerator(db *Database) *ForensicReportGenerator {
	return &ForensicReportGenerator{
		db: db,
	}
}

// GenerateReport 生成取证报告
func (frg *ForensicReportGenerator) GenerateReport(eventID int, format ReportFormat) (interface{}, error) {
	// 获取事件信息
	events, err := frg.db.GetEventByID(eventID)
	if err != nil {
		return nil, fmt.Errorf("failed to get event: %w", err)
	}
	if len(events) == 0 {
		return nil, fmt.Errorf("event not found")
	}

	event := events[0]

	// 计算时间范围（事件前10分钟）
	eventTime := time.Unix(0, int64(event.Timestamp))
	startTime := eventTime.Add(-10 * time.Minute)
	endTime := eventTime

	// 获取进程历史活动
	timeline, err := frg.db.GetProcessTimeline(event.Pid, startTime.UnixNano(), endTime.UnixNano())
	if err != nil {
		return nil, fmt.Errorf("failed to get process timeline: %w", err)
	}

	// 获取关联进程
	related, err := frg.db.GetRelatedProcesses(event.Pid)
	if err != nil {
		return nil, fmt.Errorf("failed to get related processes: %w", err)
	}

	// 获取统计信息
	stats, err := frg.db.GetProcessStatistics(event.Pid, startTime.UnixNano(), endTime.UnixNano())
	if err != nil {
		return nil, fmt.Errorf("failed to get process statistics: %w", err)
	}

	// 构建事件概要
	summary := EventSummary{
		Timestamp:   eventTime.Format("2006-01-02 15:04:05"),
		ProcessName: event.Comm,
		PID:         event.Pid,
		User:        fmt.Sprintf("%d", event.Uid),
		UIDChange:   fmt.Sprintf("%d → %d", event.OldUid, event.NewUid),
		RiskLevel:   event.RiskLevel,
	}

	// 构建报告
	report := ForensicReport{
		EventSummary:       summary,
		ProcessHistory:     timeline,
		RelatedProcesses:   *related,
		Statistics:         *stats,
		AnalysisConclusion: frg.generateAnalysisConclusion(event, timeline, stats),
		GeneratedAt:        time.Now(),
	}

	// 根据格式返回结果
	switch format {
	case FormatJSON:
		return report, nil
	case FormatText:
		return frg.generateTextReport(report, event), nil
	case FormatMarkdown:
		return frg.generateMarkdownReport(report, event), nil
	default:
		return nil, fmt.Errorf("unsupported report format: %s", format)
	}
}

// generateTextReport 生成文本格式报告
func (frg *ForensicReportGenerator) generateTextReport(report ForensicReport, event ProcessEventWithRisk) string {
	var sb strings.Builder

	sb.WriteString("=========== 提权事件取证报告 ============\n\n")

	// 事件概要
	sb.WriteString("🔍 事件概要\n")
	sb.WriteString(fmt.Sprintf("时间: %s\n", report.EventSummary.Timestamp))
	sb.WriteString(fmt.Sprintf("进程: %s (PID: %d)\n", report.EventSummary.ProcessName, report.EventSummary.PID))
	sb.WriteString(fmt.Sprintf("用户: %s (UID: %d → %d)\n", report.EventSummary.User, event.OldUid, event.NewUid))
	sb.WriteString(fmt.Sprintf("风险等级: %s\n\n", report.EventSummary.RiskLevel))

	// 进程历史活动
	sb.WriteString("📋 进程历史活动 (前10分钟)\n\n")
	if len(report.ProcessHistory) > 0 {
		for _, histEvent := range report.ProcessHistory {
			eventTime := time.Unix(0, int64(histEvent.Timestamp))
			timeStr := eventTime.Format("15:04:05")
			
			switch histEvent.EventType {
			case 0: // EXECVE
				sb.WriteString(fmt.Sprintf("%s - 执行: %s\n", timeStr, histEvent.Filename))
			case 1: // SETUID
				sb.WriteString(fmt.Sprintf("%s - 权限变更: UID %d → %d\n", timeStr, histEvent.OldUid, histEvent.NewUid))
			case 2: // FILE_WRITE
				sb.WriteString(fmt.Sprintf("%s - 写入: %s\n", timeStr, histEvent.Filename))
			case 3: // OPENAT
				sb.WriteString(fmt.Sprintf("%s - 访问: %s\n", timeStr, histEvent.Filename))
			case 4: // CONNECT
				sb.WriteString(fmt.Sprintf("%s - 网络: 连接 %s:%d\n", timeStr, histEvent.DstAddr, histEvent.DstPort))
			case 5: // BIND
				sb.WriteString(fmt.Sprintf("%s - 网络: 绑定端口 %d\n", timeStr, histEvent.SrcPort))
			default:
				sb.WriteString(fmt.Sprintf("%s - 未知事件类型: %d\n", timeStr, histEvent.EventType))
			}
		}
	} else {
		sb.WriteString("无历史活动记录\n")
	}
	sb.WriteString("\n")

	// 关联进程
	sb.WriteString("🔗 关联进程\n")
	if report.RelatedProcesses.Parent != nil {
		sb.WriteString(fmt.Sprintf("父进程: %s (PID: %d)\n", report.RelatedProcesses.Parent.Comm, report.RelatedProcesses.Parent.Pid))
	} else {
		sb.WriteString("父进程: 无\n")
	}
	
	if len(report.RelatedProcesses.Children) > 0 {
		sb.WriteString("子进程:\n")
		for _, child := range report.RelatedProcesses.Children {
			sb.WriteString(fmt.Sprintf("  - %s (PID: %d)\n", child.Comm, child.Pid))
		}
	} else {
		sb.WriteString("子进程: 无\n")
	}
	sb.WriteString("\n")

	// 统计信息
	sb.WriteString("📊 统计信息\n")
	sb.WriteString(fmt.Sprintf("总系统调用: %d次\n", report.Statistics.TotalSyscalls))
	sb.WriteString(fmt.Sprintf("敏感文件访问: %d次\n", report.Statistics.SensitiveFileAccess))
	sb.WriteString(fmt.Sprintf("网络连接: %d次\n", report.Statistics.NetworkConnections))
	sb.WriteString("\n")

	// 分析结论
	sb.WriteString("💡 分析结论\n")
	sb.WriteString(report.AnalysisConclusion)
	sb.WriteString("\n")

	return sb.String()
}

// generateMarkdownReport 生成Markdown格式报告
func (frg *ForensicReportGenerator) generateMarkdownReport(report ForensicReport, event ProcessEventWithRisk) string {
	var sb strings.Builder

	sb.WriteString("## 提权事件取证报告\n\n")

	// 事件概要
	sb.WriteString("### 🔍 事件概要\n\n")
	sb.WriteString("| 字段 | 值 |\n")
	sb.WriteString("|------|-----|\n")
	sb.WriteString(fmt.Sprintf("| 时间 | %s |\n", report.EventSummary.Timestamp))
	sb.WriteString(fmt.Sprintf("| 进程 | %s (PID: %d) |\n", report.EventSummary.ProcessName, report.EventSummary.PID))
	sb.WriteString(fmt.Sprintf("| 用户 | %s (UID: %d → %d) |\n", report.EventSummary.User, event.OldUid, event.NewUid))
	sb.WriteString(fmt.Sprintf("| 风险等级 | %s |\n\n", report.EventSummary.RiskLevel))

	// 进程历史活动
	sb.WriteString("### 📋 进程历史活动 (前10分钟)\n\n")
	if len(report.ProcessHistory) > 0 {
		sb.WriteString("| 时间 | 类型 | 详情 |\n")
		sb.WriteString("|------|------|------|\n")
		for _, histEvent := range report.ProcessHistory {
			eventTime := time.Unix(0, int64(histEvent.Timestamp))
			timeStr := eventTime.Format("15:04:05")
			
			var eventType, detail string
			switch histEvent.EventType {
			case 0: // EXECVE
				eventType = "执行"
				detail = histEvent.Filename
			case 1: // SETUID
				eventType = "权限变更"
				detail = fmt.Sprintf("UID %d → %d", histEvent.OldUid, histEvent.NewUid)
			case 2: // FILE_WRITE
				eventType = "写入"
				detail = histEvent.Filename
			case 3: // OPENAT
				eventType = "访问"
				detail = histEvent.Filename
			case 4: // CONNECT
				eventType = "网络连接"
				detail = fmt.Sprintf("连接 %s:%d", histEvent.DstAddr, histEvent.DstPort)
			case 5: // BIND
				eventType = "网络绑定"
				detail = fmt.Sprintf("绑定端口 %d", histEvent.SrcPort)
			default:
				eventType = "未知"
				detail = fmt.Sprintf("类型: %d", histEvent.EventType)
			}
			sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n", timeStr, eventType, detail))
		}
	} else {
		sb.WriteString("*无历史活动记录*\n")
	}
	sb.WriteString("\n")

	// 关联进程
	sb.WriteString("### 🔗 关联进程\n\n")
	if report.RelatedProcesses.Parent != nil {
		sb.WriteString(fmt.Sprintf("- **父进程**: %s (PID: %d)\n", report.RelatedProcesses.Parent.Comm, report.RelatedProcesses.Parent.Pid))
	} else {
		sb.WriteString("- **父进程**: 无\n")
	}
	
	if len(report.RelatedProcesses.Children) > 0 {
		sb.WriteString("\n**子进程**:\n")
		for _, child := range report.RelatedProcesses.Children {
			sb.WriteString(fmt.Sprintf("  - %s (PID: %d)\n", child.Comm, child.Pid))
		}
	} else {
		sb.WriteString("\n- **子进程**: 无\n")
	}
	sb.WriteString("\n")

	// 统计信息
	sb.WriteString("### 📊 统计信息\n\n")
	sb.WriteString("| 指标 | 数值 |\n")
	sb.WriteString("|------|------|\n")
	sb.WriteString(fmt.Sprintf("| 总系统调用 | %d次 |\n", report.Statistics.TotalSyscalls))
	sb.WriteString(fmt.Sprintf("| 敏感文件访问 | %d次 |\n", report.Statistics.SensitiveFileAccess))
	sb.WriteString(fmt.Sprintf("| 网络连接 | %d次 |\n\n", report.Statistics.NetworkConnections))

	// 分析结论
	sb.WriteString("### 💡 分析结论\n\n")
	sb.WriteString(report.AnalysisConclusion)
	sb.WriteString("\n\n")

	// 生成时间
	sb.WriteString("---\n")
	sb.WriteString(fmt.Sprintf("*报告生成时间: %s*", report.GeneratedAt.Format("2006-01-02 15:04:05")))

	return sb.String()
}

// generateAnalysisConclusion 生成分析结论
func (frg *ForensicReportGenerator) generateAnalysisConclusion(event ProcessEventWithRisk, timeline []ProcessEventWithRisk, stats *ProcessStatistics) string {
	var conclusions []string

	// 检查是否有可疑的信息收集活动
	suspiciousActivity := 0
	for _, histEvent := range timeline {
		if histEvent.EventType == 3 && (strings.Contains(histEvent.Filename, ".ssh") ||
			strings.Contains(histEvent.Filename, ".key") ||
			strings.Contains(histEvent.Filename, "/etc/passwd")) {
			suspiciousActivity++
		}
	}

	if suspiciousActivity > 0 {
		conclusions = append(conclusions, fmt.Sprintf("该提权行为前发现 %d 次可疑的信息收集活动", suspiciousActivity))
	}

	// 检查是否有网络连接
	if stats.NetworkConnections > 0 {
		conclusions = append(conclusions, fmt.Sprintf("进程在提权前有 %d 次网络连接，可能涉及数据传输或远程控制", stats.NetworkConnections))
	}

	// 检查敏感文件访问
	if stats.SensitiveFileAccess > 0 {
		conclusions = append(conclusions, fmt.Sprintf("进程访问了 %d 个敏感文件，存在数据泄露风险", stats.SensitiveFileAccess))
	}

	// 检查系统调用频率
	if stats.TotalSyscalls > 100 {
		conclusions = append(conclusions, fmt.Sprintf("进程在短时间内执行了 %d 次系统调用，活动较为频繁", stats.TotalSyscalls))
	}

	// 检查是否有子进程
	if len(event.Comm) > 0 && (event.Comm == "sudo" || event.Comm == "su") {
		conclusions = append(conclusions, "使用 sudo/su 命令进行提权，属于常见的提权方式")
	}

	// 如果没有发现任何可疑行为
	if len(conclusions) == 0 {
		conclusions = append(conclusions, "未发现明显的可疑行为，建议持续监控")
	}

	return strings.Join(conclusions, "；")
}

// GenerateBatchReports 批量生成报告
func (frg *ForensicReportGenerator) GenerateBatchReports(eventIDs []int, format ReportFormat) ([]interface{}, error) {
	var reports []interface{}

	for _, eventID := range eventIDs {
		report, err := frg.GenerateReport(eventID, format)
		if err != nil {
			return nil, fmt.Errorf("failed to generate report for event %d: %w", eventID, err)
		}
		reports = append(reports, report)
	}

	return reports, nil
}

// ExportReportToFile 导出报告到文件
func (frg *ForensicReportGenerator) ExportReportToFile(eventID int, format ReportFormat, filePath string) error {
	report, err := frg.GenerateReport(eventID, format)
	if err != nil {
		return err
	}

	var content string
	switch format {
	case FormatText, FormatMarkdown:
		content = report.(string)
	case FormatJSON:
		jsonData, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		content = string(jsonData)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}

	// 写入文件（这里简化处理，实际应该使用文件写入）
	fmt.Printf("报告内容已准备导出到: %s\n", filePath)
	fmt.Println(content)
	
	return nil
}