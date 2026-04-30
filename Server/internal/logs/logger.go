package logs

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/natefinch/lumberjack.v2"
)

// Exported categorized loggers
var (
	Sys   *slog.Logger // System startup, config, and lifecycle
	Auth  *slog.Logger // Authentication, JWT, and security audits
	Audit *slog.Logger // Manual changes/Actions by users
	Agent *slog.Logger // Agent enrollment and telemetry
	Net   *slog.Logger // TLS, Certificates, and Server middleware
	Web   *slog.Logger // UI rendering and dashboard data
	DB    *slog.Logger // Database connections and queries
	Sync  *slog.Logger // NVD API synchronization
	Map   *slog.Logger // CVE/CPE correlation alerts
)

var filePath string

func InitLogger(baseDir string) {

	filePath = filepath.Join(baseDir, "internal", "data", "logs", "watchtower.log")
	file := &lumberjack.Logger{
		Filename:   filePath,
		MaxSize:    50,
		MaxBackups: 8,
		Compress:   true,
	}

	multiWriter := io.MultiWriter(os.Stdout, file)

	handler := slog.NewTextHandler(multiWriter, &slog.HandlerOptions{
		Level: slog.LevelInfo,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{Key: "time", Value: slog.StringValue(a.Value.Time().Format("2006-01-02 15:04:05"))}
			}
			return a
		},
	})

	base := slog.New(handler)
	slog.SetDefault(base)

	// Initialize categories
	Sys = base.With("type", "system")
	Auth = base.With("type", "auth")
	Audit = base.With("type", "audit")
	Agent = base.With("type", "agent")
	Net = base.With("type", "network")
	Web = base.With("type", "web")
	DB = base.With("type", "database")
	Sync = base.With("type", "nvd_sync")
	Map = base.With("type", "mapper")
}

func GetTailLogs(lineCount int) (string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(content), "\n")
	if len(lines) > lineCount {
		lines = lines[len(lines)-lineCount:]
	}

	return strings.Join(lines, "\n"), nil
}
