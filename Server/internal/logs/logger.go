package logs

import (
	"bufio"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/svc"
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

var logDir string

func InitLogger(baseDir string) {
	targetDir := filepath.Join(baseDir, "internal", "data", "logs")
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return //
	}

	logDir = filepath.Join(targetDir, "watchtower.log")

	fileLogger := &lumberjack.Logger{
		Filename:   logDir,
		MaxSize:    50,
		MaxBackups: 8,
		Compress:   true,
	} //

	// Create the writer based on the environment
	var writer io.Writer
	isService, _ := svc.IsWindowsService()

	if isService {
		// Services don't have an Stdout. Use only the file.
		writer = fileLogger
	} else {
		// Interactive mode: write to both
		writer = io.MultiWriter(os.Stdout, fileLogger)
	}

	handler := slog.NewTextHandler(writer, &slog.HandlerOptions{
		Level: slog.LevelInfo,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{Key: "time", Value: slog.StringValue(a.Value.Time().Format("2006-01-02 15:04:05"))}
			}
			return a
		},
	}) //[cite: 1]

	base := slog.New(handler)
	slog.SetDefault(base)

	// Re-assign the categorized loggers to the new base
	Sys = base.With("type", "system")
	Auth = base.With("type", "auth")
	Audit = base.With("type", "audit")
	Agent = base.With("type", "agent")
	Net = base.With("type", "network")
	Web = base.With("type", "web")
	DB = base.With("type", "database")
	Sync = base.With("type", "nvd_sync")
	Map = base.With("type", "mapper") //[cite: 1]

	// CRITICAL: Write an immediate "Startup" log to force lumberjack to flush to disk
	Sys.Info("Logging system initialized", "mode", map[bool]string{true: "service", false: "interactive"}[isService])
}

func GetTailLogs(lineCount int) (string, error) {
	if logDir == "" {
		return "Logger not initialized", nil
	}

	file, err := os.Open(logDir)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		if len(lines) > lineCount {
			lines = lines[1:]
		}
	}
	return strings.Join(lines, "\n"), scanner.Err()
}
