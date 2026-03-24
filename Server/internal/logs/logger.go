package logs

import (
	"io"
	"log/slog"
	"os"
	"strings"

	"gopkg.in/natefinch/lumberjack.v2" // Used to maintain a rolling file logger to conserve space and efficiency long-term
)

// InitLogger() initializes the configuration to be used for slog for the purposes of logging.
// It utilizes both a log file (watchtower.log) as well as the standard console logging for quick and easy debugging
func InitLogger() {
	file := &lumberjack.Logger{
		Filename:   "./internal/logs/watchtower.log", // path to file
		MaxSize:    50,                               // file size in MB
		MaxBackups: 8,                                // maximum number of backups
		Compress:   true,                             // compresses backups to zip file
	}

	multiWriter := io.MultiWriter(os.Stdout, file)

	handler := slog.NewTextHandler(multiWriter, &slog.HandlerOptions{
		Level: slog.LevelInfo,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Simplify Time: 2026-03-23 20:30:00
			if a.Key == slog.TimeKey {
				return slog.Attr{
					Key:   "time",
					Value: slog.StringValue(a.Value.Time().Format("2006-01-02 15:04:05")),
				}
			}
			// uppercase level for readability
			if a.Key == slog.LevelKey {
				return slog.Attr{
					Key:   "level",
					Value: slog.StringValue(a.Value.String()),
				}
			}
			return a
		},
	})

	slog.SetDefault(slog.New(handler))
}

func GetTailLogs(lineCount int) (string, error) {
	content, err := os.ReadFile("./internal/logs/watchtower.log")
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(content), "\n")
	if len(lines) > lineCount {
		lines = lines[len(lines)-lineCount:]
	}

	return strings.Join(lines, "\n"), nil
}
