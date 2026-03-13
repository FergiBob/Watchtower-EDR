package logs

import (
	"io"
	"log/slog"
	"os"

	"gopkg.in/natefinch/lumberjack.v2" // Used to maintain a rolling file logger to conserve space and efficiency long-term
)

// InitLogger() initializes the configuration to be used for slog for the purposes of logging.
// It utilizes both a log file (watchtower.log) as well as the standard console logging for quick and easy debugging
func InitLogger() {

	// sets up the file properties in lumberjack
	file := &lumberjack.Logger{
		Filename:   "./internal/logs/watchtower.log",
		MaxSize:    50, //MB
		MaxBackups: 8,
		MaxAge:     0,    //default (logs do not age out by days)
		Compress:   true, //old logs will be compressed to save space
	}

	//sets the multiwriter to write to the watchtower.log and the standard console
	multiWriter := io.MultiWriter(os.Stdout, file)

	//creates the slog handler with minimum log level set to info
	handler := slog.NewTextHandler(multiWriter, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})

	//set the default logging method to the multihander established above
	logger := slog.New(handler)
	slog.SetDefault(logger)

}
