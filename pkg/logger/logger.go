package logger

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// sensitiveKeys 是 zap 字段名黑名单 — 命中后字段值会被替换为 "****"。
// 大小写不敏感,前后缀匹配(例如 "auth" 会命中 "Authorization")。
var sensitiveKeys = []string{
	"password", "passwd", "pwd",
	"token", "auth", "authorization", "bearer",
	"cookie", "session",
	"secret", "api_key", "apikey", "key_hash",
	"aes", "private_key",
	"dsn",
}

// isSensitive 判断 zap Field 的 Key 是否命中脱敏黑名单。
func isSensitive(key string) bool {
	lk := strings.ToLower(key)
	for _, bad := range sensitiveKeys {
		if strings.Contains(lk, bad) {
			return true
		}
	}
	return false
}

// redactCore 包装 zapcore.Core,在 Write 前把敏感字段替换为 "****"。
type redactCore struct {
	zapcore.Core
}

func (r *redactCore) With(fields []zapcore.Field) zapcore.Core {
	return &redactCore{Core: r.Core.With(redactFields(fields))}
}

func (r *redactCore) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if r.Enabled(ent.Level) {
		return ce.AddCore(ent, r)
	}
	return ce
}

func (r *redactCore) Write(ent zapcore.Entry, fields []zapcore.Field) error {
	return r.Core.Write(ent, redactFields(fields))
}

func redactFields(fields []zapcore.Field) []zapcore.Field {
	out := make([]zapcore.Field, len(fields))
	for i, f := range fields {
		if isSensitive(f.Key) {
			out[i] = zap.String(f.Key, "****")
			continue
		}
		out[i] = f
	}
	return out
}

var (
	global *zap.Logger
	once   sync.Once
)

// Init 初始化全局日志。format=console|json,output=stdout|<file path>.
func Init(level, format, output string) error {
	var initErr error
	once.Do(func() {
		lvl := zapcore.InfoLevel
		if err := lvl.UnmarshalText([]byte(level)); err != nil {
			initErr = fmt.Errorf("invalid log level %q: %w", level, err)
			return
		}

		encCfg := zap.NewProductionEncoderConfig()
		encCfg.TimeKey = "ts"
		encCfg.EncodeTime = zapcore.ISO8601TimeEncoder
		encCfg.EncodeDuration = zapcore.StringDurationEncoder
		encCfg.EncodeLevel = zapcore.CapitalLevelEncoder

		var encoder zapcore.Encoder
		if format == "json" {
			encoder = zapcore.NewJSONEncoder(encCfg)
		} else {
			encCfg.EncodeLevel = zapcore.CapitalColorLevelEncoder
			encoder = zapcore.NewConsoleEncoder(encCfg)
		}

		var ws zapcore.WriteSyncer
		if output == "" || output == "stdout" {
			ws = zapcore.AddSync(os.Stdout)
		} else {
			f, err := os.OpenFile(output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
			if err != nil {
				initErr = fmt.Errorf("open log file %q: %w", output, err)
				return
			}
			ws = zapcore.AddSync(f)
		}

		core := zapcore.NewCore(encoder, ws, lvl)
		// redactCore 放在外层,所有走 zap 的日志字段都会被脱敏过滤。
		global = zap.New(&redactCore{Core: core}, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
	})
	return initErr
}

// L 返回全局 logger。
func L() *zap.Logger {
	if global == nil {
		// 兜底:未初始化时返回开发 logger,避免 panic。
		l, _ := zap.NewDevelopment()
		return l
	}
	return global
}

// Sync 刷新缓冲。
func Sync() {
	if global != nil {
		_ = global.Sync()
	}
}
