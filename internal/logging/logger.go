package logging

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"os"
	"runtime/debug"
	"sync"
	"time"
)

type Environment struct {
	Service    string
	Version    string
	Commit     string
	Region     string
	MachineID  string
	PrecinctID string
}

type ctxKey struct{}

type RequestFields struct {
	mu     sync.Mutex
	fields map[string]any
}

func NewJSONLogger() *slog.Logger {
	h := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	return slog.New(h)
}

func Middleware(logger *slog.Logger, env Environment) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			reqID := r.Header.Get("X-Request-ID")
			if reqID == "" {
				reqID = randomRequestID()
			}
			fields := &RequestFields{fields: map[string]any{}}
			ctx := context.WithValue(r.Context(), ctxKey{}, fields)
			r = r.WithContext(ctx)

			ww := &statusWriter{ResponseWriter: w, statusCode: http.StatusOK}
			panicVal := any(nil)

			func() {
				defer func() {
					if recovered := recover(); recovered != nil {
						panicVal = recovered
						ww.statusCode = http.StatusInternalServerError
						http.Error(ww, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
						AddField(r.Context(), "panic", true)
						AddField(r.Context(), "stack", string(debug.Stack()))
					}
				}()
				next.ServeHTTP(ww, r)
			}()

			event := map[string]any{
				"timestamp":     time.Now().UTC().Format(time.RFC3339Nano),
				"service":       env.Service,
				"version":       env.Version,
				"commit":        env.Commit,
				"region":        env.Region,
				"machine_id":    env.MachineID,
				"precinct_id":   env.PrecinctID,
				"request_id":    reqID,
				"method":        r.Method,
				"path":          r.URL.Path,
				"remote_addr":   r.RemoteAddr,
				"user_agent":    r.UserAgent(),
				"status_code":   ww.statusCode,
				"duration_ms":   time.Since(start).Milliseconds(),
				"response_size": ww.bytes,
			}
			if ww.statusCode >= 500 {
				event["outcome"] = "error"
			} else {
				event["outcome"] = "success"
			}
			for k, v := range snapshotFields(fields) {
				event[k] = v
			}
			logger.Info("http_request", slog.Any("event", event))

			if panicVal != nil {
				panic(panicVal)
			}
		})
	}
}

func AddField(ctx context.Context, key string, value any) {
	fields, ok := ctx.Value(ctxKey{}).(*RequestFields)
	if !ok || fields == nil {
		return
	}
	fields.mu.Lock()
	defer fields.mu.Unlock()
	fields.fields[key] = value
}

func snapshotFields(fields *RequestFields) map[string]any {
	if fields == nil {
		return nil
	}
	fields.mu.Lock()
	defer fields.mu.Unlock()
	out := make(map[string]any, len(fields.fields))
	for k, v := range fields.fields {
		out[k] = v
	}
	return out
}

type statusWriter struct {
	http.ResponseWriter
	statusCode int
	bytes      int
}

func (w *statusWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *statusWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	w.bytes += n
	return n, err
}

func randomRequestID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "req_unknown"
	}
	return "req_" + hex.EncodeToString(buf)
}
