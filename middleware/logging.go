package middleware

import (
    "net/http"
    "time"

    "github.com/keystone-labs/sui-stablecoin/relayer/logging"
)

// SecurityLogger handles security-related logging
type SecurityLogger struct {
    logger *logging.Logger
}

// NewSecurityLogger creates a new security logger
func NewSecurityLogger(logger *logging.Logger) *SecurityLogger {
    return &SecurityLogger{
        logger: logger,
    }
}

// LogSecurityEvents logs security-relevant events
func (l *SecurityLogger) LogSecurityEvents(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        start := time.Now()

        // Create response wrapper to capture status code
        rw := &responseWriter{w, http.StatusOK}

        // Get auth info from context
        ctx := r.Context()
        clientIP := ctx.Value("client_ip").(string)
        apiKey := ctx.Value("api_key").(string)

        // Log request
        l.logger.Info("Security event - Request received", map[string]interface{}{
            "ip":          clientIP,
            "api_key":     maskString(apiKey),
            "method":      r.Method,
            "path":        r.URL.Path,
            "user_agent":  r.UserAgent(),
            "timestamp":   time.Now().UTC(),
        })

        next.ServeHTTP(rw, r)

        // Log response
        duration := time.Since(start)
        l.logger.Info("Security event - Response sent", map[string]interface{}{
            "ip":          clientIP,
            "status":      rw.status,
            "duration_ms": duration.Milliseconds(),
            "timestamp":   time.Now().UTC(),
        })

        // Log suspicious activity
        if rw.status >= http.StatusBadRequest {
            l.logger.Warn("Security event - Suspicious activity", map[string]interface{}{
                "ip":          clientIP,
                "status":      rw.status,
                "method":      r.Method,
                "path":        r.URL.Path,
                "user_agent":  r.UserAgent(),
                "timestamp":   time.Now().UTC(),
            })
        }
    })
}

// LogAuthEvents logs authentication events
func (l *SecurityLogger) LogAuthEvents(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        start := time.Now()

        // Create response wrapper
        rw := &responseWriter{w, http.StatusOK}

        // Get auth info
        apiKey := r.Header.Get("X-API-Key")
        clientIP := getClientIP(r)

        // Log auth attempt
        l.logger.Info("Security event - Auth attempt", map[string]interface{}{
            "ip":          clientIP,
            "api_key":     maskString(apiKey),
            "timestamp":   time.Now().UTC(),
        })

        next.ServeHTTP(rw, r)

        // Log auth result
        if rw.status == http.StatusUnauthorized {
            l.logger.Warn("Security event - Auth failure", map[string]interface{}{
                "ip":          clientIP,
                "timestamp":   time.Now().UTC(),
                "duration_ms": time.Since(start).Milliseconds(),
            })
        }
    })
}

// Helper types and functions

type responseWriter struct {
    http.ResponseWriter
    status int
}

func (rw *responseWriter) WriteHeader(status int) {
    rw.status = status
    rw.ResponseWriter.WriteHeader(status)
}

func maskString(s string) string {
    if len(s) <= 8 {
        return "***"
    }
    return s[:4] + "..." + s[len(s)-4:]
}
