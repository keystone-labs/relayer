package middleware

import (
    "net/http"
    "strings"
    "time"

    "github.com/keystone-labs/sui-stablecoin/relayer/logging"
)

// AuthMiddleware handles authentication and authorization
type AuthMiddleware struct {
    logger *logging.Logger
    apiKey string
    allowedIPs []string
}

// NewAuthMiddleware creates a new auth middleware
func NewAuthMiddleware(logger *logging.Logger, apiKey string, allowedIPs []string) *AuthMiddleware {
    return &AuthMiddleware{
        logger: logger,
        apiKey: apiKey,
        allowedIPs: allowedIPs,
    }
}

// Authenticate verifies API key and IP whitelist
func (m *AuthMiddleware) Authenticate(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Get API key from header
        apiKey := r.Header.Get("X-API-Key")
        if apiKey == "" {
            m.logger.Warn("Missing API key", nil)
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        // Verify API key
        if !m.verifyAPIKey(apiKey) {
            m.logger.Warn("Invalid API key", map[string]interface{}{
                "provided_key": maskString(apiKey),
            })
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        // Check IP whitelist
        clientIP := getClientIP(r)
        if !m.isIPAllowed(clientIP) {
            m.logger.Warn("IP not whitelisted", map[string]interface{}{
                "ip": clientIP,
            })
            http.Error(w, "Forbidden", http.StatusForbidden)
            return
        }

        // Add auth info to context
        ctx := r.Context()
        ctx = context.WithValue(ctx, "client_ip", clientIP)
        ctx = context.WithValue(ctx, "api_key", apiKey)

        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

// Helper functions

func (m *AuthMiddleware) verifyAPIKey(apiKey string) bool {
    return subtle.ConstantTimeCompare([]byte(apiKey), []byte(m.apiKey)) == 1
}

func (m *AuthMiddleware) isIPAllowed(ip string) bool {
    for _, allowed := range m.allowedIPs {
        if ip == allowed {
            return true
        }
    }
    return false
}

func getClientIP(r *http.Request) string {
    // Check X-Forwarded-For header
    forwarded := r.Header.Get("X-Forwarded-For")
    if forwarded != "" {
        return strings.Split(forwarded, ",")[0]
    }
    // Fall back to RemoteAddr
    return strings.Split(r.RemoteAddr, ":")[0]
}

func maskString(s string) string {
    if len(s) <= 8 {
        return "***"
    }
    return s[:4] + "..." + s[len(s)-4:]
}
