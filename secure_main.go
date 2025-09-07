package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

var secureUpgrader = websocket.Upgrader{
	HandshakeTimeout: 10 * time.Second,
	ReadBufferSize:   4096,
	WriteBufferSize:  4096,
	CheckOrigin:      checkOrigin, // Custom origin checker
}

var (
	config *Config
	proxy  *SecureVMTerminalProxy
)

func secureMain() {
	// Load configuration
	var err error
	config, err = LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	log.Printf("Starting secure terminal sidecar with config validation passed")

	// Create secure proxy
	proxy, err = NewSecureVMTerminalProxy(config)
	if err != nil {
		log.Fatalf("Failed to create secure proxy: %v", err)
	}
	defer proxy.Close()

	// Set up Gin with security
	if config.TLSCert != "" && config.TLSKey != "" {
		gin.SetMode(gin.ReleaseMode)
	}
	
	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())

	// Add security middleware
	router.Use(securityHeaders())
	
	if config.RequireAuth {
		router.Use(authMiddleware())
	}

	// Health check endpoint (no auth required)
	router.GET("/health", healthCheck)
	
	// Stats endpoint (auth required if enabled)
	router.GET("/stats", getStats)
	
	// Terminal WebSocket endpoint (auth required if enabled)
	router.GET("/terminal", handleSecureTerminalWebSocket)

	// Start server
	server := &http.Server{
		Addr:           config.Host + ":" + config.Port,
		Handler:        router,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1MB
	}

	if config.TLSCert != "" && config.TLSKey != "" {
		// Load TLS configuration
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		}
		server.TLSConfig = tlsConfig
		
		log.Printf("Starting secure terminal sidecar on https://%s:%s", config.Host, config.Port)
		log.Fatal(server.ListenAndServeTLS(config.TLSCert, config.TLSKey))
	} else {
		log.Printf("Starting terminal sidecar on http://%s:%s", config.Host, config.Port)
		log.Fatal(server.ListenAndServe())
	}
}

func checkOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // Allow requests without Origin header (for testing)
	}

	// Check against allowed origins
	for _, allowed := range config.AllowedOrigins {
		if origin == allowed {
			return true
		}
	}

	log.Printf("Blocked request from disallowed origin: %s", origin)
	return false
}

func securityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		
		if config.TLSCert != "" && config.TLSKey != "" {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		
		c.Next()
	}
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip auth for health check
		if c.Request.URL.Path == "/health" {
			c.Next()
			return
		}

		// Get token from header
		token := c.GetHeader(config.AuthTokenHeader)
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication required",
			})
			c.Abort()
			return
		}

		// Validate token (implement your token validation logic)
		userID, err := validateToken(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid authentication token",
			})
			c.Abort()
			return
		}

		// Set user ID in context
		c.Set("user_id", userID)
		c.Next()
	}
}

func validateToken(token string) (string, error) {
	// Implement your token validation logic here
	// This could be JWT validation, API key lookup, etc.
	
	// For now, accept any non-empty token and extract user ID
	if len(token) < 10 {
		return "", fmt.Errorf("token too short")
	}
	
	// Extract user ID from token (implement based on your auth system)
	parts := strings.Split(token, ":")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid token format")
	}
	
	return parts[1], nil // Return user ID part
}

func healthCheck(c *gin.Context) {
	stats := proxy.GetSessionStats()
	c.JSON(http.StatusOK, gin.H{
		"status":    "ok",
		"timestamp": time.Now().Unix(),
		"sessions":  stats["total_sessions"],
		"max_sessions": stats["max_sessions"],
	})
}

func getStats(c *gin.Context) {
	stats := proxy.GetSessionStats()
	c.JSON(http.StatusOK, stats)
}

func handleSecureTerminalWebSocket(c *gin.Context) {
	// Get session ID and user ID
	sessionID := c.Query("session_id")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "session_id parameter is required",
		})
		return
	}

	// Get user ID from context (set by auth middleware)
	userID := "anonymous"
	if uid, exists := c.Get("user_id"); exists {
		if uidStr, ok := uid.(string); ok {
			userID = uidStr
		}
	}

	// Upgrade to WebSocket
	conn, err := secureUpgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed for session %s: %v", sessionID, err)
		return
	}
	defer conn.Close()

	// Set connection timeouts
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetWriteDeadline(time.Now().Add(60 * time.Second))

	// Set up ping/pong to keep connection alive
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	// Start ping routine
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		
		for {
			select {
			case <-ticker.C:
				conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
					return
				}
			}
		}
	}()

	log.Printf("Secure terminal WebSocket connected for session: %s, user: %s", sessionID, userID)

	// Handle the session with comprehensive error handling
	err = proxy.HandleWebSocket(conn, sessionID, userID)
	if err != nil {
		log.Printf("Terminal proxy error for session %s: %v", sessionID, err)
		
		// Send error message to client before closing
		errorMsg := WSMessage{
			Type: "error",
			Data: fmt.Sprintf("Terminal session error: %v", err),
		}
		conn.WriteJSON(errorMsg)
	}

	log.Printf("Terminal WebSocket disconnected for session: %s", sessionID)
}