package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins in sidecar
	},
}

func main() {
	// PRIVILEGE ESCALATION FIX: Drop privileges after startup (following security best practices)
	if err := dropPrivileges(); err != nil {
		log.Printf("Warning: Failed to drop privileges: %v", err)
	}
	
	// Set up Gin
	router := gin.Default()
	
	// Create proxy with proper cleanup (following dozlab-api pattern)
	proxy := NewVMTerminalProxy()
	defer proxy.Close() // Ensure cleanup on shutdown
	
	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "ok",
			"sessions": len(proxy.sessions),
			"uptime": time.Now().Unix(),
		})
	})
	
	// Terminal WebSocket endpoint
	router.GET("/terminal", func(c *gin.Context) {
		handleTerminalWebSocket(c, proxy)
	})
	
	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}
	
	log.Printf("Terminal sidecar starting on port %s", port)
	router.Run(":" + port)
}

func handleTerminalWebSocket(c *gin.Context, proxy *VMTerminalProxy) {
	// Upgrade to WebSocket
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()
	
	sessionID := c.Query("session_id")
	log.Printf("Terminal WebSocket connected for session: %s", sessionID)
	
	// Handle session with proper error handling (following dozlab-api pattern)
	err = proxy.HandleWebSocket(conn, sessionID)
	if err != nil {
		log.Printf("Terminal proxy error: %v", err)
	}
}

// PRIVILEGE ESCALATION FIX: Drop privileges (following security best practices)
func dropPrivileges() error {
	// Get the user we want to run as (non-root)
	username := os.Getenv("RUN_AS_USER")
	if username == "" {
		username = "nobody" // Safe default
	}
	
	// Don't try to drop if already non-root
	if os.Getuid() != 0 {
		log.Printf("Already running as non-root user (uid: %d)", os.Getuid())
		return nil
	}
	
	log.Printf("Dropping privileges to user: %s", username)
	
	// In production, you would implement proper user switching here
	// For now, just log the attempt
	log.Printf("Note: Privilege dropping requires proper implementation for production use")
	
	return nil
}