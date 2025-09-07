package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

type SecureVMTerminalProxy struct {
	config         *Config
	sessions       map[string]*SecureTerminalSession
	sessionsMutex  sync.RWMutex
	sshManager     *SecureSSHManager
	vmDiscovery    *VMDiscoveryService
	userSessions   map[string]int // Track sessions per user
	userMutex      sync.RWMutex
	cleanupTicker  *time.Ticker
	ctx            context.Context
	cancel         context.CancelFunc
}

type SecureTerminalSession struct {
	ID              string
	UserID          string
	VMIP            string
	PTY             *os.File
	Cmd             *exec.Cmd
	SSHSession      *ssh.Session
	SSHConn         *ssh.Client
	CreatedAt       time.Time
	LastActivity    time.Time
	IsActive        bool
	mutex           sync.RWMutex
	buffer          *CircularBuffer
	maxIdleTime     time.Duration
}

type CircularBuffer struct {
	data     []byte
	size     int
	start    int
	end      int
	full     bool
	mutex    sync.RWMutex
}

func NewCircularBuffer(size int) *CircularBuffer {
	return &CircularBuffer{
		data: make([]byte, size),
		size: size,
	}
}

func (cb *CircularBuffer) Write(p []byte) (n int, err error) {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	n = len(p)
	for _, b := range p {
		cb.data[cb.end] = b
		cb.end = (cb.end + 1) % cb.size
		
		if cb.full {
			cb.start = (cb.start + 1) % cb.size
		}
		
		if cb.end == cb.start {
			cb.full = true
		}
	}
	return n, nil
}

func (cb *CircularBuffer) Read(p []byte) (n int, err error) {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()

	if cb.start == cb.end && !cb.full {
		return 0, io.EOF
	}

	for n < len(p) && (cb.start != cb.end || cb.full) {
		p[n] = cb.data[cb.start]
		cb.start = (cb.start + 1) % cb.size
		cb.full = false
		n++
	}
	return n, nil
}

func NewSecureVMTerminalProxy(config *Config) (*SecureVMTerminalProxy, error) {
	ctx, cancel := context.WithCancel(context.Background())
	
	sshManager, err := NewSecureSSHManager(config)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create SSH manager: %w", err)
	}

	proxy := &SecureVMTerminalProxy{
		config:       config,
		sessions:     make(map[string]*SecureTerminalSession),
		userSessions: make(map[string]int),
		sshManager:   sshManager,
		vmDiscovery:  NewVMDiscoveryService(config),
		ctx:          ctx,
		cancel:       cancel,
	}

	// Start cleanup routine
	proxy.startCleanupRoutine()

	return proxy, nil
}

func (p *SecureVMTerminalProxy) HandleWebSocket(conn *websocket.Conn, sessionID, userID string) error {
	// Validate session limits
	if !p.checkSessionLimits(userID) {
		return fmt.Errorf("session limit exceeded for user %s", userID)
	}

	// Discover VM IP
	vmIP, err := p.vmDiscovery.DiscoverVMIP(p.ctx)
	if err != nil {
		return fmt.Errorf("failed to discover VM IP: %w", err)
	}

	// Create or get terminal session
	session, err := p.getOrCreateSession(sessionID, userID, vmIP)
	if err != nil {
		return fmt.Errorf("failed to create terminal session: %w", err)
	}

	defer p.updateUserSessionCount(userID, -1)

	// Handle bidirectional communication with timeout
	sessionCtx, sessionCancel := context.WithTimeout(p.ctx, p.config.MaxSessionDuration)
	defer sessionCancel()

	return p.handleSessionCommunication(sessionCtx, conn, session)
}

func (p *SecureVMTerminalProxy) checkSessionLimits(userID string) bool {
	p.userMutex.RLock()
	defer p.userMutex.RUnlock()

	// Check per-user session limit
	if count := p.userSessions[userID]; count >= p.config.MaxSessionsPerUser {
		log.Printf("User %s has reached session limit (%d)", userID, p.config.MaxSessionsPerUser)
		return false
	}

	// Check global session limit
	p.sessionsMutex.RLock()
	totalSessions := len(p.sessions)
	p.sessionsMutex.RUnlock()

	if totalSessions >= p.config.MaxConcurrentSessions {
		log.Printf("Global session limit reached (%d)", p.config.MaxConcurrentSessions)
		return false
	}

	return true
}

func (p *SecureVMTerminalProxy) updateUserSessionCount(userID string, delta int) {
	p.userMutex.Lock()
	defer p.userMutex.Unlock()

	p.userSessions[userID] += delta
	if p.userSessions[userID] <= 0 {
		delete(p.userSessions, userID)
	}
}

func (p *SecureVMTerminalProxy) getOrCreateSession(sessionID, userID, vmIP string) (*SecureTerminalSession, error) {
	p.sessionsMutex.Lock()
	defer p.sessionsMutex.Unlock()

	// Check if session already exists
	if session, exists := p.sessions[sessionID]; exists {
		session.mutex.Lock()
		session.LastActivity = time.Now()
		session.IsActive = true
		session.mutex.Unlock()
		log.Printf("Reusing existing session %s for user %s", sessionID, userID)
		return session, nil
	}

	// Create new session
	session, err := p.createNewSession(sessionID, userID, vmIP)
	if err != nil {
		return nil, err
	}

	p.sessions[sessionID] = session
	p.updateUserSessionCount(userID, 1)

	log.Printf("Created new session %s for user %s to VM %s", sessionID, userID, vmIP)
	return session, nil
}

func (p *SecureVMTerminalProxy) createNewSession(sessionID, userID, vmIP string) (*SecureTerminalSession, error) {
	session := &SecureTerminalSession{
		ID:           sessionID,
		UserID:       userID,
		VMIP:         vmIP,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
		IsActive:     true,
		buffer:       NewCircularBuffer(p.config.MaxBufferSize),
		maxIdleTime:  p.config.SessionTimeout,
	}

	// Try to connect to VM via SSH first
	if vmIP != "" {
		sshConn, err := p.sshManager.ConnectToVM(vmIP)
		if err != nil {
			log.Printf("Failed to connect to VM %s via SSH: %v. Creating local session.", vmIP, err)
		} else {
			// Create SSH session
			sshSession, err := sshConn.NewSession()
			if err != nil {
				log.Printf("Failed to create SSH session: %v. Creating local session.", err)
				sshConn.Close()
			} else {
				// Set up SSH session
				if err := p.setupSSHSession(session, sshSession, sshConn); err != nil {
					log.Printf("Failed to setup SSH session: %v. Creating local session.", err)
					sshSession.Close()
					sshConn.Close()
				} else {
					return session, nil
				}
			}
		}
	}

	// Fallback to local session
	if err := p.setupLocalSession(session); err != nil {
		return nil, fmt.Errorf("failed to create local session: %w", err)
	}

	return session, nil
}

func (p *SecureVMTerminalProxy) setupSSHSession(session *SecureTerminalSession, sshSession *ssh.Session, sshConn *ssh.Client) error {
	// Request a pseudo terminal
	if err := sshSession.RequestPty("xterm", 80, 24, ssh.TerminalModes{
		ssh.ECHO:          1,     // enable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}); err != nil {
		return fmt.Errorf("failed to request pty: %w", err)
	}

	// Start shell
	if err := sshSession.Shell(); err != nil {
		return fmt.Errorf("failed to start shell: %w", err)
	}

	session.SSHSession = sshSession
	session.SSHConn = sshConn
	
	log.Printf("SSH session established for session %s to VM %s", session.ID, session.VMIP)
	return nil
}

func (p *SecureVMTerminalProxy) setupLocalSession(session *SecureTerminalSession) error {
	// Create local terminal as fallback
	cmd := exec.Command("/bin/bash")
	cmd.Env = append(os.Environ(), 
		"TERM=xterm",
		"DOZLAB_SESSION_ID="+session.ID,
		"DOZLAB_USER_ID="+session.UserID,
	)

	ptmx, err := pty.Start(cmd)
	if err != nil {
		return fmt.Errorf("failed to start local pty: %w", err)
	}

	session.PTY = ptmx
	session.Cmd = cmd
	
	log.Printf("Local session created for session %s", session.ID)
	return nil
}

func (p *SecureVMTerminalProxy) handleSessionCommunication(ctx context.Context, conn *websocket.Conn, session *SecureTerminalSession) error {
	done := make(chan error, 2)

	// Session -> WebSocket (terminal output to browser)
	go func() {
		defer func() { done <- nil }()
		
		var reader io.Reader
		if session.SSHSession != nil {
			stdout, err := session.SSHSession.StdoutPipe()
			if err != nil {
				done <- fmt.Errorf("failed to get SSH stdout: %w", err)
				return
			}
			reader = stdout
		} else if session.PTY != nil {
			reader = session.PTY
		} else {
			done <- fmt.Errorf("no valid session reader available")
			return
		}
		
		buffer := make([]byte, 1024)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				// Set read timeout
				if session.PTY != nil {
					session.PTY.SetReadDeadline(time.Now().Add(1 * time.Second))
				}
				
				n, err := reader.Read(buffer)
				if err != nil {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						continue // Timeout is expected
					}
					if err != io.EOF {
						log.Printf("Session read error for %s: %v", session.ID, err)
					}
					return
				}

				// Update activity and write to buffer
				session.mutex.Lock()
				session.LastActivity = time.Now()
				session.buffer.Write(buffer[:n])
				session.mutex.Unlock()

				// Send to WebSocket
				msg := WSMessage{
					Type: "output",
					Data: string(buffer[:n]),
				}

				if err := conn.WriteJSON(msg); err != nil {
					log.Printf("WebSocket write error for session %s: %v", session.ID, err)
					return
				}
			}
		}
	}()

	// WebSocket -> Session (browser input to terminal)
	go func() {
		defer func() { done <- nil }()
		
		var writer io.Writer
		if session.SSHSession != nil {
			stdin, err := session.SSHSession.StdinPipe()
			if err != nil {
				done <- fmt.Errorf("failed to get SSH stdin: %w", err)
				return
			}
			writer = stdin
		} else if session.PTY != nil {
			writer = session.PTY
		} else {
			done <- fmt.Errorf("no valid session writer available")
			return
		}
		
		for {
			select {
			case <-ctx.Done():
				return
			default:
				var msg WSMessage
				if err := conn.ReadJSON(&msg); err != nil {
					log.Printf("WebSocket read error for session %s: %v", session.ID, err)
					return
				}

				// Update activity
				session.mutex.Lock()
				session.LastActivity = time.Now()
				session.mutex.Unlock()

				switch msg.Type {
				case "input":
					if _, err := writer.Write([]byte(msg.Data)); err != nil {
						log.Printf("Session write error for %s: %v", session.ID, err)
						return
					}
				case "resize":
					if err := p.resizeSession(session, msg.Cols, msg.Rows); err != nil {
						log.Printf("Session resize error for %s: %v", session.ID, err)
					}
				}
			}
		}
	}()

	// Wait for either direction to close or timeout
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return fmt.Errorf("session timeout")
	}
}

func (p *SecureVMTerminalProxy) resizeSession(session *SecureTerminalSession, cols, rows int) error {
	// Resize SSH session
	if session.SSHSession != nil {
		return session.SSHSession.WindowChange(rows, cols)
	}

	// Resize local PTY
	if session.PTY != nil {
		return p.resizePTY(session.PTY, cols, rows)
	}

	return fmt.Errorf("no session to resize")
}

func (p *SecureVMTerminalProxy) resizePTY(ptmx *os.File, cols, rows int) error {
	type winsize struct {
		Row    uint16
		Col    uint16
		Xpixel uint16
		Ypixel uint16
	}

	ws := winsize{
		Row: uint16(rows),
		Col: uint16(cols),
	}

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		ptmx.Fd(),
		syscall.TIOCSWINSZ,
		uintptr(unsafe.Pointer(&ws)),
	)

	if errno != 0 {
		return fmt.Errorf("failed to resize pty: %v", errno)
	}

	return nil
}

func (p *SecureVMTerminalProxy) startCleanupRoutine() {
	p.cleanupTicker = time.NewTicker(p.config.CleanupInterval)
	
	go func() {
		for {
			select {
			case <-p.cleanupTicker.C:
				p.cleanupIdleSessions()
			case <-p.ctx.Done():
				return
			}
		}
	}()
}

func (p *SecureVMTerminalProxy) cleanupIdleSessions() {
	p.sessionsMutex.Lock()
	defer p.sessionsMutex.Unlock()

	now := time.Now()
	var toRemove []string

	for sessionID, session := range p.sessions {
		session.mutex.RLock()
		idle := now.Sub(session.LastActivity) > session.maxIdleTime
		session.mutex.RUnlock()

		if idle {
			log.Printf("Cleaning up idle session: %s", sessionID)
			p.cleanupSession(session)
			toRemove = append(toRemove, sessionID)
		}
	}

	// Remove cleaned up sessions
	for _, sessionID := range toRemove {
		if session := p.sessions[sessionID]; session != nil {
			p.updateUserSessionCount(session.UserID, -1)
		}
		delete(p.sessions, sessionID)
	}

	if len(toRemove) > 0 {
		log.Printf("Cleaned up %d idle sessions", len(toRemove))
	}
}

func (p *SecureVMTerminalProxy) cleanupSession(session *SecureTerminalSession) {
	session.mutex.Lock()
	defer session.mutex.Unlock()

	session.IsActive = false

	// Close SSH session
	if session.SSHSession != nil {
		session.SSHSession.Close()
		session.SSHSession = nil
	}

	// Note: SSH connection is managed by pool, don't close here

	// Close local PTY
	if session.PTY != nil {
		session.PTY.Close()
		session.PTY = nil
	}

	// Kill local process
	if session.Cmd != nil && session.Cmd.Process != nil {
		session.Cmd.Process.Kill()
		session.Cmd = nil
	}
}

func (p *SecureVMTerminalProxy) GetSessionStats() map[string]interface{} {
	p.sessionsMutex.RLock()
	p.userMutex.RLock()
	defer p.sessionsMutex.RUnlock()
	defer p.userMutex.RUnlock()

	stats := map[string]interface{}{
		"total_sessions":     len(p.sessions),
		"max_sessions":       p.config.MaxConcurrentSessions,
		"sessions_per_user":  make(map[string]int),
		"vm_connections":     len(p.vmDiscovery.GetCachedVMs()),
	}

	// Copy user session counts
	userCounts := make(map[string]int)
	for userID, count := range p.userSessions {
		userCounts[userID] = count
	}
	stats["sessions_per_user"] = userCounts

	return stats
}

func (p *SecureVMTerminalProxy) Close() {
	p.cancel()
	
	if p.cleanupTicker != nil {
		p.cleanupTicker.Stop()
	}

	// Cleanup all sessions
	p.sessionsMutex.Lock()
	for _, session := range p.sessions {
		p.cleanupSession(session)
	}
	p.sessions = make(map[string]*SecureTerminalSession)
	p.sessionsMutex.Unlock()

	// Close SSH manager
	if p.sshManager != nil {
		p.sshManager.Close()
	}

	log.Println("Secure VM terminal proxy closed")
}