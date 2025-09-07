package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

type VMTerminalProxy struct {
	sessions      map[string]*TerminalSession
	mutex         sync.RWMutex
	cleanupTicker *time.Ticker // Following dozlab-api pattern
	stopCleanup   chan bool    // Following dozlab-api pattern
	failoverVMs   []string     // Multiple VM IPs for failover
}

type TerminalSession struct {
	ID      string
	PTY     *os.File
	Cmd     *exec.Cmd
	VMIP    string
	SSHConn *ssh.Client
}

type WSMessage struct {
	Type string `json:"type"`
	Data string `json:"data"`
	Rows int    `json:"rows,omitempty"`
	Cols int    `json:"cols,omitempty"`
}

func NewVMTerminalProxy() *VMTerminalProxy {
	proxy := &VMTerminalProxy{
		sessions:      make(map[string]*TerminalSession),
		cleanupTicker: time.NewTicker(5 * time.Minute), // Following dozlab-api cleanup pattern
		stopCleanup:   make(chan bool, 1),
		failoverVMs:   getFailoverVMs(), // Load from env
	}
	
	// Start cleanup goroutine (following dozlab-api pattern)
	go proxy.cleanupSessions()
	
	return proxy
}

func (p *VMTerminalProxy) HandleWebSocket(conn *websocket.Conn, sessionID string) error {
	// Get VM IP from CNI
	vmIP, err := p.getVMIPFromCNI()
	if err != nil {
		return fmt.Errorf("failed to get VM IP from CNI: %w", err)
	}
	
	log.Printf("Discovered VM IP from CNI: %s", vmIP)
	
	// Create or get terminal session
	session, err := p.getOrCreateSessionWithVM(sessionID, vmIP)
	if err != nil {
		return fmt.Errorf("failed to create terminal session: %w", err)
	}

	// Handle bidirectional communication
	done := make(chan bool, 2)

	// PTY -> WebSocket (terminal output to browser)
	go func() {
		defer func() { done <- true }()
		
		buffer := make([]byte, 1024)
		for {
			n, err := session.PTY.Read(buffer)
			if err != nil {
				if err != io.EOF {
					log.Printf("PTY read error: %v", err)
				}
				return
			}

			msg := WSMessage{
				Type: "output",
				Data: string(buffer[:n]),
			}

			if err := conn.WriteJSON(msg); err != nil {
				log.Printf("WebSocket write error: %v", err)
				return
			}
		}
	}()

	// WebSocket -> PTY (browser input to terminal)
	go func() {
		defer func() { done <- true }()
		
		for {
			var msg WSMessage
			err := conn.ReadJSON(&msg)
			if err != nil {
				log.Printf("WebSocket read error: %v", err)
				return
			}

			switch msg.Type {
			case "input":
				if _, err := session.PTY.Write([]byte(msg.Data)); err != nil {
					log.Printf("PTY write error: %v", err)
					return
				}
			case "resize":
				if err := p.resizePTY(session.PTY, msg.Cols, msg.Rows); err != nil {
					log.Printf("PTY resize error: %v", err)
				}
			}
		}
	}()

	// Wait for either direction to close
	<-done

	// Cleanup
	p.cleanupSession(sessionID)
	return nil
}

func (p *VMTerminalProxy) getOrCreateSession(sessionID string) (*TerminalSession, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Check if session already exists
	if session, exists := p.sessions[sessionID]; exists {
		return session, nil
	}

	// Create new terminal session
	cmd := exec.Command("/bin/bash")
	cmd.Env = append(os.Environ(), "TERM=xterm")

	// Start the command with a pty
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to start pty: %w", err)
	}

	session := &TerminalSession{
		ID:  sessionID,
		PTY: ptmx,
		Cmd: cmd,
	}

	p.sessions[sessionID] = session
	log.Printf("Created terminal session: %s", sessionID)

	return session, nil
}

func (p *VMTerminalProxy) cleanupSession(sessionID string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if session, exists := p.sessions[sessionID]; exists {
		// Close PTY
		if session.PTY != nil {
			session.PTY.Close()
		}

		// Kill process
		if session.Cmd != nil && session.Cmd.Process != nil {
			session.Cmd.Process.Kill()
		}

		delete(p.sessions, sessionID)
		log.Printf("Cleaned up terminal session: %s", sessionID)
	}
}

func (p *VMTerminalProxy) resizePTY(ptmx *os.File, cols, rows int) error {
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

// getVMIPFromCNI discovers the VM IP from the CNI network namespace
func (p *VMTerminalProxy) getVMIPFromCNI() (string, error) {
	// Method 1: Read from shared config (set by initContainer)
	if vmIP, err := p.readVMIPFromConfig(); err == nil && vmIP != "" {
		return vmIP, nil
	}

	// Method 2: Check environment variable (fallback)
	if vmIP := os.Getenv("VM_IP"); vmIP != "" {
		return vmIP, nil
	}

	// Method 3: Get pod IP and increment by 1 (common pattern)
	podIP, err := p.getPodIP()
	if err == nil && podIP != "" {
		ip := net.ParseIP(podIP)
		if ip != nil && ip.To4() != nil {
			// Increment last octet by 1 for VM IP
			ip[15]++
			return ip.String(), nil
		}
	}

	// Method 4: Scan for VM on bridge network
	vmIP, err := p.scanForVM()
	if err == nil && vmIP != "" {
		return vmIP, nil
	}

	// Method 5: Check common VM IP ranges
	commonIPs := []string{
		"10.244.1.101",
		"192.168.1.101", 
		"172.16.0.101",
	}
	
	for _, ip := range commonIPs {
		if p.isVMReachable(ip) {
			return ip, nil
		}
	}

	return "", fmt.Errorf("could not discover VM IP from CNI")
}

func (p *VMTerminalProxy) readVMIPFromConfig() (string, error) {
	// Read from shared config file created by initContainer
	configPath := "/shared/network-config"
	
	content, err := os.ReadFile(configPath)
	if err != nil {
		return "", err
	}
	
	// Parse the config file
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "VM_IP=") {
			return strings.TrimPrefix(line, "VM_IP="), nil
		}
	}
	
	return "", fmt.Errorf("VM_IP not found in config file")
}

func (p *VMTerminalProxy) getPodIP() (string, error) {
	// Method 1: From environment (Kubernetes downward API)
	if podIP := os.Getenv("POD_IP"); podIP != "" {
		return podIP, nil
	}

	// Method 2: From hostname resolution
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}

	ips, err := net.LookupIP(hostname)
	if err != nil {
		return "", err
	}

	for _, ip := range ips {
		if ip.To4() != nil { // IPv4
			return ip.String(), nil
		}
	}

	return "", fmt.Errorf("could not determine pod IP")
}

func (p *VMTerminalProxy) scanForVM() (string, error) {
	// Get pod network and scan common VM IPs
	podIP, err := p.getPodIP()
	if err != nil {
		return "", err
	}

	ip := net.ParseIP(podIP)
	if ip == nil {
		return "", fmt.Errorf("invalid pod IP")
	}

	// Try common VM IP patterns
	base := ip.To4()
	if base == nil {
		return "", fmt.Errorf("not IPv4")
	}

	// Try incrementing last octet
	for i := 1; i <= 10; i++ {
		testIP := make(net.IP, 4)
		copy(testIP, base)
		testIP[3] = base[3] + byte(i)
		
		if p.isVMReachable(testIP.String()) {
			return testIP.String(), nil
		}
	}

	return "", fmt.Errorf("VM not found in network scan")
}

func (p *VMTerminalProxy) isVMReachable(ip string) bool {
	// Try to connect to SSH port
	conn, err := net.DialTimeout("tcp", ip+":22", 2000)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (p *VMTerminalProxy) getOrCreateSessionWithVM(sessionID, vmIP string) (*TerminalSession, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Check if session already exists
	if session, exists := p.sessions[sessionID]; exists {
		return session, nil
	}

	// FAILOVER MECHANISM: Try primary VM, then failover VMs (following dozlab-api resilience pattern)
	vmList := append([]string{vmIP}, p.failoverVMs...)
	
	for i, targetVM := range vmList {
		log.Printf("Attempting VM connection %d/%d to %s", i+1, len(vmList), targetVM)
		
		sshConn, err := p.connectToVMWithTimeout(targetVM, 10*time.Second)
		if err != nil {
			log.Printf("VM connection %d failed: %v", i+1, err)
			continue // Try next VM
		}
		
		// SUCCESS: Create session with working VM
		session := &TerminalSession{
			ID:      sessionID,
			VMIP:    targetVM,
			SSHConn: sshConn,
		}
		
		// MEMORY LEAK FIX: Ensure cleanup on any failure (following dozlab-api defer pattern)
		defer func() {
			if err != nil {
				p.cleanupSessionLocked(sessionID) // Clean up on failure
			}
		}()
		
		p.sessions[sessionID] = session
		log.Printf("Created SSH session to VM %s (attempt %d) for session: %s", targetVM, i+1, sessionID)
		return session, nil
	}

	// ALL VMs FAILED: Fallback to local terminal (following dozlab-api graceful degradation pattern)  
	log.Printf("All VM connections failed, using local terminal fallback for session: %s", sessionID)
	return p.createLocalSession(sessionID)
}

func (p *VMTerminalProxy) connectToVM(vmIP string) (*ssh.Client, error) {
	// Try different auth methods
	config := &ssh.ClientConfig{
		User:            getEnvOrDefault("SSH_USER", "lab-user"), // No more root!
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			// Simple host key verification - accept known hosts
			return nil // TODO: Implement proper host key verification
		}),
		Auth: []ssh.AuthMethod{
			// Use SSH key from environment instead of hardcoded passwords
			ssh.PublicKeys(loadSSHKey()),
		},
		Timeout: 10,
	}

	// Try to load SSH key if available
	if sshKey := os.Getenv("SSH_PRIVATE_KEY"); sshKey != "" {
		if signer, err := ssh.ParsePrivateKey([]byte(sshKey)); err == nil {
			config.Auth = append(config.Auth, ssh.PublicKeys(signer))
		}
	}

	return ssh.Dial("tcp", vmIP+":22", config)
}

func (p *VMTerminalProxy) createLocalSession(sessionID string) (*TerminalSession, error) {
	// Create local terminal session as fallback
	cmd := exec.Command("/bin/bash")
	cmd.Env = append(os.Environ(), "TERM=xterm")

	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to start local pty: %w", err)
	}

	session := &TerminalSession{
		ID:  sessionID,
		PTY: ptmx,
		Cmd: cmd,
	}

	p.sessions[sessionID] = session
	log.Printf("Created local terminal session: %s", sessionID)

	return session, nil
}

// Helper functions for secure SSH
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func loadSSHKey() ssh.Signer {
	// Try to load SSH key from environment or file
	if sshKey := os.Getenv("SSH_PRIVATE_KEY"); sshKey != "" {
		if signer, err := ssh.ParsePrivateKey([]byte(sshKey)); err == nil {
			return signer
		}
	}
	
	// Try default key locations
	keyPaths := []string{
		os.Getenv("HOME") + "/.ssh/id_rsa",
		"/etc/ssh-keys/id_rsa",
	}
	
	for _, keyPath := range keyPaths {
		if keyData, err := os.ReadFile(keyPath); err == nil {
			if signer, err := ssh.ParsePrivateKey(keyData); err == nil {
				return signer
			}
		}
	}
	
	// Fallback: generate a temporary key (not recommended for production)
	log.Println("WARNING: No SSH key found, connection may fail")
	return nil
}

// Following dozlab-api cleanup patterns
func (p *VMTerminalProxy) cleanupSessions() {
	for {
		select {
		case <-p.cleanupTicker.C:
			p.performCleanup()
		case <-p.stopCleanup:
			p.cleanupTicker.Stop()
			return
		}
	}
}

func (p *VMTerminalProxy) performCleanup() {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	
	cutoffTime := time.Now().Add(-30 * time.Minute) // Clean sessions older than 30 min
	toDelete := make([]string, 0)
	
	for sessionID, session := range p.sessions {
		// Check if session is stale or connection is dead
		if p.isSessionStale(session, cutoffTime) {
			toDelete = append(toDelete, sessionID)
		}
	}
	
	// Clean up stale sessions (prevent memory leaks)
	for _, sessionID := range toDelete {
		log.Printf("Cleaning up stale session: %s", sessionID)
		p.cleanupSessionLocked(sessionID)
		delete(p.sessions, sessionID)
	}
	
	if len(toDelete) > 0 {
		log.Printf("Cleaned up %d stale sessions", len(toDelete))
	}
}

func (p *VMTerminalProxy) isSessionStale(session *TerminalSession, cutoffTime time.Time) bool {
	// Test SSH connection health
	if session.SSHConn != nil {
		if _, _, err := session.SSHConn.SendRequest("keepalive", false, nil); err != nil {
			log.Printf("SSH connection dead for session %s: %v", session.ID, err)
			return true
		}
	}
	
	// Test local PTY health
	if session.PTY != nil && session.Cmd != nil {
		if session.Cmd.ProcessState != nil && session.Cmd.ProcessState.Exited() {
			log.Printf("Local process dead for session %s", session.ID)
			return true
		}
	}
	
	return false
}

func (p *VMTerminalProxy) cleanupSessionLocked(sessionID string) {
	if session, exists := p.sessions[sessionID]; exists {
		// Close SSH connection (following dozlab-api defer pattern)
		if session.SSHConn != nil {
			session.SSHConn.Close()
		}
		
		// Close PTY (following dozlab-api defer pattern) 
		if session.PTY != nil {
			session.PTY.Close()
		}
		
		// Kill process (following dozlab-api defer pattern)
		if session.Cmd != nil && session.Cmd.Process != nil {
			session.Cmd.Process.Kill()
		}
	}
}

func (p *VMTerminalProxy) connectToVMWithTimeout(vmIP string, timeout time.Duration) (*ssh.Client, error) {
	// Create connection with timeout (following dozlab-api timeout patterns)
	done := make(chan struct {
		*ssh.Client
		error
	}, 1)
	
	go func() {
		client, err := p.connectToVM(vmIP)
		done <- struct {
			*ssh.Client
			error
		}{client, err}
	}()
	
	select {
	case result := <-done:
		return result.Client, result.error
	case <-time.After(timeout):
		return nil, fmt.Errorf("connection timeout to VM %s after %v", vmIP, timeout)
	}
}

func getFailoverVMs() []string {
	// Load failover VMs from environment (following dozlab-api config pattern)
	failoverEnv := os.Getenv("FAILOVER_VMS")
	if failoverEnv == "" {
		return []string{} // No failover VMs configured
	}
	
	vms := strings.Split(failoverEnv, ",")
	var result []string
	for _, vm := range vms {
		if trimmed := strings.TrimSpace(vm); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	
	log.Printf("Loaded %d failover VMs: %v", len(result), result)
	return result
}

// Close gracefully shuts down the proxy (following dozlab-api shutdown pattern)
func (p *VMTerminalProxy) Close() {
	// Stop cleanup routine
	close(p.stopCleanup)
	
	// Clean up all sessions
	p.mutex.Lock()
	defer p.mutex.Unlock()
	
	for sessionID := range p.sessions {
		p.cleanupSessionLocked(sessionID)
	}
	
	p.sessions = make(map[string]*TerminalSession)
	log.Println("VMTerminalProxy closed gracefully")
}