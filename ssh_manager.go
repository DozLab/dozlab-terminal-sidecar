package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

type SecureSSHManager struct {
	config       *Config
	clientPool   map[string]*ssh.Client
	poolMutex    sync.RWMutex
	knownHosts   ssh.HostKeyCallback
	authMethods  []ssh.AuthMethod
	cleanupTicker *time.Ticker
	ctx          context.Context
	cancel       context.CancelFunc
}

type SSHConnection struct {
	Client    *ssh.Client
	LastUsed  time.Time
	RefCount  int
	mutex     sync.RWMutex
}

func NewSecureSSHManager(config *Config) (*SecureSSHManager, error) {
	ctx, cancel := context.WithCancel(context.Background())
	
	manager := &SecureSSHManager{
		config:     config,
		clientPool: make(map[string]*ssh.Client),
		ctx:        ctx,
		cancel:     cancel,
	}

	// Initialize host key verification
	if err := manager.initializeHostKeyCallback(); err != nil {
		return nil, fmt.Errorf("failed to initialize host key verification: %w", err)
	}

	// Initialize authentication methods
	if err := manager.initializeAuthMethods(); err != nil {
		return nil, fmt.Errorf("failed to initialize SSH auth methods: %w", err)
	}

	// Start cleanup routine
	manager.startCleanupRoutine()

	return manager, nil
}

func (m *SecureSSHManager) initializeHostKeyCallback() error {
	// Use known_hosts file for host key verification (NO InsecureIgnoreHostKey!)
	if _, err := os.Stat(m.config.SSHKnownHostsPath); err != nil {
		if os.IsNotExist(err) {
			// Create empty known_hosts file if it doesn't exist
			if err := os.MkdirAll(filepath.Dir(m.config.SSHKnownHostsPath), 0700); err != nil {
				return fmt.Errorf("failed to create known_hosts directory: %w", err)
			}
			
			file, err := os.OpenFile(m.config.SSHKnownHostsPath, os.O_CREATE|os.O_WRONLY, 0600)
			if err != nil {
				return fmt.Errorf("failed to create known_hosts file: %w", err)
			}
			file.Close()
			
			log.Printf("Created empty known_hosts file at %s", m.config.SSHKnownHostsPath)
			log.Println("WARNING: First connection to VMs will require manual host key verification")
		} else {
			return fmt.Errorf("error accessing known_hosts file: %w", err)
		}
	}

	hostKeyCallback, err := knownhosts.New(m.config.SSHKnownHostsPath)
	if err != nil {
		return fmt.Errorf("failed to load known hosts: %w", err)
	}

	// Wrap the callback to add new hosts automatically in development
	if os.Getenv("ENV") == "development" && os.Getenv("AUTO_ACCEPT_HOST_KEYS") == "true" {
		m.knownHosts = m.createAutoAcceptCallback(hostKeyCallback)
	} else {
		m.knownHosts = hostKeyCallback
	}

	return nil
}

func (m *SecureSSHManager) createAutoAcceptCallback(originalCallback ssh.HostKeyCallback) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := originalCallback(hostname, remote, key)
		if err != nil {
			// If host key is not known, add it automatically in development
			log.Printf("Auto-accepting host key for %s in development mode", hostname)
			
			// Add the host key to known_hosts file
			if err := m.addHostKey(hostname, key); err != nil {
				log.Printf("Failed to add host key: %v", err)
				return err
			}
			
			return nil
		}
		return err
	}
}

func (m *SecureSSHManager) addHostKey(hostname string, key ssh.PublicKey) error {
	file, err := os.OpenFile(m.config.SSHKnownHostsPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open known_hosts file: %w", err)
	}
	defer file.Close()

	line := knownhosts.Line([]string{hostname}, key)
	if _, err := file.WriteString(line + "\n"); err != nil {
		return fmt.Errorf("failed to write host key: %w", err)
	}

	return nil
}

func (m *SecureSSHManager) initializeAuthMethods() error {
	var authMethods []ssh.AuthMethod

	// 1. Public key authentication (primary method)
	if m.config.SSHKeyPath != "" {
		if _, err := os.Stat(m.config.SSHKeyPath); err == nil {
			key, err := m.loadPrivateKey(m.config.SSHKeyPath)
			if err != nil {
				return fmt.Errorf("failed to load SSH private key: %w", err)
			}
			authMethods = append(authMethods, ssh.PublicKeys(key))
			log.Printf("Loaded SSH private key from %s", m.config.SSHKeyPath)
		} else {
			log.Printf("SSH private key not found at %s", m.config.SSHKeyPath)
		}
	}

	// 2. Agent authentication (if available)
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if agentConn, err := net.Dial("unix", sock); err == nil {
			agentClient := agent.NewClient(agentConn)
			authMethods = append(authMethods, ssh.PublicKeysCallback(agentClient.Signers))
			log.Println("SSH agent authentication available")
		}
	}

	// 3. Environment-based key (for containers)
	if sshKeyEnv := os.Getenv("SSH_PRIVATE_KEY"); sshKeyEnv != "" {
		if signer, err := ssh.ParsePrivateKey([]byte(sshKeyEnv)); err == nil {
			authMethods = append(authMethods, ssh.PublicKeys(signer))
			log.Println("Loaded SSH key from environment variable")
		}
	}

	if len(authMethods) == 0 {
		return fmt.Errorf("no valid SSH authentication methods available")
	}

	m.authMethods = authMethods
	return nil
}

func (m *SecureSSHManager) loadPrivateKey(keyPath string) (ssh.Signer, error) {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	// Try to parse the key directly
	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		// If parsing fails, it might be encrypted
		return nil, fmt.Errorf("failed to parse private key (encrypted keys not supported): %w", err)
	}

	return signer, nil
}

func (m *SecureSSHManager) ConnectToVM(vmIP string) (*ssh.Client, error) {
	// Check if we already have a connection
	m.poolMutex.RLock()
	if client, exists := m.clientPool[vmIP]; exists {
		// Test if connection is still alive
		if _, _, err := client.SendRequest("keepalive", false, nil); err == nil {
			m.poolMutex.RUnlock()
			log.Printf("Reusing existing SSH connection to %s", vmIP)
			return client, nil
		} else {
			log.Printf("Existing SSH connection to %s is dead, removing from pool", vmIP)
		}
	}
	m.poolMutex.RUnlock()

	// Create new connection with timeout
	ctx, cancel := context.WithTimeout(m.ctx, m.config.SSHTimeout)
	defer cancel()

	config := &ssh.ClientConfig{
		User:            m.config.SSHUser,
		Auth:            m.authMethods,
		HostKeyCallback: m.knownHosts,
		Timeout:         m.config.SSHKeyExchangeTimeout,
	}

	// Try connection with retries
	var client *ssh.Client
	var err error
	
dial:
	for attempt := 1; attempt <= m.config.SSHConnectRetries; attempt++ {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("SSH connection timeout to %s", vmIP)
		default:
			client, err = ssh.Dial("tcp", net.JoinHostPort(vmIP, "22"), config)
			if err == nil {
				break dial
			}
			
			log.Printf("SSH connection attempt %d/%d to %s failed: %v", 
				attempt, m.config.SSHConnectRetries, vmIP, err)
			
			if attempt < m.config.SSHConnectRetries {
				time.Sleep(time.Second * time.Duration(attempt)) // Exponential backoff
			}
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to VM %s after %d attempts: %w", 
			vmIP, m.config.SSHConnectRetries, err)
	}

	// Add to pool
	m.poolMutex.Lock()
	m.clientPool[vmIP] = client
	m.poolMutex.Unlock()

	log.Printf("Successfully established SSH connection to %s", vmIP)
	return client, nil
}

func (m *SecureSSHManager) startCleanupRoutine() {
	m.cleanupTicker = time.NewTicker(m.config.CleanupInterval)
	
	go func() {
		for {
			select {
			case <-m.cleanupTicker.C:
				m.cleanupIdleConnections()
			case <-m.ctx.Done():
				return
			}
		}
	}()
}

func (m *SecureSSHManager) cleanupIdleConnections() {
	m.poolMutex.Lock()
	defer m.poolMutex.Unlock()

	var toRemove []string

	for vmIP, client := range m.clientPool {
		// Test connection health
		if _, _, err := client.SendRequest("keepalive", false, nil); err != nil {
			log.Printf("SSH connection to %s is dead, removing from pool", vmIP)
			toRemove = append(toRemove, vmIP)
			client.Close()
		}
	}

	// Remove dead connections
	for _, vmIP := range toRemove {
		delete(m.clientPool, vmIP)
	}

	if len(toRemove) > 0 {
		log.Printf("Cleaned up %d dead SSH connections", len(toRemove))
	}
}

func (m *SecureSSHManager) Close() {
	m.cancel()
	
	if m.cleanupTicker != nil {
		m.cleanupTicker.Stop()
	}

	m.poolMutex.Lock()
	defer m.poolMutex.Unlock()

	for vmIP, client := range m.clientPool {
		client.Close()
		log.Printf("Closed SSH connection to %s", vmIP)
	}
	
	m.clientPool = make(map[string]*ssh.Client)
}