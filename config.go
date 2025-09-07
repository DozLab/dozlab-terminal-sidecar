package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	// Server configuration
	Port    string
	Host    string
	TLSCert string
	TLSKey  string

	// SSH configuration
	SSHUser               string
	SSHKeyPath            string
	SSHKnownHostsPath     string
	SSHTimeout            time.Duration
	SSHConnectRetries     int
	SSHKeyExchangeTimeout time.Duration

	// Security configuration
	AllowedOrigins      []string
	RequireAuth         bool
	AuthTokenHeader     string
	MaxSessionsPerUser  int
	SessionTimeout      time.Duration
	MaxConcurrentSessions int

	// VM discovery configuration
	VMDiscoveryMethods    []string
	VMDiscoveryTimeout    time.Duration
	NetworkScanRanges     []string
	ConfigPath            string

	// Resource limits
	MaxSessionDuration    time.Duration
	MaxBufferSize         int
	ConnectionPoolSize    int
	CleanupInterval       time.Duration
}

func LoadConfig() (*Config, error) {
	config := &Config{
		// Server defaults
		Port:    getEnv("PORT", "8081"),
		Host:    getEnv("HOST", "0.0.0.0"),
		TLSCert: getEnv("TLS_CERT_PATH", ""),
		TLSKey:  getEnv("TLS_KEY_PATH", ""),

		// SSH configuration - secure defaults
		SSHUser:               getEnv("SSH_USER", "lab-user"), // No more root!
		SSHKeyPath:            getEnv("SSH_KEY_PATH", "/etc/ssh-keys/id_rsa"),
		SSHKnownHostsPath:     getEnv("SSH_KNOWN_HOSTS_PATH", "/etc/ssh-keys/known_hosts"),
		SSHTimeout:            getDurationEnv("SSH_TIMEOUT", 10*time.Second),
		SSHConnectRetries:     getIntEnv("SSH_CONNECT_RETRIES", 3),
		SSHKeyExchangeTimeout: getDurationEnv("SSH_KEY_EXCHANGE_TIMEOUT", 5*time.Second),

		// Security configuration
		RequireAuth:           getBoolEnv("REQUIRE_AUTH", true),
		AuthTokenHeader:       getEnv("AUTH_TOKEN_HEADER", "X-Session-Token"),
		MaxSessionsPerUser:    getIntEnv("MAX_SESSIONS_PER_USER", 5),
		SessionTimeout:        getDurationEnv("SESSION_TIMEOUT", 30*time.Minute),
		MaxConcurrentSessions: getIntEnv("MAX_CONCURRENT_SESSIONS", 100),

		// VM discovery configuration
		VMDiscoveryTimeout:    getDurationEnv("VM_DISCOVERY_TIMEOUT", 30*time.Second),
		ConfigPath:            getEnv("CONFIG_PATH", "/shared/network-config"),

		// Resource limits
		MaxSessionDuration:    getDurationEnv("MAX_SESSION_DURATION", 4*time.Hour),
		MaxBufferSize:         getIntEnv("MAX_BUFFER_SIZE", 64*1024), // 64KB
		ConnectionPoolSize:    getIntEnv("CONNECTION_POOL_SIZE", 10),
		CleanupInterval:       getDurationEnv("CLEANUP_INTERVAL", 5*time.Minute),
	}

	// Parse allowed origins
	if originsEnv := getEnv("ALLOWED_ORIGINS", ""); originsEnv != "" {
		config.AllowedOrigins = parseStringSlice(originsEnv)
	} else {
		// Default to secure origins in production
		if getEnv("ENV", "development") == "production" {
			config.AllowedOrigins = []string{
				"https://dozlab.com",
				"https://api.dozlab.com",
			}
		} else {
			config.AllowedOrigins = []string{
				"http://localhost:3000",
				"http://127.0.0.1:3000",
			}
		}
	}

	// Parse VM discovery methods
	if methodsEnv := getEnv("VM_DISCOVERY_METHODS", ""); methodsEnv != "" {
		config.VMDiscoveryMethods = parseStringSlice(methodsEnv)
	} else {
		config.VMDiscoveryMethods = []string{
			"config_file",
			"environment",
			"service_discovery",
			"network_scan", // Last resort
		}
	}

	// Parse network scan ranges (if enabled)
	if rangesEnv := getEnv("NETWORK_SCAN_RANGES", ""); rangesEnv != "" {
		config.NetworkScanRanges = parseStringSlice(rangesEnv)
	} else {
		// Default secure ranges
		config.NetworkScanRanges = []string{
			"10.244.0.0/16",    // Typical Kubernetes pod CIDR
			"172.16.0.0/12",    // Docker default
		}
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

func (c *Config) Validate() error {
	// Validate SSH configuration
	if c.SSHUser == "root" {
		return fmt.Errorf("using root user is not allowed for security reasons")
	}

	if c.SSHKeyPath == "" {
		return fmt.Errorf("SSH key path is required")
	}

	if c.SSHKnownHostsPath == "" {
		return fmt.Errorf("SSH known hosts path is required for security")
	}

	// Validate resource limits
	if c.MaxConcurrentSessions <= 0 {
		return fmt.Errorf("max concurrent sessions must be positive")
	}

	if c.MaxSessionsPerUser <= 0 {
		return fmt.Errorf("max sessions per user must be positive")
	}

	if c.SessionTimeout <= 0 {
		return fmt.Errorf("session timeout must be positive")
	}

	// Validate security settings
	if c.RequireAuth && c.AuthTokenHeader == "" {
		return fmt.Errorf("auth token header is required when auth is enabled")
	}

	// Warn about insecure configurations in production
	if getEnv("ENV", "development") == "production" {
		if len(c.AllowedOrigins) == 0 {
			return fmt.Errorf("allowed origins must be specified in production")
		}

		if c.TLSCert == "" || c.TLSKey == "" {
			return fmt.Errorf("TLS certificates are required in production")
		}

		if !c.RequireAuth {
			return fmt.Errorf("authentication is required in production")
		}
	}

	return nil
}

// Helper functions for environment variable parsing
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getIntEnv(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getBoolEnv(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getDurationEnv(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

func parseStringSlice(value string) []string {
	if value == "" {
		return []string{}
	}
	
	var result []string
	for _, item := range splitAndTrim(value, ",") {
		if item != "" {
			result = append(result, item)
		}
	}
	return result
}

func splitAndTrim(s, sep string) []string {
	var result []string
	for _, item := range strings.Split(s, sep) {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}