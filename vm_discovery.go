package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type VMDiscoveryService struct {
	config      *Config
	cache       map[string]*VMInfo
	cacheMutex  sync.RWMutex
	cacheExpiry time.Duration
}

type VMInfo struct {
	IP         string    `json:"ip"`
	Hostname   string    `json:"hostname,omitempty"`
	LastSeen   time.Time `json:"last_seen"`
	Reachable  bool      `json:"reachable"`
	SSHPort    int       `json:"ssh_port"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type ServiceDiscoveryResponse struct {
	Services []ServiceEntry `json:"services"`
}

type ServiceEntry struct {
	Name    string            `json:"name"`
	Address string            `json:"address"`
	Port    int               `json:"port"`
	Tags    []string          `json:"tags"`
	Meta    map[string]string `json:"meta"`
}

func NewVMDiscoveryService(config *Config) *VMDiscoveryService {
	return &VMDiscoveryService{
		config:      config,
		cache:       make(map[string]*VMInfo),
		cacheExpiry: 5 * time.Minute,
	}
}

func (vd *VMDiscoveryService) DiscoverVMIP(ctx context.Context) (string, error) {
	// Try each discovery method in order
	for _, method := range vd.config.VMDiscoveryMethods {
		log.Printf("Trying VM discovery method: %s", method)
		
		ip, err := vd.tryDiscoveryMethod(ctx, method)
		if err == nil && ip != "" {
			// Validate the discovered IP
			if vd.validateVMConnection(ctx, ip) {
				log.Printf("Successfully discovered VM IP: %s using method: %s", ip, method)
				return ip, nil
			} else {
				log.Printf("Discovered IP %s is not reachable via SSH", ip)
			}
		} else if err != nil {
			log.Printf("Discovery method %s failed: %v", method, err)
		}
	}

	return "", fmt.Errorf("failed to discover VM IP using any configured method")
}

func (vd *VMDiscoveryService) tryDiscoveryMethod(ctx context.Context, method string) (string, error) {
	switch method {
	case "config_file":
		return vd.discoverFromConfigFile(ctx)
	case "environment":
		return vd.discoverFromEnvironment(ctx)
	case "service_discovery":
		return vd.discoverFromServiceDiscovery(ctx)
	case "network_scan":
		return vd.discoverFromNetworkScan(ctx)
	default:
		return "", fmt.Errorf("unknown discovery method: %s", method)
	}
}

func (vd *VMDiscoveryService) discoverFromConfigFile(ctx context.Context) (string, error) {
	// Read from shared config file created by initContainer or operator
	configPath := vd.config.ConfigPath
	
	content, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("failed to read config file %s: %w", configPath, err)
	}
	
	// Try JSON format first
	var config map[string]interface{}
	if err := json.Unmarshal(content, &config); err == nil {
		if vmIP, ok := config["vm_ip"].(string); ok && vmIP != "" {
			return vmIP, nil
		}
	}
	
	// Fallback to key=value format
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "VM_IP=") {
			return strings.TrimPrefix(line, "VM_IP="), nil
		}
	}
	
	return "", fmt.Errorf("VM_IP not found in config file")
}

func (vd *VMDiscoveryService) discoverFromEnvironment(ctx context.Context) (string, error) {
	// Check multiple environment variables
	envVars := []string{
		"VM_IP",
		"LAB_VM_IP", 
		"TARGET_VM_IP",
		"DOZLAB_VM_IP",
	}
	
	for _, envVar := range envVars {
		if vmIP := os.Getenv(envVar); vmIP != "" {
			return vmIP, nil
		}
	}
	
	return "", fmt.Errorf("no VM IP found in environment variables")
}

func (vd *VMDiscoveryService) discoverFromServiceDiscovery(ctx context.Context) (string, error) {
	// Try Kubernetes service discovery first
	if vmIP, err := vd.discoverFromKubernetesService(ctx); err == nil && vmIP != "" {
		return vmIP, nil
	}
	
	// Try Consul service discovery
	if vmIP, err := vd.discoverFromConsul(ctx); err == nil && vmIP != "" {
		return vmIP, nil
	}
	
	return "", fmt.Errorf("no VM found via service discovery")
}

func (vd *VMDiscoveryService) discoverFromKubernetesService(ctx context.Context) (string, error) {
	// Look for lab VM service in the same namespace
	podNamespace := os.Getenv("POD_NAMESPACE")
	if podNamespace == "" {
		if content, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
			podNamespace = strings.TrimSpace(string(content))
		} else {
			podNamespace = "default"
		}
	}
	
	// Try to resolve lab VM service
	serviceNames := []string{
		fmt.Sprintf("lab-vm-service.%s.svc.cluster.local", podNamespace),
		fmt.Sprintf("vm-service.%s.svc.cluster.local", podNamespace),
		"lab-vm-service.default.svc.cluster.local",
	}
	
	for _, serviceName := range serviceNames {
		ips, err := net.LookupIP(serviceName)
		if err == nil && len(ips) > 0 {
			for _, ip := range ips {
				if ip.To4() != nil { // IPv4
					return ip.String(), nil
				}
			}
		}
	}
	
	return "", fmt.Errorf("no Kubernetes service found for lab VM")
}

func (vd *VMDiscoveryService) discoverFromConsul(ctx context.Context) (string, error) {
	consulAddr := os.Getenv("CONSUL_HTTP_ADDR")
	if consulAddr == "" {
		consulAddr = "http://consul:8500"
	}
	
	client := &http.Client{Timeout: 5 * time.Second}
	
	// Query Consul for lab VM services
	url := fmt.Sprintf("%s/v1/health/service/lab-vm?passing=true", consulAddr)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create consul request: %w", err)
	}
	
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to query consul: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("consul query failed with status: %d", resp.StatusCode)
	}
	
	var services []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&services); err != nil {
		return "", fmt.Errorf("failed to parse consul response: %w", err)
	}
	
	if len(services) == 0 {
		return "", fmt.Errorf("no healthy lab-vm services found in consul")
	}
	
	// Return the first healthy service IP
	if service, ok := services[0]["Service"].(map[string]interface{}); ok {
		if address, ok := service["Address"].(string); ok && address != "" {
			return address, nil
		}
	}
	
	return "", fmt.Errorf("no valid address found in consul response")
}

func (vd *VMDiscoveryService) discoverFromNetworkScan(ctx context.Context) (string, error) {
	// Only scan if explicitly enabled and we have defined ranges
	if len(vd.config.NetworkScanRanges) == 0 {
		return "", fmt.Errorf("network scanning not configured")
	}
	
	log.Printf("Starting network scan for VM discovery (ranges: %v)", vd.config.NetworkScanRanges)
	
	// Create a context with timeout for the entire scan
	scanCtx, cancel := context.WithTimeout(ctx, vd.config.VMDiscoveryTimeout)
	defer cancel()
	
	// Channel to collect results
	results := make(chan string, 100)
	var wg sync.WaitGroup
	
	// Scan each configured range
	for _, cidrRange := range vd.config.NetworkScanRanges {
		wg.Add(1)
		go func(cidr string) {
			defer wg.Done()
			vd.scanCIDRRange(scanCtx, cidr, results)
		}(cidrRange)
	}
	
	// Close results channel when all scans complete
	go func() {
		wg.Wait()
		close(results)
	}()
	
	// Return the first reachable VM found
	for ip := range results {
		select {
		case <-scanCtx.Done():
			return "", fmt.Errorf("network scan timeout")
		default:
			if vd.validateVMConnection(scanCtx, ip) {
				log.Printf("Found reachable VM at %s via network scan", ip)
				return ip, nil
			}
		}
	}
	
	return "", fmt.Errorf("no reachable VMs found in network scan")
}

func (vd *VMDiscoveryService) scanCIDRRange(ctx context.Context, cidr string, results chan<- string) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Printf("Invalid CIDR range %s: %v", cidr, err)
		return
	}
	
	// Limit scan to reasonable size
	ones, bits := ipNet.Mask.Size()
	if bits-ones > 8 { // More than 256 IPs
		log.Printf("Skipping large CIDR range %s (more than 256 IPs)", cidr)
		return
	}
	
	// Generate IPs to scan
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); vd.incrementIP(ip) {
		select {
		case <-ctx.Done():
			return
		default:
			ipStr := ip.String()
			// Skip network and broadcast addresses
			if !vd.isValidScanIP(ip, ipNet) {
				continue
			}
			
			// Quick port check for SSH
			if vd.isPortOpen(ctx, ipStr, 22) {
				results <- ipStr
			}
		}
	}
}

func (vd *VMDiscoveryService) incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func (vd *VMDiscoveryService) isValidScanIP(ip net.IP, network *net.IPNet) bool {
	// Skip network address
	if ip.Equal(network.IP) {
		return false
	}
	
	// Skip broadcast address for IPv4
	if ip.To4() != nil {
		broadcast := make(net.IP, len(network.IP))
		copy(broadcast, network.IP)
		for i := range broadcast {
			broadcast[i] |= ^network.Mask[i]
		}
		if ip.Equal(broadcast) {
			return false
		}
	}
	
	return true
}

func (vd *VMDiscoveryService) isPortOpen(ctx context.Context, ip string, port int) bool {
	timeout := 2 * time.Second
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (vd *VMDiscoveryService) validateVMConnection(ctx context.Context, ip string) bool {
	// Quick SSH port check with timeout
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	
	dialer := &net.Dialer{
		Timeout: 2 * time.Second,
	}
	
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, "22"))
	if err != nil {
		return false
	}
	conn.Close()
	
	// Update cache
	vd.cacheMutex.Lock()
	vd.cache[ip] = &VMInfo{
		IP:        ip,
		LastSeen:  time.Now(),
		Reachable: true,
		SSHPort:   22,
	}
	vd.cacheMutex.Unlock()
	
	return true
}

func (vd *VMDiscoveryService) GetCachedVMs() []*VMInfo {
	vd.cacheMutex.RLock()
	defer vd.cacheMutex.RUnlock()
	
	var vms []*VMInfo
	cutoff := time.Now().Add(-vd.cacheExpiry)
	
	for _, vm := range vd.cache {
		if vm.LastSeen.After(cutoff) {
			vms = append(vms, vm)
		}
	}
	
	return vms
}

func (vd *VMDiscoveryService) ClearCache() {
	vd.cacheMutex.Lock()
	vd.cache = make(map[string]*VMInfo)
	vd.cacheMutex.Unlock()
}