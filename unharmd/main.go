// honeypot.go
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	psutilNet "github.com/shirou/gopsutil/net"
)

// ServiceConfig holds the configuration for each honeypot service.
type ServiceConfig struct {
	Port     string `json:"port"`
	Protocol string `json:"protocol"`
	UID      string `json:"uid"`
}

// LLMRequest defines the structure of requests to the LLM API.
type LLMRequest struct {
	NodeUUID string `json:"node"`
	Token    string `json:"token"`
	InputHex string `json:"input"`
	Protocol string `json:"protocol"`
	Port     string `json:"port"`
	Session  string `json:"session"`
	RemoteIP string `json:"remote_ip"`
	UID      string `json:"uid"`
}

// LLMResponse represents the minimal response structure from the LLM API.
type LLMResponse struct {
	ResponseHex string `json:"response"`
	Delay       int    `json:"delay"`
	Continue    bool   `json:"continue"`
}

// StatusReport defines the structure of the status report sent to the server.
type StatusReport struct {
	NodeUUID             string         `json:"node"`
	Token                string         `json:"token"`
	StartTime            time.Time      `json:"start_time"`
	Uptime               string         `json:"uptime"`
	NumGoroutines        int            `json:"num_goroutines"`
	MemoryAlloc          uint64         `json:"memory_alloc"`
	MemorySys            uint64         `json:"memory_sys"`
	CPUUsage             float64        `json:"cpu_usage"`
	NetworkBytes         uint64         `json:"network_bytes"`
	DiskTotal            uint64         `json:"disk_total"`
	DiskFree             uint64         `json:"disk_free"`
	DiskUsed             uint64         `json:"disk_used"`
	ActiveGlobalRequests int32          `json:"active_global_requests"`
	GlobalRequestLimit   int            `json:"global_request_limit"`
	ActiveConnections    map[string]int `json:"active_connections"`
}

var (
	servicesStr          string
	services             []ServiceConfig
	llmApiUrl            string
	statusApiUrl         string
	apiKey               string
	nodeUUID             string
	startTime            time.Time
	connLimit            int
	globalRequestLimit   int // Maximum concurrent global requests
	activeGlobalRequests int32
	activeConns          = make(map[string]int)
	localBlacklist       = make(map[string]time.Time) // Local blacklist managed by the node
	globalBlacklist      = make(map[string]struct{})  // Global blacklist managed by the central server
	mu                   sync.Mutex
	totalNetworkBytes    uint64
	httpClient           *http.Client
	wg                   sync.WaitGroup
	ipRequestQueues      = make(map[string]chan []byte) // Buffered channel per IP
	ipActiveRequests     = make(map[string]bool)        // Track active requests per IP
	queueLock            sync.Mutex                     // Lock for the request queues map
	cancelFunc           context.CancelFunc
)

// initHTTPClient initializes a shared HTTP client with timeout.
func initHTTPClient() {
	httpClient = &http.Client{
		Timeout: 10 * time.Second,
	}
}

// blacklistIP adds an IP to the local blacklist.
func blacklistIP(ip string) {
	mu.Lock()
	defer mu.Unlock()
	localBlacklist[ip] = time.Now().Add(1 * time.Hour)
}

// isBlacklisted checks if an IP is blacklisted (either locally or globally).
func isBlacklisted(ip string) bool {
	mu.Lock()
	defer mu.Unlock()
	_, globallyBlacklisted := globalBlacklist[ip]
	_, locallyBlacklisted := localBlacklist[ip]
	return globallyBlacklisted || (locallyBlacklisted && time.Now().Before(localBlacklist[ip]))
}

// generateSessionID creates a unique session ID.
func generateSessionID() string {
	return fmt.Sprintf("%d", rand.Int63())
}

// queryLLM sends data to the LLM API and retrieves the response.
func queryLLM(inputData []byte, protocol, port, session, remoteIP, uid string) (*LLMResponse, error) {
	inputHex := hex.EncodeToString(inputData)

	requestData := LLMRequest{
		NodeUUID: nodeUUID,
		Token:    apiKey,
		InputHex: inputHex,
		Protocol: protocol,
		Port:     port,
		Session:  session,
		RemoteIP: remoteIP,
		UID:      uid,
	}

	requestBody, err := json.Marshal(requestData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal LLM request: %v", err)
	}

	req, err := http.NewRequest("POST", llmApiUrl, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create LLM API request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("LLM API request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("LLM API responded with status: %s", resp.Status)
	}

	var llmResponse LLMResponse
	if err := json.NewDecoder(resp.Body).Decode(&llmResponse); err != nil {
		return nil, fmt.Errorf("failed to decode LLM API response: %v", err)
	}

	return &llmResponse, nil
}

// processRequestQueue handles incoming requests for each IP.
func processRequestQueue(ip string, serviceConfig ServiceConfig) {
	defer func() {
		queueLock.Lock()
		delete(ipRequestQueues, ip)
		delete(ipActiveRequests, ip)
		queueLock.Unlock()
	}()

	for data := range ipRequestQueues[ip] {
		if atomic.LoadInt32(&activeGlobalRequests) >= int32(globalRequestLimit) {
			log.Printf("Global request limit reached, delaying IP %s", ip)
			time.Sleep(500 * time.Millisecond)
			continue
		}

		atomic.AddInt32(&activeGlobalRequests, 1)
		session := generateSessionID()
		llmResponse, err := queryLLM(data, serviceConfig.Protocol, serviceConfig.Port, session, ip, serviceConfig.UID)
		atomic.AddInt32(&activeGlobalRequests, -1)

		if err != nil {
			log.Printf("Error querying LLM for IP %s: %v", ip, err)
			continue
		}

		if !llmResponse.Continue {
			log.Printf("Connection terminated and IP blacklisted: %s", ip)
			blacklistIP(ip)
			break
		}

		if llmResponse.Delay > 0 {
			time.Sleep(time.Duration(llmResponse.Delay) * time.Millisecond)
		}
	}
}

// handleConnection manages each client connection, adding data to the request queue for each IP.
func handleConnection(ctx context.Context, conn net.Conn, serviceConfig ServiceConfig) {
	defer conn.Close()
	remoteAddr := conn.RemoteAddr().(*net.TCPAddr).IP.String()
	if isBlacklisted(remoteAddr) {
		log.Printf("Blocked connection from blacklisted IP: %s", remoteAddr)
		return
	}

	queueLock.Lock()
	if _, exists := ipRequestQueues[remoteAddr]; !exists {
		ipRequestQueues[remoteAddr] = make(chan []byte, 10)
		go processRequestQueue(remoteAddr, serviceConfig)
	}
	queueLock.Unlock()

	buf := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			log.Printf("Connection handling stopped for IP: %s", remoteAddr)
			return
		default:
			n, err := conn.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Printf("Error reading from %s: %v", remoteAddr, err)
				}
				return
			}
			data := make([]byte, n)
			copy(data, buf[:n])

			select {
			case ipRequestQueues[remoteAddr] <- data:
			default:
				log.Printf("Request buffer full for IP %s, data discarded", remoteAddr)
			}
		}
	}
}

// startTCPService starts a TCP service on the specified port.
func startTCPService(ctx context.Context, serviceConfig ServiceConfig) {
	defer wg.Done()
	ln, err := net.Listen("tcp", ":"+serviceConfig.Port)
	if err != nil {
		log.Fatalf("Error starting TCP service on port %s: %v", serviceConfig.Port, err)
	}
	log.Printf("TCP service '%s' started on port %s", serviceConfig.UID, serviceConfig.Port)

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				log.Printf("Shutting down TCP service on port %s", serviceConfig.Port)
				return
			default:
				log.Printf("Error accepting connection on port %s: %v", serviceConfig.Port, err)
				continue
			}
		}
		go handleConnection(ctx, conn, serviceConfig)
	}
}

// sendStatusReport sends a status report with system metrics every minute and updates the global blacklist.
func sendStatusReport(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(1 * time.Minute):
			uptime := time.Since(startTime).String()
			var m runtime.MemStats
			runtime.ReadMemStats(&m)

			cpuPercent, _ := cpu.Percent(0, false)
			netStats, _ := psutilNet.IOCounters(false)
			if len(netStats) > 0 {
				atomic.StoreUint64(&totalNetworkBytes, netStats[0].BytesSent+netStats[0].BytesRecv)
			}

			diskStats, _ := disk.Usage("/")
			statusReport := StatusReport{
				NodeUUID:             nodeUUID,
				Token:                apiKey,
				StartTime:            startTime,
				Uptime:               uptime,
				NumGoroutines:        runtime.NumGoroutine(),
				MemoryAlloc:          m.Alloc,
				MemorySys:            m.Sys,
				CPUUsage:             cpuPercent[0],
				NetworkBytes:         atomic.LoadUint64(&totalNetworkBytes),
				DiskTotal:            diskStats.Total,
				DiskFree:             diskStats.Free,
				DiskUsed:             diskStats.Used,
				ActiveGlobalRequests: atomic.LoadInt32(&activeGlobalRequests),
				GlobalRequestLimit:   globalRequestLimit,
			}

			requestBody, err := json.Marshal(statusReport)
			if err != nil {
				log.Printf("Failed to marshal status report: %v", err)
				continue
			}

			req, err := http.NewRequest("POST", statusApiUrl, bytes.NewBuffer(requestBody))
			if err != nil {
				log.Printf("Failed to create status report request: %v", err)
				continue
			}
			req.Header.Set("Content-Type", "application/json")

			resp, err := httpClient.Do(req)
			if err != nil {
				log.Printf("Status report request failed: %v", err)
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				var globalBlacklistResponse struct {
					BlacklistedIPs []string `json:"blacklisted_ips"`
				}
				if err := json.NewDecoder(resp.Body).Decode(&globalBlacklistResponse); err != nil {
					log.Printf("Failed to decode global blacklist response: %v", err)
					continue
				}

				mu.Lock()
				for _, ip := range globalBlacklistResponse.BlacklistedIPs {
					globalBlacklist[ip] = struct{}{}
				}
				mu.Unlock()
			} else {
				log.Printf("Status report failed with status: %s", resp.Status)
			}
		}
	}
}

func main() {
	startTime = time.Now()
	initHTTPClient()

	flag.StringVar(&servicesStr, "services", "", "List of services in 'port/protocol/uid' format, separated by commas")
	flag.StringVar(&llmApiUrl, "llm-api", "http://localhost:8080/llm", "LLM API URL")
	flag.StringVar(&statusApiUrl, "status-api", "http://localhost:8080/status", "Status report API URL")
	flag.StringVar(&apiKey, "api-key", "", "API key for authentication")
	flag.StringVar(&nodeUUID, "node-uuid", "", "Node UUID for identifying this honeypot instance")
	flag.IntVar(&connLimit, "conn-limit", 5, "Maximum concurrent connections per IP")
	flag.IntVar(&globalRequestLimit, "global-limit", 4, "Maximum global concurrent requests allowed")
	flag.Parse()

	if apiKey == "" || nodeUUID == "" || servicesStr == "" {
		log.Fatal("API key, node UUID, and services are required")
	}

	serviceList := strings.Split(servicesStr, ",")
	for _, svc := range serviceList {
		parts := strings.Split(svc, "/")
		if len(parts) != 3 {
			log.Fatalf("Invalid service format: %s. Expected 'port/protocol/uid'", svc)
		}
		services = append(services, ServiceConfig{
			Port:     parts[0],
			Protocol: strings.ToLower(parts[1]),
			UID:      parts[2],
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancelFunc = cancel

	go sendStatusReport(ctx)

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-c
		log.Println("Received termination signal. Shutting down...")
		cancelFunc()
		wg.Wait()
		log.Println("Honeypot instance has shut down.")
		os.Exit(0)
	}()

	for _, svc := range services {
		wg.Add(1)
		go startTCPService(ctx, svc)
	}

	wg.Wait()
}
