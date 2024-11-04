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
	Service  string `json:"service"`
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
	globalRequestLimit   int
	activeGlobalRequests int32
	activeConns          = make(map[string]int)
	localBlacklist       = make(map[string]time.Time)
	globalBlacklist      = make(map[string]struct{})
	mu                   sync.Mutex
	totalNetworkBytes    uint64
	httpClient           *http.Client
	wg                   sync.WaitGroup
	ipRequestQueues      = make(map[string]chan []byte)
	queueLock            sync.Mutex
	cancelFunc           context.CancelFunc
)

func initHTTPClient() {
	httpClient = &http.Client{
		Timeout: 5 * time.Second, // Set shorter timeout for production
	}
	log.Printf("[INFO] HTTP client initialized with timeout of 5 seconds")
}

func blacklistIP(ip string) {
	mu.Lock()
	defer mu.Unlock()
	localBlacklist[ip] = time.Now().Add(1 * time.Hour)
	log.Printf("[INFO] IP %s has been blacklisted.", ip)
}

func isBlacklisted(ip string) bool {
	mu.Lock()
	defer mu.Unlock()
	_, globallyBlacklisted := globalBlacklist[ip]
	_, locallyBlacklisted := localBlacklist[ip]
	return globallyBlacklisted || (locallyBlacklisted && time.Now().Before(localBlacklist[ip]))
}

func generateSessionID() string {
	return fmt.Sprintf("%d", rand.Int63())
}

func queryLLM(inputData []byte, protocol, port, session, remoteIP, service string) (*LLMResponse, error) {
	inputHex := hex.EncodeToString(inputData)
	requestData := LLMRequest{
		NodeUUID: nodeUUID,
		Token:    apiKey,
		InputHex: inputHex,
		Protocol: protocol,
		Port:     port,
		Session:  session,
		RemoteIP: remoteIP,
		Service:  service,
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

	log.Printf("[DEBUG] LLM response received: %+v", llmResponse)
	return &llmResponse, nil
}

func writeResponse(conn net.Conn, data []byte) error {
	_, err := conn.Write(data)
	if err != nil {
		log.Printf("[ERROR] Failed to write response: %v", err)
		return err
	}
	return nil
}

func handleConnection(ctx context.Context, conn net.Conn, serviceConfig ServiceConfig) {
	defer conn.Close()
	remoteAddr := conn.RemoteAddr().(*net.TCPAddr).IP.String()
	log.Printf("[INFO] Handling connection from IP: %s", remoteAddr)

	if isBlacklisted(remoteAddr) {
		log.Printf("[INFO] Blocked connection from blacklisted IP: %s", remoteAddr)
		writeResponse(conn, []byte("Blocked\n"))
		return
	}

	queueLock.Lock()
	if _, exists := ipRequestQueues[remoteAddr]; !exists {
		ipRequestQueues[remoteAddr] = make(chan []byte, 10)
		go processRequestQueue(remoteAddr, serviceConfig, conn)
	}
	queueLock.Unlock()

	buf := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			log.Printf("[INFO] Connection handling stopped for IP: %s", remoteAddr)
			return
		default:
			conn.SetReadDeadline(time.Now().Add(10 * time.Second)) // Prevents hanging reads
			n, err := conn.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Printf("[ERROR] Error reading from %s: %v", remoteAddr, err)
				} else {
					log.Printf("[INFO] Client disconnected from %s", remoteAddr)
				}
				return
			}
			data := make([]byte, n)
			copy(data, buf[:n])

			select {
			case ipRequestQueues[remoteAddr] <- data:
			default:
				log.Printf("[WARN] Request buffer full for IP %s, data discarded", remoteAddr)
			}
		}
	}
}

func processRequestQueue(ip string, serviceConfig ServiceConfig, conn net.Conn) {
	defer func() {
		queueLock.Lock()
		delete(ipRequestQueues, ip)
		queueLock.Unlock()
		log.Printf("[INFO] Process queue for IP %s has been cleared", ip)
	}()

	for data := range ipRequestQueues[ip] {
		if atomic.LoadInt32(&activeGlobalRequests) >= int32(globalRequestLimit) {
			log.Printf("[WARN] Global request limit reached, delaying IP %s", ip)
			time.Sleep(500 * time.Millisecond)
			continue
		}

		atomic.AddInt32(&activeGlobalRequests, 1)
		session := generateSessionID()
		llmResponse, err := queryLLM(data, serviceConfig.Protocol, serviceConfig.Port, session, ip, serviceConfig.UID)
		atomic.AddInt32(&activeGlobalRequests, -1)

		if err != nil {
			log.Printf("[ERROR] Error querying LLM for IP %s: %v. Closing connection.", ip, err)
			writeResponse(conn, []byte("Error processing request\n"))
			return
		}

		if !llmResponse.Continue {
			log.Printf("[INFO] Connection terminated and IP blacklisted: %s", ip)
			blacklistIP(ip)
			writeResponse(conn, []byte("Connection closed\n"))
			return
		}

		responseData, err := hex.DecodeString(llmResponse.ResponseHex)
		if err != nil {
			log.Printf("[ERROR] Failed to decode LLM response hex for IP %s: %v. Closing connection.", ip, err)
			writeResponse(conn, []byte("Error decoding response\n"))
			return
		}

		writeErr := writeResponse(conn, responseData)
		if writeErr != nil {
			log.Printf("[ERROR] Failed to write response to IP %s: %v", ip, writeErr)
			return
		}

		if llmResponse.Delay > 0 {
			time.Sleep(time.Duration(llmResponse.Delay) * time.Millisecond)
		}
	}
}

func sendStatusReport(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(1 * time.Minute):
			uptime := time.Since(startTime).String()
			var m runtime.MemStats
			runtime.ReadMemStats(&m)

			cpuPercent, err := cpu.Percent(0, false)
			if err != nil || len(cpuPercent) == 0 {
				log.Printf("[WARN] CPU stats not available, setting CPU usage to zero: %v", err)
				cpuPercent = []float64{0.0}
			}

			netStats, err := psutilNet.IOCounters(false)
			if err != nil || len(netStats) == 0 {
				log.Printf("[WARN] Network stats not available, setting NetworkBytes to zero: %v", err)
				atomic.StoreUint64(&totalNetworkBytes, 0)
			} else {
				atomic.StoreUint64(&totalNetworkBytes, netStats[0].BytesSent+netStats[0].BytesRecv)
			}

			diskStats, err := disk.Usage("/")
			if err != nil {
				log.Printf("[WARN] Disk stats not available, setting Disk metrics to zero: %v", err)
				diskStats = &disk.UsageStat{}
			}

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
				log.Printf("[ERROR] Failed to marshal status report: %v", err)
				continue
			}

			req, err := http.NewRequest("POST", statusApiUrl, bytes.NewBuffer(requestBody))
			if err != nil {
				log.Printf("[ERROR] Failed to create status report request: %v", err)
				continue
			}
			req.Header.Set("Content-Type", "application/json")

			resp, err := httpClient.Do(req)
			if err != nil {
				log.Printf("[ERROR] Status report request failed: %v", err)
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				var globalBlacklistResponse struct {
					BlacklistedIPs []string `json:"blacklisted_ips"`
				}
				if err := json.NewDecoder(resp.Body).Decode(&globalBlacklistResponse); err != nil {
					log.Printf("[ERROR] Failed to decode global blacklist response: %v", err)
					continue
				}

				mu.Lock()
				for _, ip := range globalBlacklistResponse.BlacklistedIPs {
					globalBlacklist[ip] = struct{}{}
				}
				mu.Unlock()
			} else {
				log.Printf("[ERROR] Status report failed with status: %s", resp.Status)
			}
		}
	}
}

func startTCPService(ctx context.Context, serviceConfig ServiceConfig) error {
	ln, err := net.Listen("tcp", ":"+serviceConfig.Port)
	if err != nil {
		log.Printf("[WARN] Error starting TCP service on port %s: %v", serviceConfig.Port, err)
		return err
	}
	log.Printf("[INFO] TCP service '%s' started on port %s", serviceConfig.UID, serviceConfig.Port)

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					log.Printf("[INFO] Shutting down TCP service on port %s", serviceConfig.Port)
					return
				default:
					log.Printf("[ERROR] Error accepting connection on port %s: %v", serviceConfig.Port, err)
					continue
				}
			}
			go handleConnection(ctx, conn, serviceConfig)
		}
	}()
	return nil
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
		log.Fatal("[FATAL] API key, node UUID, and services are required")
	}

	serviceList := strings.Split(servicesStr, ",")
	var activeServices int
	for _, svc := range serviceList {
		parts := strings.Split(svc, "/")
		if len(parts) != 3 {
			log.Fatalf("[FATAL] Invalid service format: %s. Expected 'port/protocol/uid'", svc)
		}
		service := ServiceConfig{
			Port:     parts[0],
			Protocol: strings.ToLower(parts[1]),
			UID:      parts[2],
		}
		if err := startTCPService(context.Background(), service); err == nil {
			activeServices++
		}
	}

	if activeServices == 0 {
		log.Fatal("[FATAL] No services were successfully started. Exiting.")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancelFunc = cancel

	go sendStatusReport(ctx)

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-c
		log.Println("[INFO] Received termination signal. Shutting down...")
		cancelFunc()
		wg.Wait()
		log.Println("[INFO] Honeypot instance has shut down.")
		os.Exit(0)
	}()

	wg.Wait()
}
