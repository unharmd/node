// honeypot.go
package main

import (
	"bytes"
	"container/list"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ServiceConfig represents the configuration for a service to be simulated.
type ServiceConfig struct {
	Port     string `json:"port"`
	Protocol string `json:"protocol"`
	Service  string `json:"service"`
}

// LLMRequest is used for requests to the LLM API.
type LLMRequest struct {
	NodeUUID string `json:"node_uuid"`
	Token    string `json:"token"`
	InputHex string `json:"input_hex"`
	Service  string `json:"service"`
	Protocol string `json:"protocol"`
	Port     string `json:"port"`
}

// LLMResponse represents the response from the LLM API.
type LLMResponse struct {
	IsAttack        bool   `json:"is_attack"`
	AttackType      string `json:"attack_type"`
	ResponseHex     string `json:"response_hex"`
	AttackGroupKey  string `json:"attack_group_key"`
	AdditionalNotes string `json:"additional_notes"`
}

// CacheEntry represents a single cache entry with the response and element position.
type CacheEntry struct {
	Response LLMResponse
	Element  *list.Element
}

var (
	servicesStr       string
	configFile        string
	services          []ServiceConfig
	llmApiUrl         string
	reportApiUrl      string
	apiKey            string
	authToken         string
	nodeUUID          string
	wg                sync.WaitGroup
	attackLogFilePath string
	connLimit         int
	activeConns       = make(map[string]int)
	blacklist         = make(map[string]time.Time)
	mu                sync.Mutex
	cache             = make(map[string]*CacheEntry)
	cacheOrder        = list.New()
	cacheLimit        int
)

// LRU cache management functions

// addToCache adds a new entry to the cache and evicts the oldest if limit is reached.
func addToCache(key string, response LLMResponse) {
	if entry, found := cache[key]; found {
		cacheOrder.MoveToFront(entry.Element)
		return
	}

	if cacheOrder.Len() >= cacheLimit {
		oldest := cacheOrder.Back()
		if oldest != nil {
			delete(cache, oldest.Value.(string))
			cacheOrder.Remove(oldest)
		}
	}

	element := cacheOrder.PushFront(key)
	cache[key] = &CacheEntry{Response: response, Element: element}
}

// getFromCache retrieves an entry from the cache and moves it to the front.
func getFromCache(key string) (*LLMResponse, bool) {
	if entry, found := cache[key]; found {
		cacheOrder.MoveToFront(entry.Element)
		return &entry.Response, true
	}
	return nil, false
}

// Blacklisting functions

func blacklistIP(ip string) {
	mu.Lock()
	defer mu.Unlock()
	blacklist[ip] = time.Now().Add(1 * time.Hour)
}

func isBlacklisted(ip string) bool {
	mu.Lock()
	defer mu.Unlock()
	expiry, exists := blacklist[ip]
	return exists && time.Now().Before(expiry)
}

// Functions for querying LLM and reporting attacks

// queryLLM sends data to the LLM and caches the response.
func queryLLM(inputData []byte, service, protocol, port string) (*LLMResponse, error) {
	inputHex := hex.EncodeToString(inputData)

	if cachedResponse, found := getFromCache(inputHex); found {
		return cachedResponse, nil
	}

	requestData := LLMRequest{
		NodeUUID: nodeUUID,
		Token:    authToken,
		InputHex: inputHex,
		Service:  service,
		Protocol: protocol,
		Port:     port,
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
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiKey))
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("LLM API request failed: %v", err)
	}
	defer resp.Body.Close()

	var llmResponse LLMResponse
	if err := json.NewDecoder(resp.Body).Decode(&llmResponse); err != nil {
		return nil, fmt.Errorf("failed to decode LLM API response: %v", err)
	}

	addToCache(inputHex, llmResponse)
	return &llmResponse, nil
}

// reportAttack sends a report of detected attacks to the report API.
func reportAttack(inputData []byte, service, protocol, port string, llmResponse *LLMResponse, remoteAddr string) {
	inputHex := hex.EncodeToString(inputData)

	attackData := map[string]interface{}{
		"node_uuid":        nodeUUID,
		"token":            authToken,
		"input_hex":        inputHex,
		"service":          service,
		"protocol":         protocol,
		"port":             port,
		"attack_type":      llmResponse.AttackType,
		"attack_group_key": llmResponse.AttackGroupKey,
		"timestamp":        time.Now().UTC().Format(time.RFC3339),
		"additional_notes": llmResponse.AdditionalNotes,
		"source_ip":        remoteAddr,
	}

	requestBody, err := json.Marshal(attackData)
	if err != nil {
		log.Printf("Failed to marshal attack report: %v", err)
		return
	}
	req, err := http.NewRequest("POST", reportApiUrl, bytes.NewBuffer(requestBody))
	if err != nil {
		log.Printf("Failed to create attack report request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiKey))
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Attack report request failed: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("Attack report failed with status: %s", resp.Status)
	}
}

// handleConnection processes a TCP connection, sending data to LLM and reporting attacks if detected.
func handleConnection(conn net.Conn, service, protocol, port string) {
	defer conn.Close()
	remoteAddr := conn.RemoteAddr().String()
	if isBlacklisted(remoteAddr) {
		log.Printf("Blocked connection from blacklisted IP: %s", remoteAddr)
		return
	}

	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("Error reading from %s: %v", remoteAddr, err)
			}
			break
		}
		data := buf[:n]
		llmResponse, err := queryLLM(data, service, protocol, port)
		if err != nil {
			log.Printf("Error querying LLM: %v", err)
			continue
		}
		if llmResponse.IsAttack {
			reportAttack(data, service, protocol, port, llmResponse, remoteAddr)
		}
		responseData, _ := hex.DecodeString(llmResponse.ResponseHex)
		conn.Write(responseData)
	}
}

// TCP and UDP service functions

func startTCPService(port, service string) {
	defer wg.Done()
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("Error starting TCP service on port %s: %v", port, err)
	}
	log.Printf("TCP service '%s' started on port %s", service, port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Error accepting connection on port %s: %v", port, err)
			continue
		}
		go handleConnection(conn, service, "tcp", port)
	}
}

func startUDPService(port, service string) {
	defer wg.Done()
	p, err := strconv.Atoi(port)
	if err != nil {
		log.Fatalf("Invalid port number: %s", port)
	}
	addr := net.UDPAddr{Port: p, IP: net.ParseIP("0.0.0.0")}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		log.Fatalf("Error starting UDP service on port %s: %v", port, err)
	}
	log.Printf("UDP service '%s' started on port %s", service, port)
	buf := make([]byte, 4096)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("Error reading from UDP on port %s: %v", port, err)
			continue
		}
		data := buf[:n]
		llmResponse, err := queryLLM(data, service, "udp", port)
		if err != nil {
			log.Printf("Error querying LLM: %v", err)
			continue
		}
		if llmResponse.IsAttack {
			reportAttack(data, service, "udp", port, llmResponse, remoteAddr.String())
		}
		responseData, _ := hex.DecodeString(llmResponse.ResponseHex)
		conn.WriteToUDP(responseData, remoteAddr)
	}
}

// Helper function for parsing services
func parseServices() {
	if servicesStr != "" {
		serviceList := strings.Split(servicesStr, ",")
		for _, svc := range serviceList {
			parts := strings.Split(svc, "/")
			if len(parts) != 3 {
				log.Fatalf("Invalid service format: %s. Expected 'port/protocol/service'", svc)
			}
			services = append(services, ServiceConfig{
				Port:     parts[0],
				Protocol: strings.ToLower(parts[1]),
				Service:  parts[2],
			})
		}
	} else if configFile != "" {
		data, err := os.ReadFile(configFile)
		if err != nil {
			log.Fatalf("Error reading config file: %v", err)
		}
		var cfg struct {
			Services []ServiceConfig `json:"services"`
		}
		err = json.Unmarshal(data, &cfg)
		if err != nil {
			log.Fatalf("Error parsing config file: %v", err)
		}
		services = cfg.Services
	} else {
		log.Fatal("No services specified. Use the -services flag or -config file.")
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flag.StringVar(&servicesStr, "services", "", "List of services in 'port/protocol/service' format, separated by commas")
	flag.StringVar(&configFile, "config", "", "Path to JSON configuration file")
	flag.StringVar(&llmApiUrl, "llm-api", "http://localhost:8080/llm", "LLM API URL")
	flag.StringVar(&reportApiUrl, "report-api", "http://localhost:8080/report", "Central report API URL")
	flag.StringVar(&apiKey, "api-key", "", "API key for authentication")
	flag.StringVar(&authToken, "auth-token", "", "Token for authenticating with APIs")
	flag.StringVar(&nodeUUID, "node-uuid", "", "Node UUID for identifying this honeypot instance")
	flag.StringVar(&attackLogFilePath, "log-file", "attacks.log", "Path to attack log file")
	flag.IntVar(&connLimit, "conn-limit", 5, "Maximum concurrent connections per IP")
	flag.IntVar(&cacheLimit, "cache-limit", 100, "Maximum number of items in the response cache")
	flag.Parse()

	if apiKey == "" || authToken == "" || nodeUUID == "" {
		log.Fatal("API key, auth token, and node UUID are required")
	}

	parseServices()
	for _, svc := range services {
		wg.Add(1)
		switch svc.Protocol {
		case "tcp":
			go startTCPService(svc.Port, svc.Service)
		case "udp":
			go startUDPService(svc.Port, svc.Service)
		default:
			log.Fatalf("Unsupported protocol: %s", svc.Protocol)
		}
	}
	wg.Wait()
}
