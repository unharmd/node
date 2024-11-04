// honeypot.go
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ServiceConfig holds the configuration for each honeypot service.
type ServiceConfig struct {
	Port     string `json:"port"`
	Protocol string `json:"protocol"`
	UID      string `json:"uid"`
}

var (
	servicesStr          string
	llmApiUrl            string
	apiKey               string
	nodeUUID             string
	globalRequestLimit   int
	activeGlobalRequests int32
	httpClient           *http.Client
	wg                   sync.WaitGroup
	cancelFunc           context.CancelFunc
)

func initHTTPClient() {
	httpClient = &http.Client{
		Timeout: 180 * time.Second, // Increased timeout for LLM response
	}
	log.Printf("[INFO] HTTP client initialized with timeout of 180 seconds")
}

// startProtocolService starts either an HTTP or HTTPS service based on the protocol.
func startProtocolService(ctx context.Context, serviceConfig ServiceConfig) error {
	if serviceConfig.Protocol == "http" {
		return startHTTPService(ctx, serviceConfig)
	} else if serviceConfig.Protocol == "https" {
		return startHTTPSServer(ctx, serviceConfig)
	}
	log.Printf("[WARN] Unsupported protocol '%s' on port %s", serviceConfig.Protocol, serviceConfig.Port)
	return fmt.Errorf("unsupported protocol: %s", serviceConfig.Protocol)
}

// startHTTPService starts an HTTP server honeypot on the specified port.
func startHTTPService(ctx context.Context, serviceConfig ServiceConfig) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleLLMRequest(w, r, "http", serviceConfig)
	})

	server := &http.Server{Addr: ":" + serviceConfig.Port, Handler: mux}
	go func() {
		<-ctx.Done()
		server.Close()
	}()
	log.Printf("[INFO] HTTP service started on port %s", serviceConfig.Port)
	return server.ListenAndServe()
}

// startHTTPSServer starts an HTTPS server honeypot on the specified port.
func startHTTPSServer(ctx context.Context, serviceConfig ServiceConfig) error {
	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		return fmt.Errorf("failed to load SSL certificates: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleLLMRequest(w, r, "https", serviceConfig)
	})

	server := &http.Server{
		Addr:      ":" + serviceConfig.Port,
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}
	go func() {
		<-ctx.Done()
		server.Close()
	}()
	log.Printf("[INFO] HTTPS service started on port %s", serviceConfig.Port)
	return server.ListenAndServeTLS("", "")
}

// handleLLMRequest handles incoming HTTP/HTTPS requests and sends them to the LLM for a response.
func handleLLMRequest(w http.ResponseWriter, r *http.Request, protocol string, serviceConfig ServiceConfig) {
	if atomic.LoadInt32(&activeGlobalRequests) >= int32(globalRequestLimit) {
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}
	atomic.AddInt32(&activeGlobalRequests, 1)
	defer atomic.AddInt32(&activeGlobalRequests, -1)

	// Prepare input data for LLM
	inputData := []byte(r.URL.String())
	llmResponse, err := queryLLM(inputData, protocol, serviceConfig.Port, r.RemoteAddr, serviceConfig.UID)
	if err != nil {
		http.Error(w, "Error processing request", http.StatusInternalServerError)
		return
	}

	// Handle delay if specified
	if llmResponse.Delay > 0 {
		time.Sleep(time.Duration(llmResponse.Delay) * time.Millisecond)
	}

	// Set headers from the LLM response
	for header, values := range llmResponse.Headers {
		for _, value := range values {
			w.Header().Add(header, value)
		}
	}

	// Set status code from the LLM response
	w.WriteHeader(llmResponse.StatusCode)

	// Write either binary or text response
	if len(llmResponse.BinaryResponse) > 0 {
		binaryData, err := hex.DecodeString(llmResponse.BinaryResponse)
		if err == nil {
			w.Write(binaryData)
		} else {
			log.Printf("[ERROR] Failed to decode binary response: %v", err)
		}
	} else {
		w.Write([]byte(llmResponse.TextResponse))
	}

	// If continue is false, do not process further requests from this connection
	if !llmResponse.Continue {
		return
	}
}

// LLMResponse represents the response from the LLM API, including headers, body, delay, and whether to continue.
type LLMResponse struct {
	StatusCode     int                 `json:"statuscode"`
	Headers        map[string][]string `json:"headers"`
	TextResponse   string              `json:"textresponse"`
	BinaryResponse string              `json:"binaryresponse"`
	Delay          int                 `json:"delay"`
	Continue       bool                `json:"continue"`
}

// queryLLM sends a request to the LLM API with the given input data and protocol details and receives a response.
func queryLLM(inputData []byte, protocol, port, remoteIP, service string) (*LLMResponse, error) {
	requestData := map[string]interface{}{
		"node":      nodeUUID,
		"token":     apiKey,
		"input":     hex.EncodeToString(inputData),
		"protocol":  protocol,
		"port":      port,
		"remote_ip": remoteIP,
		"service":   service,
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

func main() {
	initHTTPClient()

	flag.StringVar(&servicesStr, "services", "", "List of services in 'port/protocol/uid' format, separated by commas")
	flag.StringVar(&llmApiUrl, "llm-api", "http://localhost:8080/llm", "LLM API URL")
	flag.StringVar(&apiKey, "api-key", "", "API key for authentication")
	flag.StringVar(&nodeUUID, "node-uuid", "", "Node UUID for identifying this honeypot instance")
	flag.IntVar(&globalRequestLimit, "global-limit", 4, "Maximum global concurrent requests allowed")
	flag.Parse()

	if apiKey == "" || nodeUUID == "" || servicesStr == "" {
		log.Fatal("[FATAL] API key, node UUID, and services are required")
	}

	serviceList := strings.Split(servicesStr, ",")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancelFunc = cancel

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
		wg.Add(1)
		go func(svc ServiceConfig) {
			defer wg.Done()
			if err := startProtocolService(ctx, svc); err != nil {
				log.Printf("[ERROR] Failed to start service %s: %v", svc.UID, err)
			}
		}(service)
	}

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
