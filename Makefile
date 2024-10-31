# Makefile for Honeypot Project

# Variables
BINARY_NAME=unharmd-node
CMD_DIR=unharmd
SRC=$(CMD_DIR)/main.go
BUILD_DIR=build

# Default target
all: build

# Build the Go binary for multiple environments
build: clean
	@echo "Building the Go binary for multiple environments..."
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(SRC)
	GOOS=linux GOARCH=arm64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 $(SRC)
	GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe $(SRC)
	GOOS=darwin GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 $(SRC)
	GOOS=darwin GOARCH=arm64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 $(SRC)

# Run the binary with default configuration (for current OS)
run: build
	@echo "Running the $(BINARY_NAME) binary..."
	./$(BUILD_DIR)/$(BINARY_NAME)-$(shell go env GOOS)-$(shell go env GOARCH) \
		-services="80/tcp/HTTP,22/tcp/SSH" \
		-llm-api="http://localhost:8080/llm" \
		-report-api="http://localhost:8080/report" \
		-api-key="YOUR_API_KEY" \
		-log-file="attacks.log" \
		-conn-limit=5 \
		-cache-limit=100

# Clean up the binary and any build artifacts
clean:
	@echo "Cleaning up..."
	rm -rf $(BUILD_DIR)/*

# Tidy up Go modules
tidy:
	@echo "Tidying up Go modules..."
	go mod tidy

# Format the Go code
fmt:
	@echo "Formatting Go code..."
	go fmt ./...

# Lint the Go code (requires golangci-lint installed)
lint:
	@echo "Linting Go code..."
	golangci-lint run

# Run tests
test:
	@echo "Running tests..."
	go test ./...

# Help menu
help:
	@echo "Makefile for Honeypot Project"
	@echo ""
	@echo "Usage:"
	@echo "  make          - Build the binary"
	@echo "  make run      - Build and run the binary with default config"
	@echo "  make clean    - Remove the binary and any build artifacts"
	@echo "  make tidy     - Clean up Go module dependencies"
	@echo "  make fmt      - Format Go code"
	@echo "  make lint     - Lint Go code (requires golangci-lint)"
	@echo "  make test     - Run tests"
	@echo "  make help     - Show this help message"
