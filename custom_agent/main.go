package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const (
	Version = "1.0.0"
)

type Config struct {
	WazuhManager string   `json:"wazuh_manager"`
	WazuhPort    int      `json:"wazuh_port"`
	AgentName    string   `json:"agent_name"`
	LogPaths     []string `json:"log_paths"`
	PollInterval int      `json:"poll_interval_seconds"`
}

type LogEvent struct {
	Timestamp string                 `json:"timestamp"`
	AgentName string                 `json:"agent_name"`
	Hostname  string                 `json:"hostname"`
	LogFile   string                 `json:"log_file"`
	Message   string                 `json:"message"`
	OS        string                 `json:"os"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

type Agent struct {
	config   Config
	hostname string
	conn     net.Conn
	running  bool
}

func NewAgent(configPath string) (*Agent, error) {
	config, err := loadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %v", err)
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	return &Agent{
		config:   config,
		hostname: hostname,
		running:  false,
	}, nil
}

func loadConfig(configPath string) (Config, error) {
	var config Config
	
	file, err := os.Open(configPath)
	if err != nil {
		return config, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		return config, err
	}

	// Set defaults
	if config.WazuhPort == 0 {
		config.WazuhPort = 1514
	}
	if config.PollInterval == 0 {
		config.PollInterval = 10
	}
	if config.AgentName == "" {
		config.AgentName = "custom-agent"
	}

	return config, nil
}

func (a *Agent) Connect() error {
	address := fmt.Sprintf("%s:%d", a.config.WazuhManager, a.config.WazuhPort)
	log.Printf("Connecting to Wazuh manager at %s...", address)
	
	conn, err := net.DialTimeout("tcp", address, 30*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to Wazuh manager: %v", err)
	}
	
	a.conn = conn
	log.Printf("Successfully connected to Wazuh manager")
	return nil
}

func (a *Agent) Disconnect() {
	if a.conn != nil {
		a.conn.Close()
		log.Printf("Disconnected from Wazuh manager")
	}
}

func (a *Agent) SendEvent(event LogEvent) error {
	if a.conn == nil {
		return fmt.Errorf("not connected to Wazuh manager")
	}

	// Format event as JSON
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %v", err)
	}

	// Send to Wazuh manager
	_, err = a.conn.Write(append(eventJSON, '\n'))
	if err != nil {
		return fmt.Errorf("failed to send event: %v", err)
	}

	return nil
}

func (a *Agent) MonitorLogFile(logPath string, stopCh <-chan struct{}) {
	log.Printf("Starting to monitor log file: %s", logPath)
	
	for {
		select {
		case <-stopCh:
			log.Printf("Stopping monitoring of %s", logPath)
			return
		default:
			file, err := os.Open(logPath)
			if err != nil {
				log.Printf("Error opening log file %s: %v", logPath, err)
				time.Sleep(time.Duration(a.config.PollInterval) * time.Second)
				continue
			}

			// Seek to end of file
			_, err = file.Seek(0, io.SeekEnd)
			if err != nil {
				log.Printf("Error seeking in log file %s: %v", logPath, err)
				file.Close()
				time.Sleep(time.Duration(a.config.PollInterval) * time.Second)
				continue
			}

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := scanner.Text()
				if line != "" {
					event := LogEvent{
						Timestamp: time.Now().UTC().Format(time.RFC3339),
						AgentName: a.config.AgentName,
						Hostname:  a.hostname,
						LogFile:   logPath,
						Message:   line,
						OS:        runtime.GOOS,
					}

					err := a.SendEvent(event)
					if err != nil {
						log.Printf("Error sending event: %v", err)
						// Try to reconnect
						a.Disconnect()
						if err := a.Connect(); err != nil {
							log.Printf("Failed to reconnect: %v", err)
						}
					}
				}
			}

			if err := scanner.Err(); err != nil {
				log.Printf("Error reading log file %s: %v", logPath, err)
			}

			file.Close()
			time.Sleep(time.Duration(a.config.PollInterval) * time.Second)
		}
	}
}

func (a *Agent) CollectSystemLogs(stopCh <-chan struct{}) {
	log.Printf("Starting system log collection...")
	ticker := time.NewTicker(time.Duration(a.config.PollInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			log.Printf("Stopping system log collection")
			return
		case <-ticker.C:
			// Collect basic system information
			event := LogEvent{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				AgentName: a.config.AgentName,
				Hostname:  a.hostname,
				LogFile:   "system",
				Message:   fmt.Sprintf("Agent heartbeat - OS: %s, Arch: %s", runtime.GOOS, runtime.GOARCH),
				OS:        runtime.GOOS,
				Metadata: map[string]interface{}{
					"num_goroutines": runtime.NumGoroutine(),
					"num_cpu":        runtime.NumCPU(),
				},
			}

			err := a.SendEvent(event)
			if err != nil {
				log.Printf("Error sending heartbeat: %v", err)
			}
		}
	}
}

func (a *Agent) Start() error {
	if err := a.Connect(); err != nil {
		return err
	}

	a.running = true
	stopCh := make(chan struct{})

	// Handle shutdown gracefully
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	// Start monitoring each log file
	for _, logPath := range a.config.LogPaths {
		// Expand wildcards
		matches, err := filepath.Glob(logPath)
		if err != nil {
			log.Printf("Error expanding path %s: %v", logPath, err)
			continue
		}

		if len(matches) == 0 {
			log.Printf("Warning: No files match pattern %s", logPath)
			continue
		}

		for _, match := range matches {
			go a.MonitorLogFile(match, stopCh)
		}
	}

	// Start system log collection
	go a.CollectSystemLogs(stopCh)

	log.Printf("Wazuh custom agent v%s is running...", Version)
	log.Printf("Agent Name: %s", a.config.AgentName)
	log.Printf("Hostname: %s", a.hostname)
	log.Printf("Monitoring %d log paths", len(a.config.LogPaths))

	// Wait for shutdown signal
	<-sigCh
	log.Printf("Shutdown signal received, stopping agent...")
	
	a.running = false
	close(stopCh)
	
	// Allow goroutines to finish
	time.Sleep(2 * time.Second)
	
	a.Disconnect()
	log.Printf("Agent stopped gracefully")
	
	return nil
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	configPath := "config.json"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		log.Printf("Config file not found: %s", configPath)
		log.Printf("Usage: %s [config_path]", os.Args[0])
		os.Exit(1)
	}

	agent, err := NewAgent(configPath)
	if err != nil {
		log.Fatalf("Failed to create agent: %v", err)
	}

	if err := agent.Start(); err != nil {
		log.Fatalf("Agent failed: %v", err)
	}
}
