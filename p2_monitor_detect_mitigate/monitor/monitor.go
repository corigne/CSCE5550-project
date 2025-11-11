package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
)

var (
	targetDir       string
	signatureFile   string
	maliciousSigs   map[string]bool
	monitorNewProcs bool
)

// Process information structure
type ProcessInfo struct {
	PID        int
	Name       string
	Executable string
}

func init() {
	flag.StringVar(&targetDir, "dir", "./encrypt_me", "Directory to protect")
	flag.StringVar(&signatureFile, "sigs", "", "File containing malicious executable signatures (one per line)")
	flag.BoolVar(&monitorNewProcs, "monitor-procs", true, "Monitor new processes for malicious signatures")
	maliciousSigs = make(map[string]bool)
}

func main() {
	flag.Parse()

	log.Printf("Starting directory protection monitor...")
	log.Printf("Protected directory: %s", targetDir)

	// Ensure target directory exists
	if _, err := os.Stat(targetDir); os.IsNotExist(err) {
		log.Printf("Creating target directory: %s", targetDir)
		if err := os.MkdirAll(targetDir, 0755); err != nil {
			log.Fatalf("Failed to create target directory: %v", err)
		}
	}

	// Load malicious signatures if provided
	if signatureFile != "" {
		loadSignatures(signatureFile)
	}

	// Start process monitoring in background
	if monitorNewProcs {
		go monitorProcesses()
	}

	// Start directory monitoring
	if err := monitorDirectory(); err != nil {
		log.Fatalf("Directory monitoring failed: %v", err)
	}
}

// Load malicious executable signatures from file
func loadSignatures(filename string) {
	data, err := os.ReadFile(filename)
	if err != nil {
		log.Printf("Warning: Could not load signatures file: %v", err)
		return
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			maliciousSigs[line] = true
		}
	}
	log.Printf("Loaded %d malicious signatures", len(maliciousSigs))
}

// Calculate SHA256 hash of a file
func calculateFileHash(filepath string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// Check if a process is authorized (system binary)
func isAuthorizedProcess(procInfo ProcessInfo) bool {
	// List of authorized system directories
	authorizedPaths := []string{
		"/bin/",
		"/sbin/",
		"/usr/bin/",
		"/usr/sbin/",
		"/lib/systemd/",
	}

	execPath := procInfo.Executable
	for _, authPath := range authorizedPaths {
		if strings.HasPrefix(execPath, authPath) {
			return true
		}
	}

	return false
}

// Get process information from PID
func getProcessInfo(pid int) (*ProcessInfo, error) {
	// Read executable path from /proc/<pid>/exe
	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return nil, err
	}

	// Read command name from /proc/<pid>/comm
	commData, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return nil, err
	}

	return &ProcessInfo{
		PID:        pid,
		Name:       strings.TrimSpace(string(commData)),
		Executable: exePath,
	}, nil
}

// Get the PID that accessed a file (this is tricky and requires checking recent file operations)
func getAccessingPID(filepath string) (int, error) {
	// Use lsof to find which process has the file open
	cmd := exec.Command("lsof", "-t", filepath)
	output, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("no process found accessing file")
	}

	pidStr := strings.TrimSpace(string(output))
	if pidStr == "" {
		return 0, fmt.Errorf("no PID found")
	}

	// If multiple PIDs, take the first one
	pids := strings.Split(pidStr, "\n")
	pid, err := strconv.Atoi(pids[0])
	if err != nil {
		return 0, err
	}

	return pid, nil
}

// Kill a process
func killProcess(pid int, procName string) error {
	log.Printf("ALERT: Killing unauthorized process %s (PID: %d)", procName, pid)

	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}

	// Try SIGTERM first
	if err := process.Signal(syscall.SIGTERM); err != nil {
		// If SIGTERM fails, use SIGKILL
		return process.Kill()
	}

	return nil
}

// Monitor directory for unauthorized access
func monitorDirectory() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()

	// Add directory to watcher
	absPath, err := filepath.Abs(targetDir)
	if err != nil {
		return err
	}

	if err := watcher.Add(absPath); err != nil {
		return err
	}

	log.Printf("Monitoring directory: %s", absPath)

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}

			// Check for write/create/remove operations
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove) != 0 {
				log.Printf("Detected %s operation on: %s", event.Op.String(), event.Name)

				// Small delay to allow process to establish file handle
				time.Sleep(100 * time.Millisecond)

				// Try to find the accessing process
				pid, err := getAccessingPID(event.Name)
				if err != nil {
					// If we can't find the PID with lsof, scan recent processes
					log.Printf("Could not identify accessing process directly: %v", err)
					continue
				}

				procInfo, err := getProcessInfo(pid)
				if err != nil {
					log.Printf("Could not get process info for PID %d: %v", pid, err)
					continue
				}

				log.Printf("Process accessing file: %s (PID: %d, Path: %s)",
					procInfo.Name, procInfo.PID, procInfo.Executable)

				// Check if process is authorized
				if !isAuthorizedProcess(*procInfo) {
					log.Printf("ALERT: Unauthorized process detected!")
					log.Printf("  Process: %s", procInfo.Name)
					log.Printf("  PID: %d", procInfo.PID)
					log.Printf("  Executable: %s", procInfo.Executable)

					// Kill the unauthorized process
					if err := killProcess(procInfo.PID, procInfo.Name); err != nil {
						log.Printf("ERROR: Failed to kill process: %v", err)
					} else {
						log.Printf("SUCCESS: Terminated unauthorized process")
					}
				} else {
					log.Printf("Authorized system process: %s", procInfo.Executable)
				}
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			log.Printf("Watcher error: %v", err)
		}
	}
}

// Monitor new processes and check against known malicious signatures
func monitorProcesses() {
	log.Printf("Starting process monitor...")

	// Track seen processes to avoid duplicate checks
	seenProcs := make(map[int]bool)

	// Initial scan of existing processes
	initialProcs := scanProcesses()
	for _, pid := range initialProcs {
		seenProcs[pid] = true
	}

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		currentProcs := scanProcesses()

		// Check for new processes
		for _, pid := range currentProcs {
			if seenProcs[pid] {
				continue
			}

			seenProcs[pid] = true

			// Get process info
			procInfo, err := getProcessInfo(pid)
			if err != nil {
				continue
			}

			// Skip if authorized system process
			if isAuthorizedProcess(*procInfo) {
				continue
			}

			// Check signature if we have malicious signatures loaded
			if len(maliciousSigs) > 0 {
				hash, err := calculateFileHash(procInfo.Executable)
				if err != nil {
					continue
				}

				if maliciousSigs[hash] {
					log.Printf("ALERT: Malicious executable detected in memory!")
					log.Printf("  Process: %s", procInfo.Name)
					log.Printf("  PID: %d", procInfo.PID)
					log.Printf("  Executable: %s", procInfo.Executable)
					log.Printf("  Signature: %s", hash)

					if err := killProcess(procInfo.PID, procInfo.Name); err != nil {
						log.Printf("ERROR: Failed to kill malicious process: %v", err)
					} else {
						log.Printf("SUCCESS: Terminated malicious process")
					}
				}
			}
		}
	}
}

// Scan /proc for all current process PIDs
func scanProcesses() []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}

	var pids []int
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Check if directory name is a number (PID)
		if pid, err := strconv.Atoi(entry.Name()); err == nil {
			pids = append(pids, pid)
		}
	}

	return pids
}

// Utility function to generate signature for an executable
func GenerateSignature(executablePath string) {
	hash, err := calculateFileHash(executablePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error calculating hash: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(hash)
}
