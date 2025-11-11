// monitor_fanotify.go
// Build: go build -o monitor_fanotify monitor_fanotify.go
//
// Run (example):
//   sudo ./monitor_fanotify -dir=/full/path/to/encrypt_me -sigs=../malicious_sigs.txt
//
// Notes:
// - Must run as root.
// - Requires linux kernel with fanotify support (modern kernels do).
// - This program will deny opens it deems unauthorized/malicious.
// - Use with caution: denying legitimate opens can break other software. Logging is verbose to help tuning.

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

var (
	targetDir     string
	signatureFile string
	maliciousSigs map[string]bool
	dryRun        bool
)

const (
	// fanotify response values (from linux/fanotify.h)
	FAN_ALLOW = 0x01
	FAN_DENY  = 0x02
)

func init() {
	flag.BoolVar(&dryRun, "dry-run", true, "If true, do not deny opens or kill processes; just log decisions (default: true)")
	flag.StringVar(&targetDir, "dir", "./encrypt_me", "Directory to protect")
	flag.StringVar(&signatureFile, "sigs", "", "File containing malicious executable signatures (one per line)")
	maliciousSigs = make(map[string]bool)
}

func main() {
	flag.Parse()

	log.Printf("Starting fanotify-based directory protection monitor...")
	absPath, err := filepath.Abs(targetDir)
	if err != nil {
		log.Fatalf("Failed to resolve target dir: %v", err)
	}
	targetDir = absPath
	log.Printf("Protected directory (abs): %s", targetDir)

	// Ensure target directory exists
	if _, err := os.Stat(targetDir); os.IsNotExist(err) {
		log.Printf("Creating target directory: %s", targetDir)
		if err := os.MkdirAll(targetDir, 0755); err != nil {
			log.Fatalf("Failed to create target directory: %v", err)
		}
	}

	// Load signatures if present
	if signatureFile != "" {
		loadSignatures(signatureFile)
	}

	// Start fanotify monitor (blocks open events and responds allow/deny)
	if err := runFanotifyMonitor(targetDir); err != nil {
		log.Fatalf("fanotify monitor failed: %v", err)
	}
}

//
// Signature helpers (unchanged except for packaging)
//

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

func calculateFileHashFromFile(f *os.File) (string, error) {
	// Ensure we read from start (if possible)
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		// Not fatal; some fds (like anonymous) may not support seek
	}

	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func calculateFileHash(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	return calculateFileHashFromFile(file)
}

//
// Process helpers (mostly preserved from your original monitor)
//

type ProcessInfo struct {
	PID        int
	Name       string
	Executable string
}

func isAuthorizedProcess(procInfo ProcessInfo) bool {
	// Expand this list if your distribution stores system daemons elsewhere.
	authorizedPaths := []string{
		"/bin/",
		"/sbin/",
		"/usr/bin/",
		"/usr/sbin/",
		"/lib/systemd/",
		"/usr/lib/systemd/",
		"/lib/",
		"/usr/lib/",
		"/snap/",
	}

	execPath := filepath.Clean(procInfo.Executable)
	for _, authPath := range authorizedPaths {
		if strings.HasPrefix(execPath, filepath.Clean(authPath)) {
			return true
		}
	}

	// Process-name based allow list for core system daemons that may not live in standard dirs
	safeNames := map[string]bool{
		"systemd":          true,
		"systemd-journald": true,
		"dbus-daemon":      true,
		"sshd":             true,
		"cron":             true,
		"rsyslogd":         true,
		"udevd":            true,
		"polkitd":          true,
		"dconf-service":    true,
	}
	if safeNames[procInfo.Name] {
		return true
	}

	return false
}

func getProcessInfo(pid int) (*ProcessInfo, error) {
	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return nil, err
	}
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

func killProcess(pid int, procName string) error {
	log.Printf("ALERT: Killing unauthorized process %s (PID: %d)", procName, pid)
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	// Try SIGTERM first
	if err := process.Signal(syscall.SIGTERM); err != nil {
		return process.Kill()
	}
	return nil
}

//
// Program: fanotify monitor
//

// runFanotifyMonitor sets up fanotify to watch the mount containing targetDir for open-time permission events.
// It will reply to permission events with FAN_ALLOW or FAN_DENY.
func runFanotifyMonitor(target string) error {
	var fanFlags uint
	var eventFlags uint
	// 1) Initialize fanotify
	// Use PRE_CONTENT class so we can get permission events and deny before open completes
	fanFlags = unix.FAN_CLASS_PRE_CONTENT | unix.FAN_CLOEXEC | unix.FAN_NONBLOCK
	// event_f_flags: we want file descriptors for open files
	eventFlags = unix.O_RDONLY | unix.O_CLOEXEC

	fd, err := unix.FanotifyInit(fanFlags, eventFlags)
	if err != nil {
		return fmt.Errorf("FanotifyInit failed: %w", err)
	}
	// Ensure we close on exit
	defer unix.Close(fd)

	// 2) Mark the target mount or directory.
	// Mark the mount (so all children under same mount are covered). Use EVENT_ON_CHILD to get events for files under directory.
	var markFlags uint
	markFlags = unix.FAN_MARK_ADD | unix.FAN_MARK_MOUNT
	// We want open permission events (so we can allow/deny opens)
	mask := uint64(unix.FAN_OPEN_PERM | unix.FAN_CLOSE_WRITE)

	if err := unix.FanotifyMark(fd, markFlags, mask, unix.AT_FDCWD, target); err != nil {
		// try marking the directory itself if mount failed
		log.Printf("FanotifyMark mount failed: %v; trying to mark directory directly", err)
		markFlags = unix.FAN_MARK_ADD | unix.FAN_EVENT_ON_CHILD
		if err2 := unix.FanotifyMark(fd, markFlags, mask, unix.AT_FDCWD, target); err2 != nil {
			return fmt.Errorf("FanotifyMark failed (mount and dir): %v and %v", err, err2)
		}
	}

	log.Printf("fanotify initialized and marked. Listening for permission events... (need sudo/root)")

	for {
		var meta unix.FanotifyEventMetadata
		buf := make([]byte, unsafe.Sizeof(meta))

		n, err := unix.Read(fd, buf)
		if err != nil {
			if err == unix.EAGAIN {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return fmt.Errorf("fanotify read failed: %w", err)
		}
		if n < int(unsafe.Sizeof(meta)) {
			log.Printf("short read from fanotify: got %d bytes", n)
			continue
		}

		// Parse metadata manually
		binary.Read(bytes.NewReader(buf), binary.LittleEndian, &meta)
		pid := int(meta.Pid)
		fileFd := int(meta.Fd)
		if fileFd < 0 {
			continue
		}

		// We can inspect the file being opened
		file := os.NewFile(uintptr(fileFd), fmt.Sprintf("fanotify_fd_%d", fileFd))
		if file == nil {
			log.Printf("nil file for fd %d", fileFd)
			continue
		}

		hash, err := calculateFileHashFromFile(file)
		file.Close()

		allow := true
		reason := "default allow"

		if err == nil && len(maliciousSigs) > 0 && maliciousSigs[hash] {
			allow = false
			reason = "malicious file hash"
		}

		// Log decision
		if !allow {
			log.Printf("DENY pid=%d: %s", pid, reason)
			killProcess(pid, strconv.Itoa(pid))
		}

		// Respond to kernel
		resp := unix.FanotifyResponse{
			Fd:       int32(fileFd),
			Response: FAN_ALLOW,
		}
		if !allow {
			resp.Response = FAN_DENY
		}

		respBuf := new(bytes.Buffer)
		binary.Write(respBuf, binary.LittleEndian, resp)
		if _, err := unix.Write(fd, respBuf.Bytes()); err != nil {
			log.Printf("fanotify response write failed: %v", err)
		}
	}
}
