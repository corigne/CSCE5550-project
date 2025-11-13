// monitor_fanotify.go
// How to Build: go build -o monitor_fanotify monitor_fanotify.go
//
// How to Run:
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
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/fsnotify/fsnotify"
	"golang.org/x/sys/unix"
)

var (
	targetDir     string
	signatureFile string
	maliciousSigs map[string]bool
	// Protect concurrent access to maliciousSigs
	sigMutex     sync.RWMutex
	dryRun       bool
	accessCh     chan string
	preventionCh chan string

	// Hash cache to avoid re-hashing the same files
	hashCache   map[string]hashCacheEntry
	hashCacheMu sync.RWMutex
	cacheMaxAge = 5 * time.Minute
)

type hashCacheEntry struct {
	hash      string
	timestamp time.Time
}

const (
	// fanotify response values (from linux/fanotify.h) // this took some digging in the headers lol
	FAN_ALLOW = 0x01
	FAN_DENY  = 0x02
)

func init() {
	flag.BoolVar(&dryRun, "dry-run", true, "If true, do not deny opens or kill processes; just log decisions (default: true)")
	flag.StringVar(&targetDir, "dir", "./encrypt_me", "Directory to protect")
	flag.StringVar(&signatureFile, "sigs", "", "File containing malicious executable signatures (one per line)")
	maliciousSigs = make(map[string]bool)
	hashCache = make(map[string]hashCacheEntry)
}

func main() {
	flag.Parse()
	accessCh = startLogger("./access.log")
	preventionCh = startLogger("./prevention.log")

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

	// Start cache cleanup goroutine
	go cleanupHashCache()

	// Start fanotify monitor (blocks open events and responds allow/deny)
	go watchDir(targetDir, accessCh)
	if err := runFanotifyMonitor(targetDir); err != nil {
		log.Fatalf("fanotify monitor failed: %v", err)
	}
}

// Signature helpers
func loadSignatures(filename string) {
	data, err := os.ReadFile(filename)
	if err != nil {
		log.Printf("Warning: Could not load signatures file: %v", err)
		return
	}

	lines := strings.Split(string(data), "\n")

	sigMutex.Lock()
	defer sigMutex.Unlock()

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			maliciousSigs[line] = true
		}
	}
	log.Printf("Loaded %d malicious signatures", len(maliciousSigs))
}

// Fast path: try to get hash from cache first
func getCachedHash(path string, modTime time.Time) (string, bool) {
	hashCacheMu.RLock()
	defer hashCacheMu.RUnlock()

	if entry, ok := hashCache[path]; ok {
		// Cache hit is valid if entry is recent enough
		if time.Since(entry.timestamp) < cacheMaxAge {
			return entry.hash, true
		}
	}
	return "", false
}

func cacheHash(path string, hash string) {
	hashCacheMu.Lock()
	defer hashCacheMu.Unlock()

	hashCache[path] = hashCacheEntry{
		hash:      hash,
		timestamp: time.Now(),
	}
}

func cleanupHashCache() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		hashCacheMu.Lock()
		now := time.Now()
		for path, entry := range hashCache {
			if now.Sub(entry.timestamp) > cacheMaxAge {
				delete(hashCache, path)
			}
		}
		hashCacheMu.Unlock()
	}
}

func calculateFileHashFromFd(fd int) (string, error) {
	// Get file path from fd for caching
	fdPath := fmt.Sprintf("/proc/self/fd/%d", fd)
	realPath, err := os.Readlink(fdPath)
	if err == nil {
		// Check cache first
		if stat, err := os.Stat(realPath); err == nil {
			if hash, ok := getCachedHash(realPath, stat.ModTime()); ok {
				return hash, nil
			}
		}
	}

	// Not in cache, calculate hash
	file := os.NewFile(uintptr(fd), "fanotify_fd")
	if file == nil {
		return "", fmt.Errorf("failed to create file from fd")
	}
	// Don't close the file - we don't own this fd
	// Seek to start
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		// Some fds may not support seek, continue anyway
		// I don't like this but I prefer to highlight this could error rather
		// than not catch it at all
	}

	hash := sha256.New()
	// Use a limited buffer to avoid allocating too much memory
	buf := make([]byte, 32*1024)
	_, err = io.CopyBuffer(hash, file, buf)
	if err != nil {
		return "", err
	}

	hashStr := hex.EncodeToString(hash.Sum(nil))

	// Cache the result if we have a real path
	if realPath != "" {
		cacheHash(realPath, hashStr)
	}

	return hashStr, nil
}

func isHashMalicious(hash string) bool {
	if len(maliciousSigs) == 0 {
		return false
	}

	sigMutex.RLock()
	defer sigMutex.RUnlock()
	return maliciousSigs[hash]
}

// Process helpers
type ProcessInfo struct {
	PID        int
	Name       string
	Executable string
}

// Program: fanotify monitor
// Pre-allocate response buffers to avoid allocations in hot path
var respAllowBuf []byte
var respDenyBuf []byte
var respBufOnce sync.Once

func initResponseBuffers() {
	respBufOnce.Do(func() {
		allowResp := unix.FanotifyResponse{Response: FAN_ALLOW}
		denyResp := unix.FanotifyResponse{Response: FAN_DENY}

		buf := new(bytes.Buffer)
		binary.Write(buf, binary.LittleEndian, allowResp)
		respAllowBuf = buf.Bytes()

		buf.Reset()
		binary.Write(buf, binary.LittleEndian, denyResp)
		respDenyBuf = buf.Bytes()
	})
}

// runFanotifyMonitor sets up fanotify to watch the mount containing targetDir for open-time permission events.
// It will reply to permission events with FAN_ALLOW or FAN_DENY.
func runFanotifyMonitor(target string) error {
	initResponseBuffers()

	var fanFlags uint
	var eventFlags uint
	// Initialize fanotify
	// Use PRE_CONTENT class so we can get permission events and deny before open completes
	fanFlags = unix.FAN_CLASS_PRE_CONTENT | unix.FAN_CLOEXEC | unix.FAN_NONBLOCK
	// event_f_flags: we want file descriptors for open files
	eventFlags = unix.O_RDONLY | unix.O_CLOEXEC

	fd, err := unix.FanotifyInit(fanFlags, eventFlags)
	if err != nil {
		return fmt.Errorf("FanotifyInit failed: %w", err)
	}
	defer unix.Close(fd)

	// Mark the target mount or directory.
	var markFlags uint
	markFlags = unix.FAN_MARK_ADD | unix.FAN_MARK_MOUNT
	// We want open permission events (so we can allow/deny opens)
	mask := uint64(unix.FAN_OPEN_PERM | unix.FAN_CLOSE_WRITE)

	if err := unix.FanotifyMark(fd, markFlags, mask, unix.AT_FDCWD, target); err != nil {
		log.Printf("FanotifyMark mount failed: %v; trying to mark directory directly", err)
		markFlags = unix.FAN_MARK_ADD | unix.FAN_EVENT_ON_CHILD
		if err2 := unix.FanotifyMark(fd, markFlags, mask, unix.AT_FDCWD, target); err2 != nil {
			return fmt.Errorf("FanotifyMark failed (mount and dir): %v and %v", err, err2)
		}
	}

	log.Printf("fanotify initialized and marked. Listening for permission events... (need sudo/root)")

	// Pre-allocate buffer for reading events
	const maxEvents = 10
	metaSize := int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))
	buf := make([]byte, metaSize*maxEvents)

	for {
		n, err := unix.Read(fd, buf)
		if err != nil {
			if err == unix.EAGAIN {
				// Was 50ms, which is too long, system feels sluggish at 50ms
				time.Sleep(10 * time.Millisecond)
				continue
			}
			return fmt.Errorf("fanotify read failed: %w", err)
		}

		// Process all events in the buffer
		for offset := 0; offset < n; {
			if n-offset < metaSize {
				break
			}

			var meta unix.FanotifyEventMetadata
			reader := bytes.NewReader(buf[offset : offset+metaSize])
			if err := binary.Read(reader, binary.LittleEndian, &meta); err != nil {
				log.Printf("Failed to parse metadata: %v", err)
				break
			}

			offset += int(meta.Event_len)

			pid := int(meta.Pid)
			fileFd := int(meta.Fd)

			if fileFd < 0 {
				continue
			}

			// CRITICAL: Only hash if we have signatures loaded
			// Otherwise, always allow to minimize latency
			allow := true
			reason := ""

			if len(maliciousSigs) > 0 {
				// Hash check - this is still the expensive part
				// I wish I had a better way to do this...
				hash, err := calculateFileHashFromFd(fileFd)
				if err == nil && isHashMalicious(hash) {
					allow = false
					reason = fmt.Sprintf("malicious hash: %s", hash)
				}
			}

			// Prepare response - use pre-allocated buffers
			var respBuf []byte
			if allow {
				respBuf = respAllowBuf
			} else {
				respBuf = respDenyBuf
				select {
				case preventionCh <- fmt.Sprintf("DENY pid=%d fd=%d: %s", pid, fileFd, reason):
				default:
					// Channel full, drop log message to avoid blocking
				}
			}

			// Set the Fd field in the response
			binary.LittleEndian.PutUint32(respBuf[0:4], uint32(fileFd))

			// Respond to kernel ASAP (lol not really ASAP, but yeah, idk why I said ASAP here...)
			if _, err := unix.Write(fd, respBuf); err != nil {
				log.Printf("Failed to write response: %v", err)
			}

			// Close the fd after responding
			unix.Close(fileFd)
		}
	}
}

func watchDir(path string, ch chan string) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("Failed to create fsnotify watcher: %v", err)
		return
	}
	defer watcher.Close()

	if err := watcher.Add(path); err != nil {
		log.Printf("Failed to watch directory: %v", err)
		return
	}

	for event := range watcher.Events {
		msg := fmt.Sprintf("fsnotify event: %s %s", event.Op, event.Name)
		// Non-blocking send
		select {
		case ch <- msg:
		default:
			// Channel full, drop message
		}
	}
}

func startLogger(path string) chan string {
	// Increased buffer size, was smaller before...but log was spammy
	ch := make(chan string, 4096)
	go func() {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("failed to open log file: %v", err)
		}
		defer f.Close()

		// Batch writes to reduce syscalls
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		var batch []string
		for {
			select {
			case msg, ok := <-ch:
				if !ok {
					// Channel closed, flush and exit
					if len(batch) > 0 {
						writeBatch(f, batch)
					}
					return
				}
				batch = append(batch, msg)

				// Flush if batch gets too large
				if len(batch) >= 100 {
					writeBatch(f, batch)
					batch = batch[:0]
				}

			case <-ticker.C:
				// Periodic flush
				if len(batch) > 0 {
					writeBatch(f, batch)
					batch = batch[:0]
				}
			}
		}
	}()
	return ch
}

func writeBatch(f *os.File, batch []string) {
	timestamp := time.Now().Format(time.RFC3339)
	for _, msg := range batch {
		line := fmt.Sprintf("%s %s\n", timestamp, msg)
		f.WriteString(line)
		// also print to stdout
		log.Print(msg)
	}
}
