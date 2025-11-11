package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <executable_path>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Generates SHA256 signature for an executable\n")
		os.Exit(1)
	}

	execPath := os.Args[1]

	file, err := os.Open(execPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		fmt.Fprintf(os.Stderr, "Error calculating hash: %v\n", err)
		os.Exit(1)
	}

	signature := hex.EncodeToString(hash.Sum(nil))
	fmt.Printf("%s\n", signature)
}
