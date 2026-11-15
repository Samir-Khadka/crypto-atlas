// Clean: good patterns and known false-positive traps. Zero findings.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
)

func main() {
	// good: SHA-256, crypto/rand, a default TLS config
	_ = sha256.New()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	_ = &tls.Config{MinVersion: tls.VersionTLS13}
}
