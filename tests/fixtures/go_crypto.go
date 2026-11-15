// True positives: every Go rule fires on this file.
package main

import (
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"math/rand"
)

func main() {
	// rule 1: RSA key generation (2048 -> weakness 4)
	_, _ = rsa.GenerateKey(rand.Reader, 2048)
	// rule 1: RSA key generation, too small (1024 -> weakness 5)
	_, _ = rsa.GenerateKey(rand.Reader, 1024)
	// rule 3: weak hash
	_ = md5.New()
	_ = sha1.New()
	// rule 4: weak cipher
	_, _ = des.NewCipher([]byte("12345678"))
	// rule 5: weak randomness for a secret
	token := rand.Int()
	_ = token
	// rule 7: TLS verification disabled
	_ = &tls.Config{InsecureSkipVerify: true}
	_ = &tls.Config{MinVersion: tls.VersionTLS10}
}
