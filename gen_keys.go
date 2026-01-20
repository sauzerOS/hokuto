package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
)

func main() {
	pub, priv, _ := ed25519.GenerateKey(nil)
	fmt.Printf("Private (save to /etc/hokuto/hokuto.key): %s\nPublic (use in sign.go): %s\n", hex.EncodeToString(priv), hex.EncodeToString(pub))
}
