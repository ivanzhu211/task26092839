package vault

import "crypto/sha256"

type testItem struct {
	name string
	ver  int
	data []byte
}

func sha256Raw(b []byte) [32]byte { return sha256.Sum256(b) }
