package vault

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"time"
)

// versionMeta is the per-version metadata record stored as JSON next to the ciphertext.
type versionMeta struct {
	Version uint64 `json:"v"`
	Size    int64  `json:"s"`
	SHA256  string `json:"h"` // hex-encoded plaintext SHA-256
	Time    string `json:"t"` // RFC3339Nano upload time
	KEKGen  uint64 `json:"g"` // generation of the KEK that wraps DEK
	DEK     string `json:"d"` // base64 of KEK-wrapped per-version data key
}

// kekFile is the on-disk wrapped KEK record.
type kekFile struct {
	Gen     uint64 `json:"gen"`
	Wrapped string `json:"wrapped"` // base64 of root-secret-wrapped KEK
}

// rotateJournal records an in-progress key rotation.
type rotateJournal struct {
	OldGen  uint64 `json:"old"`
	NewGen  uint64 `json:"new"`
	Wrapped string `json:"wrapped"` // base64 of root-secret-wrapped new KEK
}

func encodeMeta(m *versionMeta) []byte {
	data, err := json.Marshal(m)
	if err != nil {
		panic(err) // versionMeta is always marshalable
	}
	return data
}

// decodeMeta parses and validates a version metadata record.
func decodeMeta(data []byte) (*versionMeta, error) {
	var m versionMeta
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, ErrCorrupt
	}
	sum, err := hex.DecodeString(m.SHA256)
	if err != nil || len(sum) != 32 {
		return nil, ErrCorrupt
	}
	if _, err := base64.StdEncoding.DecodeString(m.DEK); err != nil {
		return nil, ErrCorrupt
	}
	if _, err := time.Parse(time.RFC3339Nano, m.Time); err != nil {
		return nil, ErrCorrupt
	}
	if m.Size < 0 {
		return nil, ErrCorrupt
	}
	return &m, nil
}

func decodeKEKFile(data []byte) (*kekFile, error) {
	var k kekFile
	if err := json.Unmarshal(data, &k); err != nil {
		return nil, ErrCorrupt
	}
	if _, err := base64.StdEncoding.DecodeString(k.Wrapped); err != nil {
		return nil, ErrCorrupt
	}
	return &k, nil
}

func decodeJournal(data []byte) (*rotateJournal, error) {
	var j rotateJournal
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, ErrCorrupt
	}
	if j.NewGen != j.OldGen+1 {
		return nil, ErrCorrupt
	}
	if _, err := base64.StdEncoding.DecodeString(j.Wrapped); err != nil {
		return nil, ErrCorrupt
	}
	return &j, nil
}
