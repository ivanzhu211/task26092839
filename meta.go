package vault

// meta.go: on-disk formats, paths, and (de)serialization.
//
// Directory layout inside the vault dir:
//   kek/kek-<id>.wrap        wrapped KEK (exactly one outside of rotation)
//   journal/<id>.json        pending operation records
//   meta/<sha256(name)>.json per-logical-file metadata
//   data/<hash>/<version>.key    DEK wrapped by the current KEK
//   data/<hash>/<version>.blob   nonce || AES-256-GCM ciphertext
//   tmp/                     temporary files (cleaned on Open)

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"time"
)

const (
	kekDirName     = "kek"
	journalDirName = "journal"
	metaDirName    = "meta"
	dataDirName    = "data"
	tmpDirName     = "tmp"
)

// kekFileJSON is a KEK wrapped by the root secret.
type kekFileJSON struct {
	ID    string `json:"id"`
	Nonce []byte `json:"nonce"`
	CT    []byte `json:"ct"`
}

// keyFileJSON is a per-version DEK wrapped by a KEK.
type keyFileJSON struct {
	KEK   string `json:"kek"`
	Nonce []byte `json:"nonce"`
	CT    []byte `json:"ct"`
}

// metaFileJSON is the per-logical-file metadata.
type metaFileJSON struct {
	Name     string            `json:"name"`
	Next     int               `json:"next"`
	Versions []versionFileJSON `json:"versions"`
}

type versionFileJSON struct {
	V    int       `json:"v"`
	Size int64     `json:"size"`
	SHA  string    `json:"sha256"`
	Time time.Time `json:"time"`
}

// journalJSON records a pending operation for crash recovery.
type journalJSON struct {
	Op string `json:"op"` // "put" or "rotate"
	// put
	Name    string `json:"name,omitempty"`
	Hash    string `json:"hash,omitempty"`
	Version int    `json:"version,omitempty"`
	Evict   int    `json:"evict,omitempty"`
	// rotate
	OldKEK string `json:"old,omitempty"`
	NewKEK string `json:"new,omitempty"`
}

// nameHash maps an arbitrary logical name to a safe path component.
func nameHash(name string) string {
	sum := sha256.Sum256([]byte(name))
	return hex.EncodeToString(sum[:])
}

func (v *Vault) kekDir() string     { return filepath.Join(v.dir, kekDirName) }
func (v *Vault) journalDir() string { return filepath.Join(v.dir, journalDirName) }
func (v *Vault) metaDir() string    { return filepath.Join(v.dir, metaDirName) }
func (v *Vault) dataDir() string    { return filepath.Join(v.dir, dataDirName) }
func (v *Vault) tmpDir() string     { return filepath.Join(v.dir, tmpDirName) }

func kekPath(dir, id string) string {
	return filepath.Join(dir, kekDirName, "kek-"+id+".wrap")
}

func metaPath(dir, hash string) string {
	return filepath.Join(dir, metaDirName, hash+".json")
}

func keyPath(dir, hash string, version int) string {
	return filepath.Join(dir, dataDirName, hash, itoa(version)+".key")
}

func blobPath(dir, hash string, version int) string {
	return filepath.Join(dir, dataDirName, hash, itoa(version)+".blob")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// --- serialization helpers ---

func metaToJSON(m *fileMeta) ([]byte, error) {
	dm := metaFileJSON{Name: m.Name, Next: m.Next}
	for _, ver := range m.Versions {
		dm.Versions = append(dm.Versions, versionFileJSON{
			V:    ver.Version,
			Size: ver.Size,
			SHA:  hex.EncodeToString(ver.SHA256[:]),
			Time: ver.Time,
		})
	}
	return json.Marshal(dm)
}

func metaFromJSON(data []byte) (*fileMeta, error) {
	var dm metaFileJSON
	if err := json.Unmarshal(data, &dm); err != nil {
		return nil, err
	}
	m := &fileMeta{Name: dm.Name, Next: dm.Next}
	for _, dv := range dm.Versions {
		raw, err := hex.DecodeString(dv.SHA)
		if err != nil || len(raw) != sha256.Size {
			return nil, ErrCorrupt
		}
		var sum [32]byte
		copy(sum[:], raw)
		m.Versions = append(m.Versions, Version{
			Version: dv.V,
			Size:    dv.Size,
			SHA256:  sum,
			Time:    dv.Time,
		})
	}
	return m, nil
}

// wrapKEK encrypts kek with the root secret and serializes it.
func wrapKEK(rootSecret, kek []byte, id string) ([]byte, error) {
	sealed, err := seal(rootSecret, kek)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(rootSecret)
	if err != nil {
		return nil, err
	}
	kf := kekFileJSON{
		ID:    id,
		Nonce: sealed[:gcm.NonceSize()],
		CT:    sealed[gcm.NonceSize():],
	}
	return json.Marshal(kf)
}

// unwrapKEK parses and decrypts a wrapped KEK file.
func unwrapKEK(rootSecret, data []byte) (id string, kek []byte, err error) {
	var kf kekFileJSON
	if err := json.Unmarshal(data, &kf); err != nil {
		return "", nil, err
	}
	sealed := make([]byte, 0, len(kf.Nonce)+len(kf.CT))
	sealed = append(sealed, kf.Nonce...)
	sealed = append(sealed, kf.CT...)
	kek, err = openSealed(rootSecret, sealed)
	if err != nil {
		return "", nil, err
	}
	if len(kek) != 32 {
		return "", nil, ErrCorrupt
	}
	return kf.ID, kek, nil
}

// wrapDEK encrypts dek with the KEK and serializes the key file.
func wrapDEK(kekID string, kek, dek []byte) ([]byte, error) {
	sealed, err := seal(kek, dek)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	kf := keyFileJSON{
		KEK:   kekID,
		Nonce: sealed[:gcm.NonceSize()],
		CT:    sealed[gcm.NonceSize():],
	}
	return json.Marshal(kf)
}

// parseKeyFile parses a key file, returning the KEK id and the still-wrapped
// DEK material.
func parseKeyFile(data []byte) (kekID string, sealed []byte, err error) {
	var kf keyFileJSON
	if err := json.Unmarshal(data, &kf); err != nil {
		return "", nil, err
	}
	sealed = append(append([]byte{}, kf.Nonce...), kf.CT...)
	return kf.KEK, sealed, nil
}
