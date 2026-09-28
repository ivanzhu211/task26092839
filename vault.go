// Package vault implements a crash-safe encrypted file vault using only the
// Go standard library. All data lives inside a caller-provided directory.
package vault

import (
	"crypto/rand"
	"errors"
	"path/filepath"
	"time"
)

// MaxVersions is the maximum number of live versions per logical file.
const MaxVersions = 25

// MaxNameLen is the maximum logical file name length in bytes.
const MaxNameLen = 4096

var (
	ErrInvalidName   = errors.New("vault: invalid name")
	ErrInvalidSecret = errors.New("vault: root secret must be 32 bytes")
	ErrNotFound      = errors.New("vault: not found")
	ErrIntegrity     = errors.New("vault: integrity check failed")
	ErrQuota         = errors.New("vault: quota exceeded")
	ErrCorrupt       = errors.New("vault: corrupt or unrecognized on-disk state")
)

// Version describes one live version of a logical file.
type Version struct {
	Version int
	Size    int64
	SHA256  [32]byte
	Time    time.Time
}

// Vault is an opened encrypted vault. All calls must be serialized by the
// caller; no concurrency is supported.
type Vault struct {
	dir        string
	rootSecret []byte
	quota      int64

	kek   []byte
	kekID string

	files map[string]*fileMeta
	usage int64
}

// fileMeta is the in-memory metadata of one logical file.
type fileMeta struct {
	Name     string
	Next     int
	Versions []Version
}

// Open opens or creates a vault in dir and finishes any recovery work left
// behind by an interrupted previous run.
func Open(dir string, rootSecret []byte, quotaBytes int64) (*Vault, error) {
	if len(rootSecret) != 32 {
		return nil, ErrInvalidSecret
	}
	if err := ensureDirs(dir); err != nil {
		return nil, err
	}
	if err := cleanTmp(dir); err != nil {
		return nil, err
	}
	journals, err := loadJournals(dir)
	if err != nil {
		return nil, err
	}
	metas, err := loadMetas(dir)
	if err != nil {
		return nil, err
	}
	keks, err := loadKEKs(dir, rootSecret)
	if err != nil {
		return nil, err
	}
	if err := sweepData(dir, metas); err != nil {
		return nil, err
	}
	// Replay interrupted Puts first (journal removal only), then interrupted
	// rotations (rolled forward).
	for _, lj := range journals {
		if lj.j.Op != "put" {
			continue
		}
		if err := replayPutJournal(dir, lj); err != nil {
			return nil, err
		}
	}
	for _, lj := range journals {
		if lj.j.Op != "rotate" {
			continue
		}
		if err := replayRotateJournal(dir, metas, keks, lj); err != nil {
			return nil, err
		}
	}
	// After recovery exactly one KEK may remain. A brand-new vault gets its
	// first KEK now.
	keks, err = loadKEKs(dir, rootSecret)
	if err != nil {
		return nil, err
	}
	if len(keks) == 0 {
		if len(metas) > 0 || len(journals) > 0 {
			return nil, ErrCorrupt
		}
		id := randID()
		kek := make([]byte, 32)
		if _, err := rand.Read(kek); err != nil {
			return nil, err
		}
		wrapped, err := wrapKEK(rootSecret, kek, id)
		if err != nil {
			return nil, err
		}
		if err := writeFileAtomic(filepath.Join(dir, tmpDirName), kekPath(dir, id), wrapped); err != nil {
			return nil, err
		}
		keks = map[string][]byte{id: kek}
	}
	if len(keks) != 1 {
		return nil, ErrCorrupt
	}
	v := &Vault{
		dir:        dir,
		rootSecret: append([]byte(nil), rootSecret...),
		quota:      quotaBytes,
		files:      make(map[string]*fileMeta),
	}
	for id, kek := range keks {
		v.kekID, v.kek = id, kek
	}
	for _, m := range metas {
		v.files[m.Name] = m
		for _, ver := range m.Versions {
			v.usage += ver.Size
		}
	}
	return v, nil
}

// Usage returns the sum of plaintext sizes of all live versions.
func (v *Vault) Usage() int64 {
	return v.usage
}
