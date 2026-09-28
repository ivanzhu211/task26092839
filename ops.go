package vault

// ops.go: Put, Get, Versions.
//
// Put write-ahead protocol (commit point is the metadata rename):
//  1. write journal (intent: name, new version, version to evict)
//  2. write wrapped DEK key file        (temp + rename)
//  3. write ciphertext blob             (temp + rename)
//  4. write updated metadata            (temp + rename)  <-- commit
//  5. delete evicted version's blob/key
//  6. delete journal
// A crash before 4 is rolled back by the Open-time sweep (unreferenced
// blob/key files are removed); a crash after 4 is finished by the same
// sweep (evicted files become unreferenced and are removed).

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

func validName(name string) bool {
	return len(name) > 0 && len(name) <= MaxNameLen
}

// ensureHashDir makes sure data/<hash> exists.
func (v *Vault) ensureHashDir(hash string) error {
	p := filepath.Join(v.dataDir(), hash)
	return mutate(hookOp{Kind: opMkdir, Path: p}, func() error {
		if err := os.MkdirAll(p, 0o700); err != nil {
			return err
		}
		return fsyncDir(v.dataDir())
	})
}

// Put stores data as a new version of name and returns its version number.
func (v *Vault) Put(name string, data []byte) (int, error) {
	if !validName(name) {
		return 0, ErrInvalidName
	}
	fm := v.files[name]
	var evict Version
	evicting := fm != nil && len(fm.Versions) >= MaxVersions
	if evicting {
		evict = fm.Versions[0]
	}
	newUsage := v.usage - evict.Size + int64(len(data))
	if newUsage > v.quota {
		return 0, ErrQuota
	}
	version := 1
	if fm != nil {
		version = fm.Next
	}
	hash := nameHash(name)

	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return 0, err
	}

	// 1. journal
	j := journalJSON{Op: "put", Name: name, Hash: hash, Version: version}
	if evicting {
		j.Evict = evict.Version
	}
	jb, err := json.Marshal(j)
	if err != nil {
		return 0, err
	}
	jPath := filepath.Join(v.journalDir(), "put-"+hash[:16]+"-"+itoa(version)+"-"+randID()+".json")
	if err := writeFileAtomic(v.tmpDir(), jPath, jb); err != nil {
		return 0, err
	}

	// 2. wrapped DEK key file
	if err := v.ensureHashDir(hash); err != nil {
		return 0, err
	}
	wrappedDEK, err := wrapDEK(v.kekID, v.kek, dek)
	if err != nil {
		return 0, err
	}
	if err := writeFileAtomic(v.tmpDir(), keyPath(v.dir, hash, version), wrappedDEK); err != nil {
		return 0, err
	}

	// 3. ciphertext blob
	sealed, err := seal(dek, data)
	if err != nil {
		return 0, err
	}
	if err := writeFileAtomic(v.tmpDir(), blobPath(v.dir, hash, version), sealed); err != nil {
		return 0, err
	}

	// 4. commit: updated metadata
	nm := &fileMeta{Name: name, Next: version + 1}
	if fm != nil {
		for _, ver := range fm.Versions {
			if evicting && ver.Version == evict.Version {
				continue
			}
			nm.Versions = append(nm.Versions, ver)
		}
	}
	sum := sha256.Sum256(data)
	nm.Versions = append(nm.Versions, Version{
		Version: version,
		Size:    int64(len(data)),
		SHA256:  sum,
		Time:    time.Now().UTC(),
	})
	mb, err := metaToJSON(nm)
	if err != nil {
		return 0, err
	}
	if err := writeFileAtomic(v.tmpDir(), metaPath(v.dir, hash), mb); err != nil {
		return 0, err
	}

	// 5. evict the oldest version's ciphertext and key material
	if evicting {
		if err := deleteFile(blobPath(v.dir, hash, evict.Version)); err != nil {
			return 0, err
		}
		if err := deleteFile(keyPath(v.dir, hash, evict.Version)); err != nil {
			return 0, err
		}
	}

	// 6. remove the journal
	if err := deleteFile(jPath); err != nil {
		return 0, err
	}

	v.files[name] = nm
	v.usage = newUsage
	return version, nil
}

// Get returns the plaintext of the given version, verifying its SHA-256.
func (v *Vault) Get(name string, version int) ([]byte, error) {
	if !validName(name) {
		return nil, ErrInvalidName
	}
	fm := v.files[name]
	if fm == nil {
		return nil, ErrNotFound
	}
	var meta *Version
	for i := range fm.Versions {
		if fm.Versions[i].Version == version {
			meta = &fm.Versions[i]
			break
		}
	}
	if meta == nil {
		return nil, ErrNotFound
	}
	hash := nameHash(name)
	kd, err := os.ReadFile(keyPath(v.dir, hash, version))
	if err != nil {
		return nil, err
	}
	kekID, sealedDEK, err := parseKeyFile(kd)
	if err != nil {
		return nil, ErrCorrupt
	}
	if kekID != v.kekID {
		return nil, ErrCorrupt
	}
	dek, err := openSealed(v.kek, sealedDEK)
	if err != nil {
		return nil, ErrCorrupt
	}
	blob, err := os.ReadFile(blobPath(v.dir, hash, version))
	if err != nil {
		return nil, err
	}
	plain, err := openSealed(dek, blob)
	if err != nil {
		return nil, ErrIntegrity
	}
	sum := sha256.Sum256(plain)
	if !bytes.Equal(sum[:], meta.SHA256[:]) {
		return nil, ErrIntegrity
	}
	return plain, nil
}

// Versions lists the metadata of all live versions of name.
func (v *Vault) Versions(name string) ([]Version, error) {
	if !validName(name) {
		return nil, ErrInvalidName
	}
	fm := v.files[name]
	if fm == nil {
		return nil, nil
	}
	out := make([]Version, len(fm.Versions))
	copy(out, fm.Versions)
	return out, nil
}
