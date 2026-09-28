package vault

// rotate.go: RotateKey.
//
// Protocol (roll-forward; commit point is the deletion of the old wrapped
// KEK):
//  1. write rotate journal {old, new}
//  2. write the new wrapped KEK            (temp + rename)
//  3. rewrap every version's DEK key file  (temp + rename each)
//  4. delete the old wrapped KEK           <-- commit
//  5. delete the journal
// Disk I/O is O(number of live versions) on small key files only; it never
// touches ciphertext blobs, so it does not grow with total ciphertext bytes.
// If interrupted, Open rolls the rotation forward: both KEKs are still
// recoverable from disk until step 4, and key files record which KEK wraps
// them, so rewrapping is idempotent.

import (
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
)

// RotateKey replaces the KEK. After it returns, every live version depends
// only on the new KEK and the retired KEK (wrapped or not) is gone from disk.
func (v *Vault) RotateKey() error {
	newKEK := make([]byte, 32)
	if _, err := rand.Read(newKEK); err != nil {
		return err
	}
	newID := randID()
	oldID := v.kekID

	// 1. journal
	jb, err := json.Marshal(journalJSON{Op: "rotate", OldKEK: oldID, NewKEK: newID})
	if err != nil {
		return err
	}
	jPath := filepath.Join(v.journalDir(), "rotate-"+newID[:16]+"-"+randID()+".json")
	if err := writeFileAtomic(v.tmpDir(), jPath, jb); err != nil {
		return err
	}

	// 2. new wrapped KEK
	wrapped, err := wrapKEK(v.rootSecret, newKEK, newID)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(v.tmpDir(), kekPath(v.dir, newID), wrapped); err != nil {
		return err
	}

	// 3. rewrap every key file, in deterministic order
	var names []string
	for name := range v.files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fm := v.files[name]
		hash := nameHash(name)
		for _, ver := range fm.Versions {
			kp := keyPath(v.dir, hash, ver.Version)
			data, err := os.ReadFile(kp)
			if err != nil {
				return err
			}
			kekID, sealedDEK, err := parseKeyFile(data)
			if err != nil {
				return ErrCorrupt
			}
			if kekID != oldID {
				continue
			}
			dek, err := openSealed(v.kek, sealedDEK)
			if err != nil {
				return ErrCorrupt
			}
			w, err := wrapDEK(newID, newKEK, dek)
			if err != nil {
				return err
			}
			if err := writeFileAtomic(v.tmpDir(), kp, w); err != nil {
				return err
			}
		}
	}

	// 4. commit: retire the old KEK
	if err := deleteFile(kekPath(v.dir, oldID)); err != nil {
		return err
	}

	// 5. remove the journal
	if err := deleteFile(jPath); err != nil {
		return err
	}

	v.kek = newKEK
	v.kekID = newID
	return nil
}
