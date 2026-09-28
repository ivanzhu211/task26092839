package vault

// recover.go: Open-time recovery. Everything here is idempotent, so a crash
// during recovery itself is handled by simply running it again on the next
// Open.
//
// Recovery steps:
//  1. create missing layout directories
//  2. remove all temporary files (tmp/)
//  3. load journals, per-file metadata, and wrapped KEKs
//  4. sweep data/: delete every blob/key file not referenced by a committed
//     metadata file (interrupted Puts and already-evicted versions)
//  5. replay journals: finished/unfinished Puts only need their journal
//     removed (the sweep already reconciled data/); interrupted RotateKey is
//     rolled forward so all key files depend on the new KEK only
//  6. verify that exactly one KEK remains

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func ensureDirs(dir string) error {
	for _, sub := range []string{kekDirName, journalDirName, metaDirName, dataDirName, tmpDirName} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return err
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	known := map[string]bool{
		kekDirName: true, journalDirName: true, metaDirName: true,
		dataDirName: true, tmpDirName: true,
	}
	for _, e := range entries {
		if !known[e.Name()] || !e.IsDir() {
			return ErrCorrupt
		}
	}
	return nil
}

// cleanTmp removes every entry inside tmp/. Any file there is an unfinished
// atomic write and can never be referenced by committed state.
func cleanTmp(dir string) error {
	entries, err := os.ReadDir(filepath.Join(dir, tmpDirName))
	if err != nil {
		return err
	}
	for _, e := range entries {
		p := filepath.Join(dir, tmpDirName, e.Name())
		if err := mutate(hookOp{Kind: opDelete, Path: p}, func() error {
			return os.RemoveAll(p)
		}); err != nil {
			return err
		}
	}
	return fsyncDir(filepath.Join(dir, tmpDirName))
}

type loadedJournal struct {
	path string
	j    journalJSON
}

func loadJournals(dir string) ([]loadedJournal, error) {
	jdir := filepath.Join(dir, journalDirName)
	entries, err := os.ReadDir(jdir)
	if err != nil {
		return nil, err
	}
	var out []loadedJournal
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			return nil, ErrCorrupt
		}
		p := filepath.Join(jdir, e.Name())
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var j journalJSON
		if err := json.Unmarshal(data, &j); err != nil {
			return nil, ErrCorrupt
		}
		if j.Op != "put" && j.Op != "rotate" {
			return nil, ErrCorrupt
		}
		out = append(out, loadedJournal{path: p, j: j})
	}
	sort.Slice(out, func(a, b int) bool { return out[a].path < out[b].path })
	return out, nil
}

// loadMetas reads every meta file, keyed by name hash.
func loadMetas(dir string) (map[string]*fileMeta, error) {
	mdir := filepath.Join(dir, metaDirName)
	entries, err := os.ReadDir(mdir)
	if err != nil {
		return nil, err
	}
	out := make(map[string]*fileMeta)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			return nil, ErrCorrupt
		}
		hash := strings.TrimSuffix(e.Name(), ".json")
		data, err := os.ReadFile(filepath.Join(mdir, e.Name()))
		if err != nil {
			return nil, err
		}
		m, err := metaFromJSON(data)
		if err != nil {
			return nil, ErrCorrupt
		}
		if nameHash(m.Name) != hash {
			return nil, ErrCorrupt
		}
		out[hash] = m
	}
	return out, nil
}

// loadKEKs reads and unwraps every wrapped KEK file, keyed by KEK id.
func loadKEKs(dir string, rootSecret []byte) (map[string][]byte, error) {
	kdir := filepath.Join(dir, kekDirName)
	entries, err := os.ReadDir(kdir)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]byte)
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "kek-") || !strings.HasSuffix(e.Name(), ".wrap") {
			return nil, ErrCorrupt
		}
		data, err := os.ReadFile(filepath.Join(kdir, e.Name()))
		if err != nil {
			return nil, err
		}
		id, kek, err := unwrapKEK(rootSecret, data)
		if err != nil {
			return nil, ErrCorrupt
		}
		if kekPath(dir, id) != filepath.Join(kdir, e.Name()) {
			return nil, ErrCorrupt
		}
		out[id] = kek
	}
	return out, nil
}

// sweepData deletes every file under data/ that is not referenced by the
// committed metadata, then removes emptied hash directories. This reclaims
// blobs/keys from interrupted Puts and from versions evicted by a committed
// Put whose cleanup was interrupted.
func sweepData(dir string, metas map[string]*fileMeta) error {
	expected := make(map[string]bool)
	for hash, m := range metas {
		for _, ver := range m.Versions {
			expected[keyPath(dir, hash, ver.Version)] = true
			expected[blobPath(dir, hash, ver.Version)] = true
		}
	}
	ddir := filepath.Join(dir, dataDirName)
	entries, err := os.ReadDir(ddir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		p := filepath.Join(ddir, e.Name())
		if !e.IsDir() {
			if err := deleteFile(p); err != nil {
				return err
			}
			continue
		}
		sub, err := os.ReadDir(p)
		if err != nil {
			return err
		}
		for _, se := range sub {
			sp := filepath.Join(p, se.Name())
			if se.IsDir() {
				if err := mutate(hookOp{Kind: opDelete, Path: sp}, func() error {
					return os.RemoveAll(sp)
				}); err != nil {
					return err
				}
				continue
			}
			if !expected[sp] {
				if err := deleteFile(sp); err != nil {
					return err
				}
			}
		}
		// Remove the hash directory if it is now empty.
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			// Non-empty is fine (live versions remain); anything else is too,
			// the directory is just a cache of structure.
			_ = err
		}
	}
	return fsyncDir(ddir)
}

// replayPutJournal finishes recovery of one interrupted Put. The data sweep
// has already reconciled blob/key files with the committed metadata, so the
// only remaining work is removing the journal itself.
func replayPutJournal(dir string, lj loadedJournal) error {
	return deleteFile(lj.path)
}

// replayRotateJournal rolls an interrupted RotateKey forward.
func replayRotateJournal(dir string, metas map[string]*fileMeta, keks map[string][]byte, lj loadedJournal) error {
	j := lj.j
	newPath := kekPath(dir, j.NewKEK)
	oldPath := kekPath(dir, j.OldKEK)

	if _, ok := keks[j.NewKEK]; !ok {
		// The new wrapped KEK was never committed; rotation never started.
		if _, err := os.Stat(newPath); !errors.Is(err, fs.ErrNotExist) && err == nil {
			return ErrCorrupt
		}
		return deleteFile(lj.path)
	}
	newKEK := keks[j.NewKEK]

	if _, ok := keks[j.OldKEK]; !ok {
		// Old KEK already removed: rotation had committed, only the journal
		// removal was lost.
		return deleteFile(lj.path)
	}
	oldKEK := keks[j.OldKEK]

	// Rewrap every key file still wrapped with the old KEK. Iteration order
	// is deterministic so crash-point enumeration in tests is stable.
	var hashes []string
	for hash := range metas {
		hashes = append(hashes, hash)
	}
	sort.Strings(hashes)
	for _, hash := range hashes {
		for _, ver := range metas[hash].Versions {
			kp := keyPath(dir, hash, ver.Version)
			data, err := os.ReadFile(kp)
			if err != nil {
				return err
			}
			kekID, sealed, err := parseKeyFile(data)
			if err != nil {
				return ErrCorrupt
			}
			if kekID != j.OldKEK {
				continue
			}
			dek, err := openSealed(oldKEK, sealed)
			if err != nil {
				return ErrCorrupt
			}
			wrapped, err := wrapDEK(j.NewKEK, newKEK, dek)
			if err != nil {
				return err
			}
			if err := writeFileAtomic(filepath.Join(dir, tmpDirName), kp, wrapped); err != nil {
				return err
			}
		}
	}
	// Commit: retire the old KEK, then remove the journal.
	if err := deleteFile(oldPath); err != nil {
		return err
	}
	return deleteFile(lj.path)
}
