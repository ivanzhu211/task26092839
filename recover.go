package vault

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strconv"
	"strings"
)

// recover scans the vault directory, finishes or rolls back any interrupted
// operation, and loads the in-memory index. It is idempotent: every step can
// be re-run after another kill -9. Called once from openVault.
func (v *Vault) recover() error {
	if err := v.fs.MkdirAll(v.dir); err != nil {
		return err
	}
	entries, err := v.fs.ReadDir(v.dir)
	if err != nil {
		return err
	}
	var haveKEK, haveJournal, haveFiles bool
	for _, e := range entries {
		switch {
		case e == kekName:
			haveKEK = true
		case e == journalName:
			haveJournal = true
		case e == filesDir:
			haveFiles = true
		case strings.HasSuffix(e, ".tmp"):
			// Stray temp from an interrupted atomic write; the rename never
			// happened, so the original (if any) is intact.
			v.removeQuiet(path.Join(v.dir, e))
		default:
			return fmt.Errorf("%w: unexpected entry %q in vault root", ErrCorrupt, e)
		}
	}

	if !haveKEK {
		if haveJournal {
			return fmt.Errorf("%w: rotation journal without KEK file", ErrCorrupt)
		}
		return v.freshInit()
	}

	// Load the current KEK.
	kdata, err := v.fs.ReadFile(path.Join(v.dir, kekName))
	if err != nil {
		return err
	}
	kf, err := decodeKEKFile(kdata)
	if err != nil {
		return err
	}
	wrapped, _ := base64.StdEncoding.DecodeString(kf.Wrapped)
	kek, err := unseal(v.root, wrapped)
	if err != nil {
		return ErrBadSecret
	}
	v.kek = kek
	v.kekGen = kf.Gen

	var journal *rotateJournal
	if haveJournal {
		jdata, err := v.fs.ReadFile(path.Join(v.dir, journalName))
		if err != nil {
			return err
		}
		journal, err = decodeJournal(jdata)
		if err != nil {
			return err
		}
	}

	// Scan all logical files: drop interrupted-write leftovers, finish
	// interrupted evictions, build the index and compute usage.
	if haveFiles {
		if err := v.scanFiles(); err != nil {
			return err
		}
	}

	if journal != nil {
		if err := v.finishRotation(journal); err != nil {
			return err
		}
	} else if err := v.checkGens(); err != nil {
		return err
	}
	return nil
}

// freshInit creates a brand-new vault. It refuses to initialize over
// unrecognized data.
func (v *Vault) freshInit() error {
	entries, err := v.fs.ReadDir(path.Join(v.dir, filesDir))
	if err != nil && !isNotExist(err) {
		return err
	}
	if len(entries) > 0 {
		return fmt.Errorf("%w: file data present without KEK", ErrCorrupt)
	}
	kek, err := randomKey()
	if err != nil {
		return err
	}
	wrapped, err := seal(v.root, kek)
	if err != nil {
		return err
	}
	if err := v.writeKEKFile(1, base64.StdEncoding.EncodeToString(wrapped)); err != nil {
		return err
	}
	v.kek = kek
	v.kekGen = 1
	return nil
}

// scanFiles walks files/<hash>/ directories, cleaning up and indexing.
func (v *Vault) scanFiles() error {
	froot := path.Join(v.dir, filesDir)
	dirs, err := v.fs.ReadDir(froot)
	if err != nil {
		return fmt.Errorf("%w: cannot list files dir: %v", ErrCorrupt, err)
	}
	for _, d := range dirs {
		if len(d) != 64 || !isHex(d) {
			return fmt.Errorf("%w: unexpected entry %q in files dir", ErrCorrupt, d)
		}
		if err := v.scanOneFile(froot, d); err != nil {
			return err
		}
	}
	return nil
}

func (v *Vault) scanOneFile(froot, key string) error {
	fdir := path.Join(froot, key)
	entries, err := v.fs.ReadDir(fdir)
	if err != nil {
		return fmt.Errorf("%w: cannot list %q: %v", ErrCorrupt, fdir, err)
	}
	bins := make(map[uint64]bool)
	metas := make(map[uint64]*versionMeta)
	for _, e := range entries {
		if strings.HasSuffix(e, ".tmp") {
			v.removeQuiet(path.Join(fdir, e))
			continue
		}
		ver, kind, ok := parseVersionName(e)
		if !ok {
			return fmt.Errorf("%w: unexpected entry %q in %q", ErrCorrupt, e, fdir)
		}
		if kind == "bin" {
			bins[ver] = true
			continue
		}
		data, err := v.fs.ReadFile(path.Join(fdir, e))
		if err != nil {
			return err
		}
		m, err := decodeMeta(data)
		if err != nil {
			return err
		}
		if m.Version != ver {
			return fmt.Errorf("%w: meta version mismatch in %q", ErrCorrupt, e)
		}
		metas[ver] = m
	}
	// Orphans: a .bin without .meta is an interrupted Put (rolled back);
	// a .meta without .bin is an interrupted eviction (finished here).
	for ver := range bins {
		if metas[ver] == nil {
			v.removeQuiet(path.Join(fdir, binName(ver)))
			delete(bins, ver)
		}
	}
	for ver := range metas {
		if !bins[ver] {
			v.removeQuiet(path.Join(fdir, metaName(ver)))
			delete(metas, ver)
		}
	}
	// Finish an interrupted eviction: never more than maxVersions survive.
	for len(metas) > maxVersions {
		oldest := oldestVersion(&fileState{versions: metas})
		v.removeQuiet(path.Join(fdir, binName(oldest)))
		v.removeQuiet(path.Join(fdir, metaName(oldest)))
		delete(metas, oldest)
	}
	if len(metas) == 0 {
		return nil
	}
	st := &fileState{versions: metas}
	for ver := range metas {
		if ver >= st.nextVersion {
			st.nextVersion = ver + 1
		}
		v.usage += metas[ver].Size
	}
	v.files[key] = st
	return nil
}

// finishRotation completes an interrupted RotateKey.
func (v *Vault) finishRotation(j *rotateJournal) error {
	switch v.kekGen {
	case j.OldGen:
		// The KEK file still holds the old KEK: rewrap remaining versions,
		// then switch the KEK file and drop the journal.
		wrapped, _ := base64.StdEncoding.DecodeString(j.Wrapped)
		newKEK, err := unseal(v.root, wrapped)
		if err != nil {
			return ErrCorrupt
		}
		if err := v.rewrapAll(j, newKEK); err != nil {
			return err
		}
		if err := v.writeKEKFile(j.NewGen, j.Wrapped); err != nil {
			return err
		}
		v.kek = newKEK
		v.kekGen = j.NewGen
	case j.NewGen:
		// The KEK file was already switched; only the journal removal was
		// interrupted. Every version must already use the new generation.
		if err := v.checkGens(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: journal generations %d->%d but KEK is %d",
			ErrCorrupt, j.OldGen, j.NewGen, v.kekGen)
	}
	v.removeQuiet(path.Join(v.dir, journalName))
	return nil
}

// checkGens verifies every surviving version depends on the current KEK.
func (v *Vault) checkGens() error {
	for key, st := range v.files {
		for ver, m := range st.versions {
			if m.KEKGen != v.kekGen {
				return fmt.Errorf("%w: version %s/%d has KEK generation %d, want %d",
					ErrCorrupt, key, ver, m.KEKGen, v.kekGen)
			}
		}
	}
	return nil
}

func (v *Vault) removeQuiet(name string) {
	v.fs.Remove(name) // best effort; re-run on next Open if it fails
}

// parseVersionName parses "<version>.bin" or "<version>.meta".
func parseVersionName(name string) (ver uint64, kind string, ok bool) {
	dot := strings.LastIndexByte(name, '.')
	if dot <= 0 {
		return 0, "", false
	}
	ext := name[dot+1:]
	if ext != "bin" && ext != "meta" {
		return 0, "", false
	}
	n, err := strconv.ParseUint(name[:dot], 10, 64)
	if err != nil || n == 0 {
		return 0, "", false
	}
	return n, ext, true
}

func isHex(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func isNotExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist)
}
