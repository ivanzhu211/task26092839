package vault

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"time"
)

var (
	ErrNotFound      = errors.New("vault: not found")
	ErrQuotaExceeded = errors.New("vault: quota exceeded")
	ErrInvalidName   = errors.New("vault: invalid name")
	ErrIntegrity     = errors.New("vault: integrity check failed")
	ErrCorrupt       = errors.New("vault: corrupt or unrecognized on-disk state")
	ErrBadSecret     = errors.New("vault: invalid root secret")
)

const (
	maxVersions = 25
	maxNameLen  = 4096
	kekName     = "kek"
	journalName = "rotate.journal"
	filesDir    = "files"
)

// VersionInfo describes one surviving version of a logical file.
type VersionInfo struct {
	Version uint64
	Size    int64
	SHA256  [32]byte
	Time    time.Time
}

type fileState struct {
	nextVersion uint64
	versions    map[uint64]*versionMeta
}

// Vault is an encrypted file vault rooted at a local directory.
//
// On-disk layout:
//
//	<dir>/kek                  wrapped current KEK (exactly one after Open)
//	<dir>/rotate.journal       rotation journal, only while rotating
//	<dir>/files/<sha256(name)>/<version>.bin   ciphertext (nonce||GCM)
//	<dir>/files/<sha256(name)>/<version>.meta  version metadata JSON
//
// All file payloads are written via tmp+rename so a kill -9 can never leave a
// half-written file at its final name; recovery removes any leftover state.
type Vault struct {
	dir    string
	fs     fsys
	root   []byte
	quota  int64
	kek    []byte
	kekGen uint64
	files  map[string]*fileState
	usage  int64
}

// Open opens or creates the vault in dir and finishes all recovery work left
// by an interrupted previous run. rootSecret must be 32 bytes and never
// touches disk.
func Open(dir string, rootSecret []byte, quotaBytes int64) (*Vault, error) {
	return openVault(osFS{}, dir, rootSecret, quotaBytes)
}

func openVault(fs fsys, dir string, rootSecret []byte, quotaBytes int64) (*Vault, error) {
	if len(rootSecret) != 32 {
		return nil, ErrBadSecret
	}
	if quotaBytes < 0 {
		return nil, errors.New("vault: negative quota")
	}
	v := &Vault{
		dir:   dir,
		fs:    fs,
		root:  append([]byte(nil), rootSecret...),
		quota: quotaBytes,
		files: make(map[string]*fileState),
	}
	if err := v.recover(); err != nil {
		return nil, err
	}
	return v, nil
}

// Put stores data as a new version of name. If name already has maxVersions
// versions, the oldest is evicted in the same operation. If the surviving
// plaintext total would exceed the quota, Put fails without touching disk.
func (v *Vault) Put(name string, data []byte) (uint64, error) {
	if err := validateName(name); err != nil {
		return 0, err
	}
	key := nameKey(name)
	st := v.files[key]

	var evictVer uint64
	var evictSize int64
	evict := st != nil && len(st.versions) >= maxVersions
	if evict {
		evictVer = oldestVersion(st)
		evictSize = st.versions[evictVer].Size
	}
	if v.usage+int64(len(data))-evictSize > v.quota {
		return 0, ErrQuotaExceeded
	}

	fdir := path.Join(v.dir, filesDir, key)
	if st == nil {
		if err := v.fs.MkdirAll(fdir); err != nil {
			return 0, err
		}
		if err := v.fs.SyncDir(path.Join(v.dir, filesDir)); err != nil {
			return 0, err
		}
		st = &fileState{nextVersion: 1, versions: make(map[uint64]*versionMeta)}
	}
	ver := st.nextVersion

	dek, err := randomKey()
	if err != nil {
		return 0, err
	}
	ct, err := seal(dek, data)
	if err != nil {
		return 0, err
	}
	wrappedDEK, err := seal(v.kek, dek)
	if err != nil {
		return 0, err
	}
	if err := v.writeFileAtomic(fdir, binName(ver), ct); err != nil {
		return 0, err
	}
	sum := sha256.Sum256(data)
	meta := &versionMeta{
		Version: ver,
		Size:    int64(len(data)),
		SHA256:  hex.EncodeToString(sum[:]),
		Time:    time.Now().UTC().Format(time.RFC3339Nano),
		KEKGen:  v.kekGen,
		DEK:     base64.StdEncoding.EncodeToString(wrappedDEK),
	}
	// Commit point: once the meta file is renamed into place the version exists.
	if err := v.writeFileAtomic(fdir, metaName(ver), encodeMeta(meta)); err != nil {
		return 0, err
	}
	st.versions[ver] = meta
	st.nextVersion = ver + 1
	v.files[key] = st
	v.usage += int64(len(data))

	if evict {
		if err := v.fs.Remove(path.Join(fdir, binName(evictVer))); err != nil {
			return 0, err
		}
		if err := v.fs.SyncDir(fdir); err != nil {
			return 0, err
		}
		if err := v.fs.Remove(path.Join(fdir, metaName(evictVer))); err != nil {
			return 0, err
		}
		if err := v.fs.SyncDir(fdir); err != nil {
			return 0, err
		}
		delete(st.versions, evictVer)
		v.usage -= evictSize
	}
	return ver, nil
}

// Get returns the plaintext of one version, verifying its SHA-256 first.
func (v *Vault) Get(name string, version uint64) ([]byte, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}
	st := v.files[nameKey(name)]
	if st == nil {
		return nil, ErrNotFound
	}
	m := st.versions[version]
	if m == nil {
		return nil, ErrNotFound
	}
	if m.KEKGen != v.kekGen {
		return nil, ErrCorrupt
	}
	blob, err := v.fs.ReadFile(path.Join(v.dir, filesDir, nameKey(name), binName(version)))
	if err != nil {
		return nil, err
	}
	wrapped, err := base64.StdEncoding.DecodeString(m.DEK)
	if err != nil {
		return nil, ErrCorrupt
	}
	dek, err := unseal(v.kek, wrapped)
	if err != nil {
		return nil, ErrCorrupt
	}
	pt, err := unseal(dek, blob)
	if err != nil {
		return nil, ErrIntegrity
	}
	sum := sha256.Sum256(pt)
	if hex.EncodeToString(sum[:]) != m.SHA256 || int64(len(pt)) != m.Size {
		return nil, ErrIntegrity
	}
	return pt, nil
}

// Versions lists metadata of all surviving versions of name, ascending.
func (v *Vault) Versions(name string) ([]VersionInfo, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}
	st := v.files[nameKey(name)]
	if st == nil {
		return nil, nil
	}
	out := make([]VersionInfo, 0, len(st.versions))
	for _, m := range st.versions {
		vi, err := m.toInfo()
		if err != nil {
			return nil, err
		}
		out = append(out, vi)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// RotateKey replaces the KEK. Afterwards every surviving version depends only
// on the new KEK. I/O is proportional to the number of versions (metadata
// rewraps), never to ciphertext bytes.
func (v *Vault) RotateKey() error {
	newKEK, err := randomKey()
	if err != nil {
		return err
	}
	wrapped, err := seal(v.root, newKEK)
	if err != nil {
		return err
	}
	j := rotateJournal{
		OldGen:  v.kekGen,
		NewGen:  v.kekGen + 1,
		Wrapped: base64.StdEncoding.EncodeToString(wrapped),
	}
	jdata, err := json.Marshal(j)
	if err != nil {
		return err
	}
	// Commit to the rotation: the journal lets recovery resume after a crash.
	// It is written atomically like everything else, so a torn journal can
	// never appear at its final name.
	if err := v.writeFileAtomic(v.dir, journalName, jdata); err != nil {
		return err
	}
	if err := v.rewrapAll(&j, newKEK); err != nil {
		return err
	}
	// All versions now depend on the new KEK only: switch the KEK file and
	// retire the old KEK and the journal.
	if err := v.writeKEKFile(j.NewGen, j.Wrapped); err != nil {
		return err
	}
	if err := v.fs.Remove(path.Join(v.dir, journalName)); err != nil {
		return err
	}
	if err := v.fs.SyncDir(v.dir); err != nil {
		return err
	}
	v.kek = newKEK
	v.kekGen = j.NewGen
	return nil
}

// Usage returns the total plaintext bytes of all surviving versions.
func (v *Vault) Usage() int64 { return v.usage }

// rewrapAll rewrites every version metadata whose DEK is still wrapped with
// the old KEK so it is wrapped with newKEK instead. Shared by RotateKey and
// recovery; safe to re-run after a crash.
func (v *Vault) rewrapAll(j *rotateJournal, newKEK []byte) error {
	for _, key := range v.sortedFileKeys() {
		st := v.files[key]
		fdir := path.Join(v.dir, filesDir, key)
		for _, ver := range sortedVersions(st) {
			m := st.versions[ver]
			if m.KEKGen == j.NewGen {
				continue // already rewrapped before a crash
			}
			if m.KEKGen != j.OldGen {
				return fmt.Errorf("%w: version %s/%d has KEK generation %d", ErrCorrupt, key, ver, m.KEKGen)
			}
			if err := v.rewrapMeta(fdir, m, newKEK, j.NewGen); err != nil {
				return err
			}
		}
	}
	return nil
}

func (v *Vault) rewrapMeta(fdir string, m *versionMeta, newKEK []byte, newGen uint64) error {
	wrapped, err := base64.StdEncoding.DecodeString(m.DEK)
	if err != nil {
		return ErrCorrupt
	}
	dek, err := unseal(v.kek, wrapped)
	if err != nil {
		return ErrCorrupt
	}
	w2, err := seal(newKEK, dek)
	if err != nil {
		return err
	}
	m.DEK = base64.StdEncoding.EncodeToString(w2)
	m.KEKGen = newGen
	return v.writeFileAtomic(fdir, metaName(m.Version), encodeMeta(m))
}

// writeKEKFile atomically replaces the KEK file, retiring the previous KEK.
func (v *Vault) writeKEKFile(gen uint64, wrappedB64 string) error {
	data, err := json.Marshal(kekFile{Gen: gen, Wrapped: wrappedB64})
	if err != nil {
		return err
	}
	return v.writeFileAtomic(v.dir, kekName, data)
}

// writeFileAtomic writes data to dir/name via a tmp file, rename and dir sync.
func (v *Vault) writeFileAtomic(dir, name string, data []byte) error {
	tmp := name + ".tmp"
	if err := v.fs.WriteFile(path.Join(dir, tmp), data); err != nil {
		return err
	}
	if err := v.fs.Rename(path.Join(dir, tmp), path.Join(dir, name)); err != nil {
		return err
	}
	return v.fs.SyncDir(dir)
}

func (m *versionMeta) toInfo() (VersionInfo, error) {
	var vi VersionInfo
	sum, err := hex.DecodeString(m.SHA256)
	if err != nil || len(sum) != 32 {
		return vi, ErrCorrupt
	}
	t, err := time.Parse(time.RFC3339Nano, m.Time)
	if err != nil {
		return vi, ErrCorrupt
	}
	vi.Version = m.Version
	vi.Size = m.Size
	copy(vi.SHA256[:], sum)
	vi.Time = t
	return vi, nil
}

func validateName(name string) error {
	if len(name) == 0 || len(name) > maxNameLen {
		return ErrInvalidName
	}
	return nil
}

// nameKey maps an arbitrary logical name to a safe directory name.
func nameKey(name string) string {
	sum := sha256.Sum256([]byte(name))
	return hex.EncodeToString(sum[:])
}

func binName(ver uint64) string  { return fmt.Sprintf("%d.bin", ver) }
func metaName(ver uint64) string { return fmt.Sprintf("%d.meta", ver) }

func oldestVersion(st *fileState) uint64 {
	min := uint64(0)
	first := true
	for ver := range st.versions {
		if first || ver < min {
			min = ver
			first = false
		}
	}
	return min
}

func sortedVersions(st *fileState) []uint64 {
	vers := make([]uint64, 0, len(st.versions))
	for ver := range st.versions {
		vers = append(vers, ver)
	}
	sort.Slice(vers, func(i, j int) bool { return vers[i] < vers[j] })
	return vers
}

func (v *Vault) sortedFileKeys() []string {
	keys := make([]string, 0, len(v.files))
	for k := range v.files {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
