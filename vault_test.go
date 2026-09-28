package vault

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var testSecret = bytes.Repeat([]byte{0x42}, 32)

func openTest(t *testing.T, dir string, quota int64) *Vault {
	t.Helper()
	v, err := Open(dir, testSecret, quota)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return v
}

func mustPut(t *testing.T, v *Vault, name string, data []byte) uint64 {
	t.Helper()
	ver, err := v.Put(name, data)
	if err != nil {
		t.Fatalf("Put(%q): %v", name, err)
	}
	return ver
}

func mustGet(t *testing.T, v *Vault, name string, ver uint64, want []byte) {
	t.Helper()
	got, err := v.Get(name, ver)
	if err != nil {
		t.Fatalf("Get(%q,%d): %v", name, ver, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Get(%q,%d) = %q, want %q", name, ver, got, want)
	}
}

func TestBasicPutGetVersions(t *testing.T) {
	dir := t.TempDir()
	v := openTest(t, dir, 1<<40)
	if v.Usage() != 0 {
		t.Fatalf("fresh Usage = %d", v.Usage())
	}
	d1 := []byte("hello world")
	d2 := []byte("second version")
	ver1 := mustPut(t, v, "file", d1)
	ver2 := mustPut(t, v, "file", d2)
	if ver1 != 1 || ver2 != 2 {
		t.Fatalf("versions = %d,%d, want 1,2", ver1, ver2)
	}
	mustGet(t, v, "file", 1, d1)
	mustGet(t, v, "file", 2, d2)
	if got := v.Usage(); got != int64(len(d1)+len(d2)) {
		t.Fatalf("Usage = %d, want %d", got, len(d1)+len(d2))
	}
	infos, err := v.Versions("file")
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 2 || infos[0].Version != 1 || infos[1].Version != 2 {
		t.Fatalf("Versions = %+v", infos)
	}
	sum := sha256.Sum256(d2)
	if infos[1].SHA256 != sum || infos[1].Size != int64(len(d2)) || infos[1].Time.IsZero() {
		t.Fatalf("bad metadata: %+v", infos[1])
	}
	if _, err := v.Get("file", 99); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get missing = %v", err)
	}
	if _, err := v.Get("nope", 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get unknown name = %v", err)
	}
}

func TestArbitraryNames(t *testing.T) {
	dir := t.TempDir()
	v := openTest(t, dir, 1<<40)
	names := []string{
		"/", "..", "../..", "a/b/c", ".", "...",
		"文件🔒/üñïçødé", strings.Repeat("x", 4096),
		"CaseSensitive", "casesensitive",
	}
	for i, n := range names {
		data := []byte{byte(i)}
		mustPut(t, v, n, data)
		mustGet(t, v, n, 1, data)
	}
	for _, n := range []string{"", strings.Repeat("y", 4097)} {
		if _, err := v.Put(n, nil); !errors.Is(err, ErrInvalidName) {
			t.Fatalf("Put(%q len=%d) = %v", n, len(n), err)
		}
		if _, err := v.Get(n, 1); !errors.Is(err, ErrInvalidName) {
			t.Fatalf("Get invalid = %v", err)
		}
	}
}

func TestEviction(t *testing.T) {
	dir := t.TempDir()
	v := openTest(t, dir, 1<<40)
	for i := 1; i <= 26; i++ {
		ver := mustPut(t, v, "f", []byte{byte(i)})
		if ver != uint64(i) {
			t.Fatalf("ver = %d, want %d", ver, i)
		}
	}
	infos, _ := v.Versions("f")
	if len(infos) != 25 || infos[0].Version != 2 || infos[24].Version != 26 {
		t.Fatalf("after eviction: %+v", infos)
	}
	if _, err := v.Get("f", 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("evicted version still readable: %v", err)
	}
	mustGet(t, v, "f", 26, []byte{26})
	if got := v.Usage(); got != 25 {
		t.Fatalf("Usage = %d, want 25", got)
	}
	// Evicted ciphertext and metadata must be gone from disk.
	ents, err := os.ReadDir(filepath.Join(dir, filesDir, nameKey("f")))
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 50 {
		t.Fatalf("on-disk entries = %d, want 50 (25 bin + 25 meta)", len(ents))
	}
}

func TestQuota(t *testing.T) {
	dir := t.TempDir()
	v := openTest(t, dir, 10)
	mustPut(t, v, "a", []byte("12345"))
	mustPut(t, v, "b", []byte("12345"))
	before := snapshotDir(t, dir)
	if _, err := v.Put("c", []byte("x")); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("Put over quota = %v", err)
	}
	if got := v.Usage(); got != 10 {
		t.Fatalf("Usage = %d after rejected put", got)
	}
	if after := snapshotDir(t, dir); before != after {
		t.Fatalf("rejected put left traces on disk")
	}
	// Eviction makes room: 25 one-byte versions, quota 25, 26th fits.
	v2 := openTest(t, t.TempDir(), 25)
	for i := 0; i < 25; i++ {
		mustPut(t, v2, "f", []byte{byte(i)})
	}
	mustPut(t, v2, "f", []byte{0xff}) // evicts version 1, usage stays 25
	if got := v2.Usage(); got != 25 {
		t.Fatalf("Usage = %d, want 25", got)
	}
	if _, err := v2.Put("g", []byte{1}); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("Put beyond quota with full vault = %v", err)
	}
}

func TestRotateKey(t *testing.T) {
	dir := t.TempDir()
	v := openTest(t, dir, 1<<40)
	data := [][]byte{[]byte("alpha"), []byte("beta"), []byte("gamma")}
	for _, d := range data {
		mustPut(t, v, "f", d)
	}
	if err := v.RotateKey(); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	for i, d := range data {
		mustGet(t, v, "f", uint64(i+1), d)
	}
	// Exactly one KEK on disk, and it is generation 2.
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	kekCount := 0
	for _, e := range ents {
		if e.Name() == kekName {
			kekCount++
		}
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("leftover tmp file %q after RotateKey", e.Name())
		}
	}
	if kekCount != 1 {
		t.Fatalf("kek files = %d, want 1", kekCount)
	}
	kf, err := decodeKEKFile(must(os.ReadFile(filepath.Join(dir, kekName))))
	if err != nil || kf.Gen != 2 {
		t.Fatalf("kek gen = %+v, %v; want gen 2", kf, err)
	}
	// Reopen and rotate again.
	v = openTest(t, dir, 1<<40)
	mustGet(t, v, "f", 1, data[0])
	if err := v.RotateKey(); err != nil {
		t.Fatal(err)
	}
	mustGet(t, v, "f", 3, data[2])
}

func TestWrongSecret(t *testing.T) {
	dir := t.TempDir()
	v := openTest(t, dir, 1<<40)
	mustPut(t, v, "f", []byte("data"))
	bad := bytes.Repeat([]byte{0x99}, 32)
	if _, err := Open(dir, bad, 1<<40); !errors.Is(err, ErrBadSecret) {
		t.Fatalf("Open with wrong secret = %v", err)
	}
	if _, err := Open(dir, []byte("short"), 1<<40); !errors.Is(err, ErrBadSecret) {
		t.Fatalf("Open with short secret = %v", err)
	}
}

func TestIntegrityCheck(t *testing.T) {
	dir := t.TempDir()
	v := openTest(t, dir, 1<<40)
	mustPut(t, v, "f", []byte("important data"))
	bin := filepath.Join(dir, filesDir, nameKey("f"), "1.bin")
	ct := must(os.ReadFile(bin))
	ct[len(ct)-1] ^= 0xff
	if err := os.WriteFile(bin, ct, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Get("f", 1); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("Get corrupted = %v", err)
	}
}

func TestReopenPersists(t *testing.T) {
	dir := t.TempDir()
	v := openTest(t, dir, 1<<40)
	mustPut(t, v, "f", []byte("one"))
	mustPut(t, v, "f", []byte("two"))
	v = openTest(t, dir, 1<<40)
	mustGet(t, v, "f", 1, []byte("one"))
	ver := mustPut(t, v, "f", []byte("three"))
	if ver != 3 {
		t.Fatalf("version after reopen = %d, want 3", ver)
	}
	if got := v.Usage(); got != 11 {
		t.Fatalf("Usage = %d, want 11", got)
	}
}

func TestUnrecognizedFilesRejected(t *testing.T) {
	dir := t.TempDir()
	v := openTest(t, dir, 1<<40)
	mustPut(t, v, "f", []byte("x"))
	if err := os.WriteFile(filepath.Join(dir, "mystery"), []byte("?"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, testSecret, 1<<40); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Open with junk file = %v", err)
	}
}

func snapshotDir(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		if !info.IsDir() {
			data := must(os.ReadFile(p))
			sum := sha256.Sum256(data)
			b.WriteString(p)
			b.WriteByte(':')
			b.Write(sum[:])
			b.WriteByte('\n')
		}
		return nil
	})
	return b.String()
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
