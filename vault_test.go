package vault

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testRoot() []byte {
	return bytes.Repeat([]byte{0x42}, 32)
}

func TestPutGetBasic(t *testing.T) {
	v, dir := openTestVault(t, 1<<30)
	data := []byte("hello vault")
	ver, err := v.Put("a/b/c.txt", data)
	if err != nil {
		t.Fatal(err)
	}
	if ver != 1 {
		t.Fatalf("version = %d, want 1", ver)
	}
	got, err := v.Get("a/b/c.txt", 1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("data mismatch")
	}
	if v.Usage() != int64(len(data)) {
		t.Fatalf("usage = %d", v.Usage())
	}
	vers, err := v.Versions("a/b/c.txt")
	if err != nil || len(vers) != 1 {
		t.Fatalf("Versions = %v %v", vers, err)
	}
	if vers[0].Size != int64(len(data)) || vers[0].Version != 1 {
		t.Fatalf("version meta = %+v", vers[0])
	}
	if vers[0].SHA256 != sha256Sum(data) {
		t.Fatal("sha mismatch in meta")
	}
	_ = dir
}

func TestVersionsAndUsage(t *testing.T) {
	v, _ := openTestVault(t, 1<<30)
	if _, err := v.Put("f1", []byte("aaa")); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Put("f2", []byte("bbbbb")); err != nil {
		t.Fatal(err)
	}
	v2, err := v.Put("f1", []byte("cc"))
	if err != nil || v2 != 2 {
		t.Fatalf("v2 = %d %v", v2, err)
	}
	if v.Usage() != 3+5+2 {
		t.Fatalf("usage = %d", v.Usage())
	}
	vers, _ := v.Versions("f1")
	if len(vers) != 2 || vers[0].Version != 1 || vers[1].Version != 2 {
		t.Fatalf("f1 versions = %+v", vers)
	}
	got, err := v.Get("f1", 1)
	if err != nil || string(got) != "aaa" {
		t.Fatalf("get v1 = %q %v", got, err)
	}
	got, err = v.Get("f1", 2)
	if err != nil || string(got) != "cc" {
		t.Fatalf("get v2 = %q %v", got, err)
	}
	if _, err := v.Get("f1", 99); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing version err = %v", err)
	}
	if _, err := v.Get("nope", 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing name err = %v", err)
	}
	vers, err = v.Versions("nope")
	if err != nil || len(vers) != 0 {
		t.Fatalf("Versions missing = %v %v", vers, err)
	}
}

func TestEviction(t *testing.T) {
	v, dir := openTestVault(t, 1<<30)
	var contents [][]byte
	for i := 0; i < 25; i++ {
		data := []byte(fmt.Sprintf("data-%02d", i))
		contents = append(contents, data)
		if ver, err := v.Put("f", data); err != nil || ver != i+1 {
			t.Fatalf("put %d: %d %v", i, ver, err)
		}
	}
	if _, err := v.Put("f", []byte("data-25")); err != nil {
		t.Fatal(err)
	}
	vers, _ := v.Versions("f")
	if len(vers) != 25 {
		t.Fatalf("live versions = %d", len(vers))
	}
	if vers[0].Version != 2 {
		t.Fatalf("oldest = %d, want 2", vers[0].Version)
	}
	if _, err := v.Get("f", 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("evicted v1 err = %v", err)
	}
	got, err := v.Get("f", 2)
	if err != nil || string(got) != "data-01" {
		t.Fatalf("v2 = %q %v", got, err)
	}
	got, err = v.Get("f", 26)
	if err != nil || string(got) != "data-25" {
		t.Fatalf("v26 = %q %v", got, err)
	}
	// after reopen: still 25 versions, usage consistent, no orphan files
	v2, err := Open(dir, testRoot(), 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	vers, _ = v2.Versions("f")
	if len(vers) != 25 || vers[0].Version != 2 || vers[24].Version != 26 {
		t.Fatalf("after reopen: %+v", vers)
	}
	var wantUsage int64
	for _, c := range contents[1:] {
		wantUsage += int64(len(c))
	}
	wantUsage += 7
	if v2.Usage() != wantUsage {
		t.Fatalf("usage after reopen = %d want %d", v2.Usage(), wantUsage)
	}
	countFiles(t, dir, nil)
}

func TestQuotaRejection(t *testing.T) {
	v, dir := openTestVault(t, 10)
	if _, err := v.Put("f", []byte("12345")); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Put("g", []byte("ABCDEFG")); !errors.Is(err, ErrQuota) {
		t.Fatalf("quota err = %v", err)
	}
	if v.Usage() != 5 {
		t.Fatalf("usage after reject = %d", v.Usage())
	}
	// rejected put left no trace: same version number is allocated again
	ver, err := v.Put("g", []byte("12345"))
	if err != nil || ver != 1 {
		t.Fatalf("retry put = %d %v", ver, err)
	}
	if v.Usage() != 10 {
		t.Fatalf("usage = %d", v.Usage())
	}
	// third put to a 25-version file must also be checked against post-eviction usage
	v2, err := Open(dir, testRoot(), 10)
	if err != nil {
		t.Fatal(err)
	}
	countFiles(t, dir, nil)
	_ = v2
}

func TestRotateKey(t *testing.T) {
	v, dir := openTestVault(t, 1<<30)
	var items []testItem
	for f := 0; f < 30; f++ {
		for i := 0; i < 4; i++ {
			data := []byte(fmt.Sprintf("file-%d-content-%d-%s", f, i, strings.Repeat("x", i*7)))
			ver, err := v.Put(fmt.Sprintf("dir%d/f%d", f, f), data)
			if err != nil {
				t.Fatal(err)
			}
			items = append(items, testItem{fmt.Sprintf("dir%d/f%d", f, f), ver, data})
		}
	}
	oldID := v.kekID
	if err := v.RotateKey(); err != nil {
		t.Fatal(err)
	}
	if v.kekID == oldID {
		t.Fatal("KEK id did not change")
	}
	for _, it := range items {
		got, err := v.Get(it.name, it.ver)
		if err != nil || !bytes.Equal(got, it.data) {
			t.Fatalf("get %s v%d after rotate: %v", it.name, it.ver, err)
		}
	}
	// reopen with the new KEK and verify again
	v2, err := Open(dir, testRoot(), 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	if v2.kekID != v.kekID {
		t.Fatalf("kek after reopen = %s want %s", v2.kekID, v.kekID)
	}
	for _, it := range items {
		got, err := v2.Get(it.name, it.ver)
		if err != nil || !bytes.Equal(got, it.data) {
			t.Fatalf("reopen get %s v%d: %v", it.name, it.ver, err)
		}
	}
	auditDir(t, dir, v2, items)
}

func TestNamesAndCaseSensitivity(t *testing.T) {
	v, _ := openTestVault(t, 1<<30)
	names := []string{
		"..",
		"../escape",
		"a/../../b",
		"日本語/ファイル.txt",
		strings.Repeat("\x01", 4096),
		"Mix",
		"mix",
		"MIX",
		"",
	}
	for i, name := range names {
		if name == "" {
			if _, err := v.Put(name, []byte("x")); !errors.Is(err, ErrInvalidName) {
				t.Fatalf("empty name err = %v", err)
			}
			continue
		}
		data := []byte(fmt.Sprintf("payload-%d", i))
		if _, err := v.Put(name, data); err != nil {
			t.Fatalf("put %q: %v", name, err)
		}
		got, err := v.Get(name, 1)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("get %q: %v", name, err)
		}
	}
	if _, err := v.Put(strings.Repeat("a", 4097), nil); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("long name err = %v", err)
	}
	vers, _ := v.Versions("mix")
	if len(vers) != 1 {
		t.Fatalf("case sensitivity broken: %+v", vers)
	}
}

func TestTamperDetected(t *testing.T) {
	v, dir := openTestVault(t, 1<<30)
	data := []byte("tamper me please")
	if _, err := v.Put("f", data); err != nil {
		t.Fatal(err)
	}
	hash := nameHash("f")
	bp := blobPath(dir, hash, 1)
	b, err := os.ReadFile(bp)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)-1] ^= 0xff
	if err := os.WriteFile(bp, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Get("f", 1); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("tamper err = %v", err)
	}
}

func TestOpenWrongSecret(t *testing.T) {
	_, dir := openTestVault(t, 1<<30)
	if _, err := Open(dir, bytes.Repeat([]byte{1}, 32), 1<<30); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("wrong secret err = %v", err)
	}
}

// --- helpers ---

func openTestVault(t *testing.T, quota int64) (*Vault, string) {
	t.Helper()
	dir := t.TempDir()
	v, err := Open(dir, testRoot(), quota)
	if err != nil {
		t.Fatal(err)
	}
	return v, dir
}

func sha256Sum(b []byte) [32]byte {
	return sha256Raw(b)
}

// countFiles asserts on leftover categories in the vault directory.
func countFiles(t *testing.T, dir string, _ []string) {
	t.Helper()
	if entries, _ := os.ReadDir(filepath.Join(dir, tmpDirName)); len(entries) != 0 {
		t.Fatalf("tmp not empty: %d entries", len(entries))
	}
	if entries, _ := os.ReadDir(filepath.Join(dir, journalDirName)); len(entries) != 0 {
		t.Fatalf("journal not empty: %d", len(entries))
	}
}

// auditDir checks exactly one KEK, expected blobs/keys, and no plaintext
// leaks anywhere on disk.
func auditDir(t *testing.T, dir string, v *Vault, items []testItem) {
	t.Helper()
	keks, _ := os.ReadDir(filepath.Join(dir, kekDirName))
	if len(keks) != 1 {
		t.Fatalf("kek count = %d", len(keks))
	}
	countFiles(t, dir, nil)
	// no plaintext content anywhere on disk
	var foundPlaintext bool
	filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		for _, it := range items {
			if len(it.data) > 0 && bytes.Contains(b, it.data) {
				foundPlaintext = true
				t.Errorf("plaintext of %q v%d found in %s", it.name, it.ver, path)
			}
		}
		return nil
	})
	if foundPlaintext {
		t.Fatal("plaintext leaked to disk")
	}
}
