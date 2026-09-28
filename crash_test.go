package vault

// crash_test.go: exhaustive crash injection tests.
//
// Every persistent mutation (write-to-temp, rename, delete, mkdir) is routed
// through mutate(). For one RotateKey run and one evicting Put run we:
//   - record the complete ordered list of mutation points,
//   - for every point N and every interruption mode (before the mutation,
//     after it, and halfway through a content write), rebuild the same
//     starting state, install a hook that simulates kill -9 at that point,
//     reopen the vault, and verify every required safety property.

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type crashPanic struct{}

type crashMode int

const (
	modeBefore crashMode = iota
	modeMid
	modeAfter
)

func (m crashMode) String() string {
	switch m {
	case modeBefore:
		return "before"
	case modeMid:
		return "mid"
	default:
		return "after"
	}
}

// recordingHook performs every mutation and records it.
func recordingHook(log *[]hookOp) func(hookOp, func() error) error {
	return func(op hookOp, perform func() error) error {
		*log = append(*log, op)
		return perform()
	}
}

// crashingHook performs mutations normally until index at; at that point it
// interrupts with crashPanic (before: mutation skipped; mid: content write is
// performed halfway, other op kinds are performed atomically; after: the
// mutation completes).
func crashingHook(at int, mode crashMode, log *[]hookOp) func(hookOp, func() error) error {
	idx := 0
	return func(op hookOp, perform func() error) error {
		*log = append(*log, op)
		if idx < at {
			idx++
			return perform()
		}
		switch mode {
		case modeBefore:
			panic(crashPanic{})
		case modeMid:
			if op.Kind == opWrite {
				f, err := os.OpenFile(op.Path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
				if err != nil {
					panic(err)
				}
				half := len(op.Data) / 2
				if half == 0 {
					half = 1
				}
				if _, err := f.Write(op.Data[:half]); err != nil {
					f.Close()
					panic(err)
				}
				f.Close()
				panic(crashPanic{})
			}
			if err := perform(); err != nil {
				panic(err)
			}
			panic(crashPanic{})
		default: // after
			if err := perform(); err != nil {
				panic(err)
			}
			panic(crashPanic{})
		}
	}
}

func expectCrash(t *testing.T, label string) {
	t.Helper()
	if r := recover(); r != nil {
		if _, ok := r.(crashPanic); !ok {
			panic(r)
		}
	} else {
		t.Fatalf("%s: expected simulated crash", label)
	}
}

func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	if err := os.MkdirAll(dst, 0o700); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		sp := filepath.Join(src, e.Name())
		dp := filepath.Join(dst, e.Name())
		if e.IsDir() {
			copyDir(t, sp, dp)
			continue
		}
		in, err := os.Open(sp)
		if err != nil {
			t.Fatal(err)
		}
		out, err := os.OpenFile(dp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(out, in); err != nil {
			t.Fatal(err)
		}
		out.Close()
		in.Close()
	}
}

// assertCleanInvariants checks: exactly one KEK, empty tmp/journal, and that
// every blob/key file on disk is exactly the set referenced by metadata.
func assertCleanInvariants(t *testing.T, dir string, v *Vault, label string) {
	t.Helper()
	if keks, _ := os.ReadDir(filepath.Join(dir, kekDirName)); len(keks) != 1 {
		t.Fatalf("%s: KEK count = %d", label, len(keks))
	}
	if entries, _ := os.ReadDir(filepath.Join(dir, tmpDirName)); len(entries) != 0 {
		t.Fatalf("%s: tmp left behind: %d", label, len(entries))
	}
	if entries, _ := os.ReadDir(filepath.Join(dir, journalDirName)); len(entries) != 0 {
		t.Fatalf("%s: journal left behind: %d", label, len(entries))
	}
	expected := map[string]bool{}
	for name, fm := range v.files {
		hash := nameHash(name)
		for _, ver := range fm.Versions {
			expected[keyPath(dir, hash, ver.Version)] = true
			expected[blobPath(dir, hash, ver.Version)] = true
		}
	}
	actual := map[string]bool{}
	filepath.WalkDir(filepath.Join(dir, dataDirName), func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		actual[path] = true
		return nil
	})
	for p := range expected {
		if !actual[p] {
			t.Fatalf("%s: missing expected file %s", label, p)
		}
	}
	for p := range actual {
		if !expected[p] {
			t.Fatalf("%s: orphan file %s", label, p)
		}
	}
}

func scanNoPlaintext(t *testing.T, dir string, items []testItem, label string) {
	t.Helper()
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
				t.Fatalf("%s: plaintext leaked into %s (%s v%d)", label, path, it.name, it.ver)
			}
		}
		return nil
	})
}

// buildRotateState creates the starting vault for the RotateKey crash test:
// 30 logical files, 4 versions each (120 live versions).
func buildRotateState(t *testing.T) (items []testItem, dir, oldID string) {
	t.Helper()
	dir = t.TempDir()
	v, err := Open(dir, testRoot(), 1<<40)
	if err != nil {
		t.Fatal(err)
	}
	for f := 0; f < 30; f++ {
		name := fmt.Sprintf("dir-%02d/file", f)
		for i := 0; i < 4; i++ {
			data := []byte(fmt.Sprintf("ROTATE-SECRET-f%02d-i%d-payload%s", f, i, strings.Repeat("z", 11+i)))
			ver, err := v.Put(name, data)
			if err != nil {
				t.Fatal(err)
			}
			items = append(items, testItem{name, ver, data})
		}
	}
	return items, dir, v.kekID
}

func TestCrashRotateKey(t *testing.T) {
	testNoFsync = true
	defer func() { testNoFsync = false; testHook = nil }()

	items, masterDir, oldID := buildRotateState(t)

	// Counting run: a full RotateKey with every mutation recorded.
	countDir := t.TempDir()
	copyDir(t, masterDir, countDir)
	var ops []hookOp
	testHook = recordingHook(&ops)
	cv, err := Open(countDir, testRoot(), 1<<40)
	if err != nil {
		t.Fatal(err)
	}
	if err := cv.RotateKey(); err != nil {
		t.Fatal(err)
	}
	var newID string
	renameIndex := -1
	for i, op := range ops {
		if op.Kind == opRename && strings.HasSuffix(op.Path2, ".wrap") &&
			filepath.Base(op.Path2) != "kek-"+oldID+".wrap" {
			newID = strings.TrimSuffix(strings.TrimPrefix(filepath.Base(op.Path2), "kek-"), ".wrap")
			renameIndex = i
		}
	}
	if newID == "" || renameIndex < 0 {
		t.Fatal("could not locate new-KEK commit point")
	}
	assertCleanInvariants(t, countDir, cv, "counting run")
	testHook = nil

	total := len(ops)
	t.Logf("RotateKey: %d mutation points x 3 modes = %d crash scenarios", total, total*3)
	for i := 0; i < total; i++ {
		for _, mode := range []crashMode{modeBefore, modeMid, modeAfter} {
			label := fmt.Sprintf("rotate point %d/%d %s", i, total, mode)
			scenarioDir := t.TempDir()
			copyDir(t, masterDir, scenarioDir)

			v, err := Open(scenarioDir, testRoot(), 1<<40)
			if err != nil {
				t.Fatalf("%s: open: %v", label, err)
			}
			var crashedOp []hookOp
			testHook = crashingHook(i, mode, &crashedOp)
			func() {
				defer expectCrash(t, label)
				if err := v.RotateKey(); err != nil {
					t.Fatalf("%s: rotate returned err: %v", label, err)
				}
			}()
			testHook = nil

			rv, err := Open(scenarioDir, testRoot(), 1<<40)
			if err != nil {
				t.Fatalf("%s: reopen: %v", label, err)
			}

			var scenarioNewID string
			for _, op := range crashedOp {
				if op.Kind == opRename && strings.HasSuffix(op.Path2, ".wrap") &&
					filepath.Base(op.Path2) != "kek-"+oldID+".wrap" {
					scenarioNewID = strings.TrimSuffix(strings.TrimPrefix(filepath.Base(op.Path2), "kek-"), ".wrap")
				}
			}
			committedNew := i > renameIndex || (i == renameIndex && mode != modeBefore)
			if committedNew {
				if scenarioNewID == "" || rv.kekID != scenarioNewID {
					t.Fatalf("%s: kek = %s, want scenario-new %s", label, rv.kekID, scenarioNewID)
				}
				if _, err := os.Stat(kekPath(scenarioDir, oldID)); !os.IsNotExist(err) {
					t.Fatalf("%s: retired KEK still on disk", label)
				}
			} else {
				if rv.kekID != oldID {
					t.Fatalf("%s: kek = %s, want old %s", label, rv.kekID, oldID)
				}
			}

			// Every pre-existing version reads back byte-for-byte.
			var wantUsage int64
			for _, it := range items {
				got, err := rv.Get(it.name, it.ver)
				if err != nil {
					t.Fatalf("%s: get %s v%d: %v", label, it.name, it.ver, err)
				}
				if !bytes.Equal(got, it.data) {
					t.Fatalf("%s: data mismatch %s v%d", label, it.name, it.ver)
				}
				wantUsage += int64(len(it.data))
			}
			if rv.Usage() != wantUsage {
				t.Fatalf("%s: usage = %d want %d", label, rv.Usage(), wantUsage)
			}

			// Every key file on disk is wrapped with the surviving KEK.
			filepath.WalkDir(filepath.Join(scenarioDir, dataDirName), func(path string, d os.DirEntry, err error) error {
				if err != nil || d.IsDir() || !strings.HasSuffix(path, ".key") {
					return nil
				}
				b, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("%s: %v", label, err)
				}
				id, _, err := parseKeyFile(b)
				if err != nil || id != rv.kekID {
					t.Fatalf("%s: key %s wrapped by %q, want %q", label, path, id, rv.kekID)
				}
				return nil
			})

			assertCleanInvariants(t, scenarioDir, rv, label)
			scanNoPlaintext(t, scenarioDir, items, label)

			// The surviving KEK must support new writes.
			if _, err := rv.Put("dir-00/file", []byte("post-crash-put-content")); err != nil {
				t.Fatalf("%s: post-crash put: %v", label, err)
			}
			got, err := rv.Get("dir-00/file", 5)
			if err != nil || string(got) != "post-crash-put-content" {
				t.Fatalf("%s: post-crash get: %q %v", label, got, err)
			}
		}
	}
}

// buildEvictionState: file "evict-file" with exactly 25 versions plus an
// unrelated file with 2 versions.
func buildEvictionState(t *testing.T) (fItems, other []testItem, dir string) {
	t.Helper()
	dir = t.TempDir()
	v, err := Open(dir, testRoot(), 1<<40)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 25; i++ {
		data := []byte(fmt.Sprintf("evict-file-version-%02d-body", i))
		ver, err := v.Put("evict-file", data)
		if err != nil || ver != i {
			t.Fatalf("put v%d = %d %v", i, ver, err)
		}
		fItems = append(fItems, testItem{"evict-file", ver, data})
	}
	for i := 1; i <= 2; i++ {
		data := []byte(fmt.Sprintf("other-file-version-%d", i))
		ver, err := v.Put("other-file", data)
		if err != nil {
			t.Fatal(err)
		}
		other = append(other, testItem{"other-file", ver, data})
	}
	return fItems, other, dir
}

func TestCrashPutEviction(t *testing.T) {
	testNoFsync = true
	defer func() { testNoFsync = false; testHook = nil }()

	fItems, other, masterDir := buildEvictionState(t)
	newData := []byte("evict-file-version-26-the-newcomer")

	// Counting run.
	countDir := t.TempDir()
	copyDir(t, masterDir, countDir)
	var ops []hookOp
	testHook = recordingHook(&ops)
	cv, err := Open(countDir, testRoot(), 1<<40)
	if err != nil {
		t.Fatal(err)
	}
	newVer, err := cv.Put("evict-file", newData)
	if err != nil || newVer != 26 {
		t.Fatalf("counting put = %d %v", newVer, err)
	}
	hash := nameHash("evict-file")
	commitIndex := -1
	for i, op := range ops {
		if op.Kind == opRename && op.Path2 == metaPath(countDir, hash) {
			commitIndex = i
		}
	}
	if commitIndex < 0 {
		t.Fatal("could not locate Put commit point")
	}
	assertCleanInvariants(t, countDir, cv, "counting run")
	testHook = nil

	total := len(ops)
	t.Logf("evicting Put: %d mutation points x 3 modes = %d crash scenarios", total, total*3)
	for i := 0; i < total; i++ {
		for _, mode := range []crashMode{modeBefore, modeMid, modeAfter} {
			label := fmt.Sprintf("put point %d/%d %s", i, total, mode)
			scenarioDir := t.TempDir()
			copyDir(t, masterDir, scenarioDir)

			v, err := Open(scenarioDir, testRoot(), 1<<40)
			if err != nil {
				t.Fatalf("%s: open: %v", label, err)
			}
			var crashedOp []hookOp
			testHook = crashingHook(i, mode, &crashedOp)
			var putErr error
			func() {
				defer expectCrash(t, label)
				_, putErr = v.Put("evict-file", newData)
			}()
			testHook = nil
			if putErr != nil {
				t.Fatalf("%s: put returned err: %v", label, putErr)
			}

			rv, err := Open(scenarioDir, testRoot(), 1<<40)
			if err != nil {
				t.Fatalf("%s: reopen: %v", label, err)
			}

			committed := i > commitIndex || (i == commitIndex && mode != modeBefore)
			vers, err := rv.Versions("evict-file")
			if err != nil {
				t.Fatalf("%s: versions: %v", label, err)
			}
			if len(vers) != 25 {
				t.Fatalf("%s: live versions = %d, want 25 (never 26)", label, len(vers))
			}
			if committed {
				// New version present, oldest evicted.
				if vers[0].Version != 2 || vers[24].Version != 26 {
					t.Fatalf("%s: committed state versions %+v", label, vers)
				}
				got, err := rv.Get("evict-file", 26)
				if err != nil || !bytes.Equal(got, newData) {
					t.Fatalf("%s: v26 = %q %v", label, got, err)
				}
				if _, err := rv.Get("evict-file", 1); err == nil {
					t.Fatalf("%s: evicted v1 still readable", label)
				}
			} else {
				// Rolled back: v1 alive, no v26.
				if vers[0].Version != 1 || vers[24].Version != 25 {
					t.Fatalf("%s: rolled-back versions %+v", label, vers)
				}
				if _, err := rv.Get("evict-file", 26); err == nil {
					t.Fatalf("%s: v26 readable after rollback", label)
				}
				got, err := rv.Get("evict-file", 1)
				if err != nil || !bytes.Equal(got, fItems[0].data) {
					t.Fatalf("%s: v1 = %q %v", label, got, err)
				}
			}

			// All surviving versions read back byte-for-byte.
			var wantUsage int64
			live := fItems
			if committed {
				live = append(append([]testItem{}, fItems[1:]...), testItem{"evict-file", 26, newData})
			}
			for _, it := range live {
				got, err := rv.Get(it.name, it.ver)
				if err != nil || !bytes.Equal(got, it.data) {
					t.Fatalf("%s: get %s v%d: %v", label, it.name, it.ver, err)
				}
				wantUsage += int64(len(it.data))
			}
			for _, it := range other {
				got, err := rv.Get(it.name, it.ver)
				if err != nil || !bytes.Equal(got, it.data) {
					t.Fatalf("%s: get %s v%d: %v", label, it.name, it.ver, err)
				}
				wantUsage += int64(len(it.data))
			}
			if rv.Usage() != wantUsage {
				t.Fatalf("%s: usage = %d want %d", label, rv.Usage(), wantUsage)
			}

			assertCleanInvariants(t, scenarioDir, rv, label)
			scanNoPlaintext(t, scenarioDir, append(append([]testItem{}, live...), other...), label)

			// Version numbers of committed Puts are never reused.
			next, err := rv.Put("evict-file", []byte("post-crash-followup"))
			if err != nil {
				t.Fatalf("%s: follow-up put: %v", label, err)
			}
			wantNext := 26
			if committed {
				wantNext = 27
			}
			if next != wantNext {
				t.Fatalf("%s: follow-up version = %d, want %d", label, next, wantNext)
			}
		}
	}
}

// TestCrashDuringRecovery verifies that Open-time recovery is itself
// crash-safe: interrupting a recovering Open at every recovery write point
// leaves a state that the next Open completes correctly.
func TestCrashDuringRecovery(t *testing.T) {
	testNoFsync = true
	defer func() { testNoFsync = false; testHook = nil }()

	items, masterDir, oldID := buildRotateState(t)

	// Build a crashed-mid-rotation snapshot (point 50 = inside key rewrapping).
	const basePoint = 50
	crashedMaster := t.TempDir()
	copyDir(t, masterDir, crashedMaster)
	v, err := Open(crashedMaster, testRoot(), 1<<40)
	if err != nil {
		t.Fatal(err)
	}
	var baseOp []hookOp
	testHook = crashingHook(basePoint, modeMid, &baseOp)
	func() { defer expectCrash(t, "base crash"); _ = v.RotateKey() }()
	testHook = nil

	// Count recovery write points for one successful recovering Open.
	countDir := t.TempDir()
	copyDir(t, crashedMaster, countDir)
	var recOps []hookOp
	testHook = recordingHook(&recOps)
	if _, err := Open(countDir, testRoot(), 1<<40); err != nil {
		t.Fatal(err)
	}
	testHook = nil

	total := len(recOps)
	t.Logf("recovery: %d points, testing every 2nd point x 3 modes", total)
	if total < 100 {
		t.Fatalf("suspiciously few recovery points: %d", total)
	}
	for i := 0; i < total; i += 2 {
		for _, mode := range []crashMode{modeBefore, modeMid, modeAfter} {
			label := fmt.Sprintf("recovery point %d/%d %s", i, total, mode)
			scenarioDir := t.TempDir()
			copyDir(t, crashedMaster, scenarioDir)

			var crashedOps []hookOp
			testHook = crashingHook(i, mode, &crashedOps)
			func() {
				defer expectCrash(t, label)
				if _, err := Open(scenarioDir, testRoot(), 1<<40); err != nil {
					t.Fatalf("%s: err: %v", label, err)
				}
			}()
			testHook = nil

			rv, err := Open(scenarioDir, testRoot(), 1<<40)
			if err != nil {
				t.Fatalf("%s: final open: %v", label, err)
			}
			if rv.kekID == oldID {
				t.Fatalf("%s: rotation not rolled forward", label)
			}
			for _, it := range items {
				got, err := rv.Get(it.name, it.ver)
				if err != nil || !bytes.Equal(got, it.data) {
					t.Fatalf("%s: get %s v%d: %v", label, it.name, it.ver, err)
				}
			}
			assertCleanInvariants(t, scenarioDir, rv, label)
		}
	}
}
