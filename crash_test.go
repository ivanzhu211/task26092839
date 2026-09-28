package vault

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

const (
	crashDir   = "vault"
	crashQuota = int64(1) << 50
)

var crashSecret = bytes.Repeat([]byte{0x07}, 32)

// crashCase is one enumerated interruption of a vault operation.
type crashCase struct {
	index int       // write-point index
	kind  string    // write-point kind ("write", "rename", ...)
	mode  crashMode // before / after / mid-write
}

// enumerateWritePoints dry-runs op on a clone of base and returns every crash
// case to test: before and after each persistence write point, plus halfway
// through every file write.
func enumerateWritePoints(t *testing.T, base *memFS, op func(v *Vault) error) []crashCase {
	t.Helper()
	dry := base.clone()
	v, err := openVault(dry, crashDir, crashSecret, crashQuota)
	if err != nil {
		t.Fatalf("dry-run open: %v", err)
	}
	dry.arm(-1, crashBefore) // reset the op log
	if err := op(v); err != nil {
		t.Fatalf("dry-run op: %v", err)
	}
	var cases []crashCase
	for i, kind := range dry.ops {
		cases = append(cases, crashCase{i, kind, crashBefore})
		cases = append(cases, crashCase{i, kind, crashAfter})
		if kind == "write" {
			cases = append(cases, crashCase{i, kind, crashMid})
		}
	}
	return cases
}

// verifyCleanTree asserts the on-disk tree is exactly a well-formed vault:
// one KEK file, no journal, no temp files anywhere.
func verifyCleanTree(t *testing.T, m *memFS) {
	t.Helper()
	ents, err := m.ReadDir(crashDir)
	if err != nil {
		t.Fatalf("read root: %v", err)
	}
	kekCount := 0
	for _, e := range ents {
		switch e {
		case kekName:
			kekCount++
		case filesDir:
		default:
			t.Errorf("unexpected root entry %q", e)
		}
	}
	if kekCount != 1 {
		t.Errorf("root has %d KEK files, want exactly 1", kekCount)
	}
	for p := range m.files {
		if strings.HasSuffix(p, ".tmp") {
			t.Errorf("leftover temp file %q", p)
		}
	}
}

// verifyState asserts every property that must hold after Open returns:
// exact surviving version sets, byte-exact reads, single usable KEK
// generation, and exact usage accounting.
func verifyState(t *testing.T, v *Vault, want map[string]map[uint64][]byte) {
	t.Helper()
	var usage int64
	for name, versions := range want {
		infos, err := v.Versions(name)
		if err != nil {
			t.Fatalf("Versions(%q): %v", name, err)
		}
		if len(infos) > maxVersions {
			t.Fatalf("Versions(%q) = %d entries, more than %d", name, len(infos), maxVersions)
		}
		if len(infos) != len(versions) {
			t.Fatalf("Versions(%q) = %d entries, want %d", name, len(infos), len(versions))
		}
		for i, info := range infos {
			data, ok := versions[info.Version]
			if !ok {
				t.Fatalf("Versions(%q): unexpected version %d", name, info.Version)
			}
			if i > 0 && infos[i-1].Version >= info.Version {
				t.Fatalf("Versions(%q) not strictly increasing", name)
			}
			if info.Size != int64(len(data)) {
				t.Fatalf("Versions(%q)[%d].Size = %d, want %d", name, info.Version, info.Size, len(data))
			}
			got, err := v.Get(name, info.Version)
			if err != nil {
				t.Fatalf("Get(%q,%d): %v", name, info.Version, err)
			}
			if !bytes.Equal(got, data) {
				t.Fatalf("Get(%q,%d) returned wrong bytes", name, info.Version)
			}
			usage += info.Size
		}
	}
	if got := v.Usage(); got != usage {
		t.Fatalf("Usage() = %d, want %d", got, usage)
	}
	// Every surviving version must depend on the single current KEK.
	for key, st := range v.files {
		for ver, m := range st.versions {
			if m.KEKGen != v.kekGen {
				t.Fatalf("version %s/%d wrapped with KEK gen %d, current is %d",
					key, ver, m.KEKGen, v.kekGen)
			}
		}
	}
}

// TestCrashPutWithEviction interrupts a Put that triggers an eviction at every
// persistence write point: before it, after it, and halfway through it.
func TestCrashPutWithEviction(t *testing.T) {
	base := newMemFS()
	v, err := openVault(base, crashDir, crashSecret, crashQuota)
	if err != nil {
		t.Fatal(err)
	}
	all := make(map[string]map[uint64][]byte)
	put := func(name string, data []byte) uint64 {
		ver, err := v.Put(name, data)
		if err != nil {
			t.Fatalf("setup Put(%q): %v", name, err)
		}
		if all[name] == nil {
			all[name] = make(map[uint64][]byte)
		}
		all[name][ver] = data
		return ver
	}
	for i := 1; i <= maxVersions; i++ {
		put("victim", []byte(fmt.Sprintf("victim-version-%02d", i)))
	}
	put("other/one", []byte("first other"))
	put("other/one", []byte("second other"))
	put("other/两", []byte("unicode data"))

	data26 := []byte("the twenty-sixth version, triggering eviction")
	op := func(v *Vault) error {
		_, err := v.Put("victim", data26)
		return err
	}
	cases := enumerateWritePoints(t, base, op)
	if len(cases) == 0 {
		t.Fatal("no write points enumerated")
	}
	t.Logf("enumerating %d crash cases", len(cases))

	for _, c := range cases {
		t.Run(fmt.Sprintf("op%d_%s_mode%d", c.index, c.kind, c.mode), func(t *testing.T) {
			m := base.clone()
			v2, err := openVault(m, crashDir, crashSecret, crashQuota)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			m.arm(c.index, c.mode)
			ver, putErr := v2.Put("victim", data26)
			putOK := putErr == nil
			if putOK && ver != 26 {
				t.Fatalf("Put returned version %d, want 26", ver)
			}
			m.revive()

			v3, err := openVault(m, crashDir, crashSecret, crashQuota)
			if err != nil {
				t.Fatalf("reopen after crash: %v", err)
			}
			verifyCleanTree(t, m)

			// The interrupted Put is either fully effective (version 26
			// present, version 1 evicted) or never happened (1..25 intact).
			want := make(map[string]map[uint64][]byte)
			for name, versions := range all {
				want[name] = make(map[uint64][]byte)
				for ver, data := range versions {
					want[name][ver] = data
				}
			}
			_, has26 := v3.files[nameKey("victim")].versions[26]
			if putOK && !has26 {
				t.Fatal("Put returned success but version 26 is missing after recovery")
			}
			if has26 {
				delete(want["victim"], 1)
				want["victim"][26] = data26
			}
			verifyState(t, v3, want)

			// Version numbers are never reused after a successful Put.
			maxVer := uint64(0)
			for ver := range v3.files[nameKey("victim")].versions {
				if ver > maxVer {
					maxVer = ver
				}
			}
			newVer, err := v3.Put("victim", []byte("post-crash put"))
			if err != nil {
				t.Fatalf("post-crash Put: %v", err)
			}
			if newVer <= maxVer {
				t.Fatalf("post-crash Put reused version %d <= %d", newVer, maxVer)
			}
			if putOK && newVer <= 26 {
				t.Fatalf("version 26 was returned by a successful Put but %d was reallocated", newVer)
			}
		})
	}
}

// TestCrashRotateKey interrupts RotateKey at every persistence write point:
// before it, after it, and halfway through it.
func TestCrashRotateKey(t *testing.T) {
	base := newMemFS()
	v, err := openVault(base, crashDir, crashSecret, crashQuota)
	if err != nil {
		t.Fatal(err)
	}
	all := make(map[string]map[uint64][]byte)
	// 40 logical files x 4 versions = 160 surviving versions.
	for f := 0; f < 40; f++ {
		name := fmt.Sprintf("dir%d/file-%d", f%7, f)
		all[name] = make(map[uint64][]byte)
		for ver := uint64(1); ver <= 4; ver++ {
			data := []byte(fmt.Sprintf("file %d version %d payload", f, ver))
			got, err := v.Put(name, data)
			if err != nil {
				t.Fatalf("setup Put: %v", err)
			}
			if got != ver {
				t.Fatalf("setup Put version = %d, want %d", got, ver)
			}
			all[name][ver] = data
		}
	}
	oldGen := v.kekGen

	op := func(v *Vault) error { return v.RotateKey() }
	cases := enumerateWritePoints(t, base, op)
	t.Logf("enumerating %d crash cases", len(cases))

	for _, c := range cases {
		t.Run(fmt.Sprintf("op%d_%s_mode%d", c.index, c.kind, c.mode), func(t *testing.T) {
			m := base.clone()
			v2, err := openVault(m, crashDir, crashSecret, crashQuota)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			m.arm(c.index, c.mode)
			rotErr := v2.RotateKey()
			rotOK := rotErr == nil
			m.revive()

			v3, err := openVault(m, crashDir, crashSecret, crashQuota)
			if err != nil {
				t.Fatalf("reopen after crash: %v", err)
			}
			verifyCleanTree(t, m)

			// Exactly one KEK on disk; if RotateKey returned, it is the new one.
			kf, err := decodeKEKFile(must(m.ReadFile(crashDir + "/" + kekName)))
			if err != nil {
				t.Fatalf("decode kek: %v", err)
			}
			if rotOK && kf.Gen != oldGen+1 {
				t.Fatalf("RotateKey returned success but KEK gen = %d, want %d", kf.Gen, oldGen+1)
			}
			if kf.Gen != oldGen && kf.Gen != oldGen+1 {
				t.Fatalf("KEK gen = %d, want %d or %d", kf.Gen, oldGen, oldGen+1)
			}
			if v3.kekGen != kf.Gen {
				t.Fatalf("in-memory gen %d != on-disk gen %d", v3.kekGen, kf.Gen)
			}

			// Every surviving version reads back byte-exact with the one KEK.
			verifyState(t, v3, all)

			// The vault stays fully functional: another rotation and more Puts.
			if err := v3.RotateKey(); err != nil {
				t.Fatalf("post-crash RotateKey: %v", err)
			}
			verifyState(t, v3, all)
			ver, err := v3.Put("dir0/file-0", []byte("post-crash"))
			if err != nil {
				t.Fatalf("post-crash Put: %v", err)
			}
			if ver != 5 {
				t.Fatalf("post-crash Put version = %d, want 5", ver)
			}
		})
	}
}
