package vault

import (
	"errors"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// errInjectedCrash is returned by every memFS operation once the simulated
// kill -9 has happened: the process is dead, nothing more can be persisted.
var errInjectedCrash = errors.New("injected crash")

// crashMode selects how the crash at a given write point happens.
type crashMode int

const (
	crashBefore crashMode = iota // die just before the write point
	crashAfter                   // die just after it completed
	crashMid                     // die halfway through a file write
)

// memFS is an in-memory fsys. Because we simulate kill -9 (not power loss),
// every completed operation is immediately durable; a crash only stops future
// operations. Mutating operations are counted as persistence write points so
// tests can enumerate every one of them.
type memFS struct {
	files map[string][]byte
	dirs  map[string]bool

	ops      []string  // kinds of mutating ops performed (for enumeration)
	limit    int       // op index to crash at; -1 disables injection
	mode     crashMode // how to crash at limit
	count    int       // mutating ops so far since arm
	dead     bool      // crashed: all further ops fail
	dieAfter bool      // crash once the current op completes
}

func newMemFS() *memFS {
	return &memFS{
		files: make(map[string][]byte),
		dirs:  map[string]bool{".": true},
		limit: -1,
	}
}

func (m *memFS) clone() *memFS {
	c := newMemFS()
	for k, v := range m.files {
		c.files[k] = append([]byte(nil), v...)
	}
	for k := range m.dirs {
		c.dirs[k] = true
	}
	return c
}

// arm enables fault injection at the given write-point index.
func (m *memFS) arm(limit int, mode crashMode) {
	m.limit = limit
	m.mode = mode
	m.count = 0
	m.ops = nil
	m.dead = false
	m.dieAfter = false
}

// revive disables injection after a crash, simulating the next process start.
func (m *memFS) revive() {
	m.limit = -1
	m.dead = false
	m.dieAfter = false
}

// tick accounts for one mutating op. It reports whether the op must fail
// before doing anything (crash-before) and whether a file write must be
// truncated halfway (crash-mid).
func (m *memFS) tick(kind string) (fail bool, mid bool) {
	if m.dead {
		return true, false
	}
	idx := m.count
	m.count++
	m.ops = append(m.ops, kind)
	if m.limit < 0 || idx != m.limit {
		return false, false
	}
	switch m.mode {
	case crashBefore:
		m.dead = true
		return true, false
	case crashAfter:
		m.dieAfter = true
	case crashMid:
		m.dieAfter = true // die right after the partial write lands
		return false, true
	}
	return false, false
}

func (m *memFS) postOp() {
	if m.dieAfter {
		m.dead = true
		m.dieAfter = false
	}
}

func (m *memFS) MkdirAll(dir string) error {
	if fail, _ := m.tick("mkdir"); fail {
		return errInjectedCrash
	}
	for d := dir; d != "." && d != "/" && d != ""; d = path.Dir(d) {
		m.dirs[d] = true
	}
	m.postOp()
	return nil
}

func (m *memFS) ReadDir(dir string) ([]string, error) {
	if m.dead {
		return nil, errInjectedCrash
	}
	if !m.dirs[dir] {
		return nil, fs.ErrNotExist
	}
	seen := make(map[string]bool)
	prefix := dir + "/"
	collect := func(p string) {
		if !strings.HasPrefix(p, prefix) {
			return
		}
		rest := p[len(prefix):]
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			rest = rest[:i]
		}
		seen[rest] = true
	}
	for p := range m.files {
		collect(p)
	}
	for d := range m.dirs {
		if d != dir {
			collect(d)
		}
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

func (m *memFS) ReadFile(name string) ([]byte, error) {
	if m.dead {
		return nil, errInjectedCrash
	}
	data, ok := m.files[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return append([]byte(nil), data...), nil
}

func (m *memFS) WriteFile(name string, data []byte) error {
	fail, mid := m.tick("write")
	if fail {
		return errInjectedCrash
	}
	if !m.dirs[path.Dir(name)] {
		return fs.ErrNotExist
	}
	if mid {
		data = data[:len(data)/2]
	}
	m.files[name] = append([]byte(nil), data...)
	m.postOp()
	return nil
}

func (m *memFS) Rename(oldname, newname string) error {
	if fail, _ := m.tick("rename"); fail {
		return errInjectedCrash
	}
	data, ok := m.files[oldname]
	if !ok {
		return fs.ErrNotExist
	}
	m.files[newname] = data
	delete(m.files, oldname)
	m.postOp()
	return nil
}

func (m *memFS) Remove(name string) error {
	if fail, _ := m.tick("remove"); fail {
		return errInjectedCrash
	}
	if _, ok := m.files[name]; !ok {
		return fs.ErrNotExist
	}
	delete(m.files, name)
	m.postOp()
	return nil
}

func (m *memFS) SyncDir(dir string) error {
	if fail, _ := m.tick("syncdir"); fail {
		return errInjectedCrash
	}
	m.postOp()
	return nil
}
