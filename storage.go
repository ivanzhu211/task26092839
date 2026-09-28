package vault

// storage.go: low-level persistent mutation primitives.
//
// Every persistent mutation performed by the vault goes through exactly one
// of the functions in this file (writeFileAtomic, deleteFile). Each mutation
// is reported to testHook (when set) as a single hookOp, which lets the
// crash test enumerate every persistent write point and interrupt before it,
// after it, or in the middle of a partial write.
//
// Durability model: file contents are written to a temporary file in tmp/,
// fsynced, then atomically renamed into place, followed by an fsync of the
// target directory. kill -9 at any point leaves either the old or the new
// state; partial writes can only ever affect files inside tmp/, which Open
// cleans up.

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// opKind identifies the kind of a persistent mutation.
type opKind int

const (
	opWrite  opKind = iota // write content to a (temporary) file
	opRename               // atomic rename
	opDelete               // delete a file
	opMkdir                // create a directory
)

// hookOp describes one persistent write point.
type hookOp struct {
	Kind  opKind
	Path  string
	Path2 string // destination for opRename
	Data  []byte // content for opWrite
}

// testHook, when non-nil, wraps every persistent mutation. It may perform
// the mutation itself (fully or partially) and/or panic to simulate a
// kill -9. Production code never sets it.
var testHook func(op hookOp, perform func() error) error

// testNoFsync disables fsync calls (used by the crash test for speed; kill -9
// does not lose written data, only power loss would, which is out of scope).
var testNoFsync bool

// mutate runs one persistent mutation, routing it through testHook if set.
func mutate(op hookOp, perform func() error) error {
	if testHook != nil {
		return testHook(op, perform)
	}
	return perform()
}

// randID returns a random hex identifier.
func randID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

// writeFileAtomic writes data to a fresh temporary file inside tmpDir,
// fsyncs it, renames it onto path, and fsyncs the target directory.
func writeFileAtomic(tmpDir, path string, data []byte) error {
	tmp := filepath.Join(tmpDir, "w-"+randID())
	if err := mutate(hookOp{Kind: opWrite, Path: tmp, Data: data}, func() error {
		f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		if _, err := f.Write(data); err != nil {
			f.Close()
			return err
		}
		if !testNoFsync {
			if err := f.Sync(); err != nil {
				f.Close()
				return err
			}
		}
		return f.Close()
	}); err != nil {
		return err
	}
	if err := mutate(hookOp{Kind: opRename, Path: tmp, Path2: path}, func() error {
		return os.Rename(tmp, path)
	}); err != nil {
		return err
	}
	return fsyncDir(filepath.Dir(path))
}

// deleteFile removes path (already missing is OK) and fsyncs the parent dir.
func deleteFile(path string) error {
	if err := mutate(hookOp{Kind: opDelete, Path: path}, func() error {
		err := os.Remove(path)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}); err != nil {
		return err
	}
	return fsyncDir(filepath.Dir(path))
}

// fsyncDir fsyncs a directory so that rename/delete effects are durable.
func fsyncDir(dir string) error {
	if testNoFsync {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
