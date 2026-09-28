package vault

import "os"

// fsys abstracts all filesystem persistence so crash tests can inject faults.
// Every mutating method is a single persistence write point.
type fsys interface {
	MkdirAll(dir string) error
	ReadDir(dir string) ([]string, error)
	ReadFile(name string) ([]byte, error)
	WriteFile(name string, data []byte) error
	Rename(oldname, newname string) error
	Remove(name string) error
	SyncDir(dir string) error
}

// osFS is the production fsys backed by the operating system.
type osFS struct{}

func (osFS) MkdirAll(dir string) error { return os.MkdirAll(dir, 0o755) }

func (osFS) ReadDir(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names, nil
}

func (osFS) ReadFile(name string) ([]byte, error) { return os.ReadFile(name) }

func (osFS) WriteFile(name string, data []byte) error {
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func (osFS) Rename(oldname, newname string) error { return os.Rename(oldname, newname) }

func (osFS) Remove(name string) error { return os.Remove(name) }

func (osFS) SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
