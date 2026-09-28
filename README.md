# vault

Encrypted file vault library in Go, standard library only. All data lives in a
caller-provided local directory; the 32-byte root secret is supplied to `Open`
and never touches disk.

## Design

On-disk layout:

```
<dir>/kek                            current KEK, wrapped by the root secret
<dir>/rotate.journal                 rotation journal (only while rotating)
<dir>/files/<sha256(name)>/<n>.bin   ciphertext: per-version DEK, AES-256-GCM
<dir>/files/<sha256(name)>/<n>.meta  JSON: version, size, plaintext SHA-256,
                                     upload time, KEK generation, wrapped DEK
```

- Each version gets a random DEK; the DEK is wrapped by the current KEK and
  stored in the version's metadata. `RotateKey` therefore only rewrites
  metadata (I/O grows with version count, never with ciphertext bytes).
- Every file is written via tmp + rename + dir sync, so a `kill -9` can never
  leave a half-written file at its final name. Leftover `*.tmp` files are
  removed by the next `Open`.
- `Put` commits at the meta rename, then evicts the oldest version. A crash
  in between leaves 26 versions on disk; the next `Open` finishes the
  eviction. Orphan `.bin` (interrupted Put) and orphan `.meta` (interrupted
  eviction) are cleaned up unambiguously.
- `RotateKey` writes a journal first, rewraps every version's DEK, atomically
  replaces the `kek` file, then deletes the journal. `Open` resumes any
  interrupted rotation from the journal.
- Unknown files anywhere in the tree are treated as corruption, never
  silently ignored.

## API

```go
v, err := vault.Open(dir, rootSecret, quotaBytes) // 32-byte rootSecret
ver, err := v.Put(name, data)                     // names: any 1..4096 bytes
data, err := v.Get(name, ver)
infos, err := v.Versions(name)
err = v.RotateKey()
usage := v.Usage()
```

## Tests

`go test ./...` runs functional tests plus crash tests that enumerate every
persistence write point of `RotateKey` (40 files x 4 versions) and of an
evicting `Put`, interrupting before, after, and halfway through each one, then
verify all invariants after reopening.
