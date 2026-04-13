# gopkcs11

A CGO-free PKCS#11 binding for Go, using [purego](https://github.com/ebitengine/purego) to load and call PKCS#11 shared libraries at runtime.

API-compatible with [miekg/pkcs11](https://github.com/miekg/pkcs11). Includes a `crypto.Signer` implementation compatible with [letsencrypt/pkcs11key](https://github.com/letsencrypt/pkcs11key).

Linux only. `CGO_ENABLED=0` always.

## Usage

```go
import pkcs11 "github.com/kradalby/gopkcs11"

p := pkcs11.New("/usr/lib/softhsm/libsofthsm2.so")
defer p.Destroy()

p.Initialize()
defer p.Finalize()

slots, _ := p.GetSlotList(true)
session, _ := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION)
p.Login(session, pkcs11.CKU_USER, "1234")

// Sign, verify, encrypt, decrypt, generate keys, etc.
// Same API as miekg/pkcs11.
```

### crypto.Signer

```go
import "github.com/kradalby/gopkcs11/signer"

k, err := signer.New("/path/to/pkcs11.so", "token-label", "pin", publicKey)
defer k.Destroy()

// Use anywhere a crypto.Signer is accepted.
sig, err := k.Sign(rand.Reader, hash[:], crypto.SHA256)

// Or use a pool for concurrent signing.
pool, err := signer.NewPool(4, "/path/to/pkcs11.so", "token-label", "pin", publicKey)
```

## Development

Requires [Nix](https://nixos.org/) with flakes enabled.

```bash
nix develop
```

This provides Go, SoftHSM2, tpm2-pkcs11, tpm2-tools, golangci-lint, and opensc. It also sets:

- `CGO_ENABLED=0`
- `SOFTHSM_LIB` - path to `libsofthsm2.so`
- `TPM2_PKCS11_LIB` - path to `libtpm2_pkcs11.so`

### Running tests

```bash
# All tests (SoftHSM)
go test ./...

# Verbose
go test -v ./...

# Lint
golangci-lint run ./...
```

### TPM2 integration tests

These test against a real TPM 2.0 via `tpm2-pkcs11` and are gated behind `//go:build tpm2`. They skip gracefully if the token is not found.

#### One-time setup

```bash
# Verify TPM is present
ls /dev/tpmrm0
cat /sys/class/tpm/tpm0/tpm_version_major  # should print "2"

# Initialize a tpm2-pkcs11 token
tpm2_ptool init
tpm2_ptool addtoken --pid=1 --sopin=sopin --userpin=userpin --label=test
tpm2_ptool addkey --algorithm=rsa2048 --label=test --userpin=userpin
tpm2_ptool addkey --algorithm=ecc256 --label=test --userpin=userpin
```

#### Run

```bash
go test -tags tpm2 -v ./...
```

The token label and PIN default to `test` and `userpin`. Override with:

```bash
TPM2_TOKEN_LABEL=mytoken TPM2_PIN=mypin go test -tags tpm2 -v ./...
```

### Regenerating constants

The PKCS#11 constants are generated from `pkcs11t.h`:

```bash
go run cmd/constgen/main.go
```

This produces `zconst.go` and `zerror_strings.go`.
