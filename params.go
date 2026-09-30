//go:build linux

package pkcs11

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

// GCMParams holds parameters for CKM_AES_GCM.
// Some modules write a generated IV back, possibly not until the operation
// ends; IV returns it. Each operation's parameters live outside the Go heap
// until Free: call it once no operation using g is active and its IV is
// read, or that memory leaks.
type GCMParams struct {
	iv      []byte
	aad     []byte
	tagSize int

	mu sync.Mutex
	// ops holds each operation's memory, newest last, so operations never
	// share what the module writes. The module may keep pointers into it
	// until the operation ends, which only the caller knows. Pinning Go
	// memory that long would crash the process if g were dropped without
	// Free, so it is mmap'd instead.
	ops []gcmOp
}

type gcmOp struct {
	// mem is the whole mapping: CK_GCM_PARAMS, then IV, then AAD.
	mem, iv []byte
}

// Swapped by tests to watch operation memory come and go.
var mmap, munmap = syscall.Mmap, syscall.Munmap

// NewGCMParams creates GCM parameters.
func NewGCMParams(iv, aad []byte, tagSize int) *GCMParams {
	return &GCMParams{
		iv:      bytes.Clone(iv),
		aad:     aad,
		tagSize: tagSize,
	}
}

// IV returns a copy of the newest operation's IV, as the module left it.
// With operations sharing g concurrently, newest is arbitrary: give each
// operation its own GCMParams to read back its IV.
func (g *GCMParams) IV() []byte {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.ops) == 0 {
		return bytes.Clone(g.iv)
	}
	return bytes.Clone(g.ops[len(g.ops)-1].iv)
}

// Free releases the native memory each operation using g mapped; without
// it that memory leaks. No operation using g may be active.
func (g *GCMParams) Free() {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, op := range g.ops {
		// Only fails for memory not from mmap.
		_ = munmap(op.mem)
	}
	g.ops = nil
}

// marshal builds one operation's CK_GCM_PARAMS, IV and AAD in memory that
// stays valid until Free, not just for the call.
func (g *GCMParams) marshal() ([]byte, error) {
	const paramsLen = 48
	if unsafe.Sizeof(uintptr(0)) != 8 {
		panic("pkcs11: GCMParams only supports 64-bit platforms")
	}
	mem, err := mmap(-1, 0, paramsLen+len(g.iv)+len(g.aad),
		syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS)
	if err != nil {
		return nil, Error(CKR_HOST_MEMORY)
	}
	b := mem[:paramsLen]
	iv := mem[paramsLen : paramsLen+len(g.iv)]
	aad := mem[paramsLen+len(g.iv):]
	copy(iv, g.iv)
	copy(aad, g.aad)
	// CK_GCM_PARAMS layout:
	//   pIv          CK_BYTE_PTR (8 bytes)
	//   ulIvLen      CK_ULONG (8 bytes)
	//   ulIvBits     CK_ULONG (8 bytes)
	//   pAAD         CK_BYTE_PTR (8 bytes)
	//   ulAADLen     CK_ULONG (8 bytes)
	//   ulTagBits    CK_ULONG (8 bytes)
	binary.LittleEndian.PutUint64(b[0:8], uint64(addr(iv)))
	binary.LittleEndian.PutUint64(b[8:16], uint64(len(iv)))
	binary.LittleEndian.PutUint64(b[16:24], uint64(len(iv)*8))
	binary.LittleEndian.PutUint64(b[24:32], uint64(addr(aad)))
	binary.LittleEndian.PutUint64(b[32:40], uint64(len(aad)))
	binary.LittleEndian.PutUint64(b[40:48], uint64(g.tagSize))

	g.mu.Lock()
	g.ops = append(g.ops, gcmOp{mem: mem, iv: iv})
	g.mu.Unlock()
	return b, nil
}

// addr returns the address of non-Go memory b, or 0 (NULL) when b is empty.
func addr(b []byte) uintptr {
	if len(b) == 0 {
		return 0
	}
	return uintptr(unsafe.Pointer(&b[0]))
}

// OAEPParams holds parameters for CKM_RSA_PKCS_OAEP.
type OAEPParams struct {
	HashAlg    uint
	MGF        uint
	SourceType uint
	SourceData []byte
}

// NewOAEPParams creates OAEP parameters.
func NewOAEPParams(hashAlg, mgf, sourceType uint, sourceData []byte) *OAEPParams {
	return &OAEPParams{
		HashAlg:    hashAlg,
		MGF:        mgf,
		SourceType: sourceType,
		SourceData: sourceData,
	}
}

func (o *OAEPParams) marshal(p *runtime.Pinner) []byte {
	// CK_RSA_PKCS_OAEP_PARAMS layout:
	//   hashAlg      CK_MECHANISM_TYPE (8 bytes)
	//   mgf          CK_RSA_PKCS_MGF_TYPE (8 bytes)
	//   source       CK_RSA_PKCS_OAEP_SOURCE_TYPE (8 bytes)
	//   pSourceData  CK_VOID_PTR (8 bytes)
	//   ulSourceDataLen CK_ULONG (8 bytes)
	b := make([]byte, 40)
	binary.LittleEndian.PutUint64(b[0:8], uint64(o.HashAlg))
	binary.LittleEndian.PutUint64(b[8:16], uint64(o.MGF))
	binary.LittleEndian.PutUint64(b[16:24], uint64(o.SourceType))
	binary.LittleEndian.PutUint64(b[24:32], uint64(pinBytes(p, o.SourceData)))
	binary.LittleEndian.PutUint64(b[32:40], uint64(len(o.SourceData)))
	return b
}

// ECDH1DeriveParams holds parameters for CKM_ECDH1_DERIVE.
type ECDH1DeriveParams struct {
	KDF           uint
	SharedData    []byte
	PublicKeyData []byte
}

// NewECDH1DeriveParams creates ECDH1 key derivation parameters.
func NewECDH1DeriveParams(kdf uint, sharedData, publicKeyData []byte) *ECDH1DeriveParams {
	return &ECDH1DeriveParams{
		KDF:           kdf,
		SharedData:    sharedData,
		PublicKeyData: publicKeyData,
	}
}

func (e *ECDH1DeriveParams) marshal(p *runtime.Pinner) []byte {
	// CK_ECDH1_DERIVE_PARAMS layout:
	//   kdf                CK_EC_KDF_TYPE (8 bytes)
	//   ulSharedDataLen    CK_ULONG (8 bytes)
	//   pSharedData        CK_BYTE_PTR (8 bytes)
	//   ulPublicDataLen    CK_ULONG (8 bytes)
	//   pPublicData        CK_BYTE_PTR (8 bytes)
	b := make([]byte, 40)
	binary.LittleEndian.PutUint64(b[0:8], uint64(e.KDF))
	binary.LittleEndian.PutUint64(b[8:16], uint64(len(e.SharedData)))
	binary.LittleEndian.PutUint64(b[16:24], uint64(pinBytes(p, e.SharedData)))
	binary.LittleEndian.PutUint64(b[24:32], uint64(len(e.PublicKeyData)))
	binary.LittleEndian.PutUint64(b[32:40], uint64(pinBytes(p, e.PublicKeyData)))
	return b
}

// NewPSSParams creates RSA-PSS parameters as raw bytes matching
// CK_RSA_PKCS_PSS_PARAMS layout.
func NewPSSParams(hashAlg, mgf, saltLength uint) []byte {
	// CK_RSA_PKCS_PSS_PARAMS layout:
	//   hashAlg    CK_MECHANISM_TYPE (8 bytes)
	//   mgf        CK_RSA_PKCS_MGF_TYPE (8 bytes)
	//   saltLen    CK_ULONG (8 bytes)
	b := make([]byte, 24)
	binary.LittleEndian.PutUint64(b[0:8], uint64(hashAlg))
	binary.LittleEndian.PutUint64(b[8:16], uint64(mgf))
	binary.LittleEndian.PutUint64(b[16:24], uint64(saltLength))
	return b
}

// RSAAESKeyWrapParams holds parameters for RSA-AES key wrapping.
type RSAAESKeyWrapParams struct {
	AESKeyBits uint
	OAEPParams OAEPParams
}
