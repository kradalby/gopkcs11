//go:build linux

package pkcs11

import (
	"encoding/binary"
	"unsafe"
)

// GCMParams holds parameters for CKM_AES_GCM.
// The caller must call Free() after the encrypt/decrypt operation to release
// resources. Do NOT free before reading the IV (which may be written back by
// the HSM during encryption).
type GCMParams struct {
	iv      []byte
	aad     []byte
	tagSize int
	// params is the C-layout struct for CK_GCM_PARAMS:
	//   pIv          unsafe.Pointer (8 bytes)
	//   ulIvLen      CK_ULONG (8 bytes)
	//   ulIvBits     CK_ULONG (8 bytes)
	//   pAAD         unsafe.Pointer (8 bytes)
	//   ulAADLen     CK_ULONG (8 bytes)
	//   ulTagBits    CK_ULONG (8 bytes)
	params [48]byte
}

// NewGCMParams creates GCM parameters.
func NewGCMParams(iv, aad []byte, tagSize int) *GCMParams {
	g := &GCMParams{
		iv:      iv,
		aad:     aad,
		tagSize: tagSize,
	}
	return g
}

// IV returns the IV, possibly updated by the HSM after encryption.
func (g *GCMParams) IV() []byte {
	return g.iv
}

// Free releases resources held by GCMParams.
func (g *GCMParams) Free() {
	// No C allocations to free in the purego implementation.
}

func (g *GCMParams) marshal() []byte {
	ptrSize := unsafe.Sizeof(uintptr(0))
	if ptrSize != 8 {
		panic("pkcs11: GCMParams only supports 64-bit platforms")
	}
	var b [48]byte
	if len(g.iv) > 0 {
		binary.LittleEndian.PutUint64(b[0:8], uint64(uintptr(unsafe.Pointer(&g.iv[0]))))
	}
	binary.LittleEndian.PutUint64(b[8:16], uint64(len(g.iv)))
	binary.LittleEndian.PutUint64(b[16:24], uint64(len(g.iv)*8))
	if len(g.aad) > 0 {
		binary.LittleEndian.PutUint64(b[24:32], uint64(uintptr(unsafe.Pointer(&g.aad[0]))))
	}
	binary.LittleEndian.PutUint64(b[32:40], uint64(len(g.aad)))
	binary.LittleEndian.PutUint64(b[40:48], uint64(g.tagSize))
	copy(g.params[:], b[:])
	return g.params[:]
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

func (o *OAEPParams) marshal() []byte {
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
	if len(o.SourceData) > 0 {
		binary.LittleEndian.PutUint64(b[24:32], uint64(uintptr(unsafe.Pointer(&o.SourceData[0]))))
	}
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

func (e *ECDH1DeriveParams) marshal() []byte {
	// CK_ECDH1_DERIVE_PARAMS layout:
	//   kdf                CK_EC_KDF_TYPE (8 bytes)
	//   ulSharedDataLen    CK_ULONG (8 bytes)
	//   pSharedData        CK_BYTE_PTR (8 bytes)
	//   ulPublicDataLen    CK_ULONG (8 bytes)
	//   pPublicData        CK_BYTE_PTR (8 bytes)
	b := make([]byte, 40)
	binary.LittleEndian.PutUint64(b[0:8], uint64(e.KDF))
	binary.LittleEndian.PutUint64(b[8:16], uint64(len(e.SharedData)))
	if len(e.SharedData) > 0 {
		binary.LittleEndian.PutUint64(b[16:24], uint64(uintptr(unsafe.Pointer(&e.SharedData[0]))))
	}
	binary.LittleEndian.PutUint64(b[24:32], uint64(len(e.PublicKeyData)))
	if len(e.PublicKeyData) > 0 {
		binary.LittleEndian.PutUint64(b[32:40], uint64(uintptr(unsafe.Pointer(&e.PublicKeyData[0]))))
	}
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
