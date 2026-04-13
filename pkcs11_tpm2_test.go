//go:build tpm2

// TPM2 integration tests for the pkcs11 package.
//
// Prerequisites:
//
//  1. A real TPM 2.0 accessible at /dev/tpmrm0
//  2. tpm2-pkcs11 token initialized with a key:
//     tpm2_ptool init
//     tpm2_ptool addtoken --pid=1 --sopin=sopin --userpin=userpin --label=test
//     tpm2_ptool addkey --algorithm=rsa2048 --label=test --userpin=userpin
//     tpm2_ptool addkey --algorithm=ecc256 --label=test --userpin=userpin
//  3. Environment variables:
//     TPM2_PKCS11_LIB   - path to libtpm2_pkcs11.so (set by flake.nix)
//     TPM2_TOKEN_LABEL   - token label (default: "test")
//     TPM2_PIN           - user PIN (default: "userpin")
//
// Run:
//
//	CGO_ENABLED=0 go test -tags tpm2 -v ./...
package pkcs11

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"os"
	"testing"
)

func tpm2Lib(t *testing.T) string {
	t.Helper()
	lib := os.Getenv("TPM2_PKCS11_LIB")
	if lib == "" {
		t.Skip("TPM2_PKCS11_LIB not set")
	}
	if _, err := os.Stat(lib); err != nil {
		t.Skipf("TPM2_PKCS11_LIB %s not found: %v", lib, err)
	}
	return lib
}

func tpm2TokenLabel() string {
	if v := os.Getenv("TPM2_TOKEN_LABEL"); v != "" {
		return v
	}
	return "test"
}

func tpm2PIN() string {
	if v := os.Getenv("TPM2_PIN"); v != "" {
		return v
	}
	return "userpin"
}

func tpm2Setup(t *testing.T) (*Ctx, uint, SessionHandle) {
	t.Helper()

	lib := tpm2Lib(t)
	p := New(lib)
	if p == nil {
		t.Fatalf("failed to load TPM2 PKCS#11 module: %s", lib)
	}
	t.Cleanup(func() { p.Destroy() })

	if err := p.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	t.Cleanup(func() { p.Finalize() })

	slots, err := p.GetSlotList(true)
	if err != nil {
		t.Fatalf("GetSlotList: %v", err)
	}

	label := tpm2TokenLabel()
	var slotID uint
	found := false
	for _, s := range slots {
		ti, err := p.GetTokenInfo(s)
		if err != nil {
			continue
		}
		if ti.Label == label {
			slotID = s
			found = true
			break
		}
	}
	if !found {
		t.Skipf("TPM2 token %q not found in %d slots (create it with tpm2_ptool)", label, len(slots))
	}

	session, err := p.OpenSession(slotID, CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	t.Cleanup(func() { p.CloseSession(session) })

	if err := p.Login(session, CKU_USER, tpm2PIN()); err != nil {
		t.Fatalf("Login: %v", err)
	}
	t.Cleanup(func() { p.Logout(session) })

	return p, slotID, session
}

func TestTPM2GetInfo(t *testing.T) {
	lib := tpm2Lib(t)
	p := New(lib)
	if p == nil {
		t.Fatalf("failed to load %s", lib)
	}
	defer p.Destroy()

	if err := p.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	defer p.Finalize()

	info, err := p.GetInfo()
	if err != nil {
		t.Fatalf("GetInfo: %v", err)
	}
	t.Logf("Manufacturer: %s", info.ManufacturerID)
	t.Logf("Description:  %s", info.LibraryDescription)
	t.Logf("Version:      %d.%d", info.CryptokiVersion.Major, info.CryptokiVersion.Minor)
}

func TestTPM2TokenInfo(t *testing.T) {
	p, slotID, _ := tpm2Setup(t)

	ti, err := p.GetTokenInfo(slotID)
	if err != nil {
		t.Fatalf("GetTokenInfo: %v", err)
	}
	t.Logf("Label:   %s", ti.Label)
	t.Logf("Model:   %s", ti.Model)
	t.Logf("Serial:  %s", ti.SerialNumber)
	t.Logf("Mfr:     %s", ti.ManufacturerID)
}

func TestTPM2MechanismList(t *testing.T) {
	p, slotID, _ := tpm2Setup(t)

	mechs, err := p.GetMechanismList(slotID)
	if err != nil {
		t.Fatalf("GetMechanismList: %v", err)
	}
	t.Logf("Mechanisms: %d", len(mechs))
	for _, m := range mechs {
		t.Logf("  0x%08X", m.Mechanism)
	}
}

func TestTPM2FindKeys(t *testing.T) {
	p, _, session := tpm2Setup(t)

	for _, class := range []uint{CKO_PUBLIC_KEY, CKO_PRIVATE_KEY} {
		if err := p.FindObjectsInit(session, []*Attribute{
			NewAttribute(CKA_CLASS, class),
		}); err != nil {
			t.Fatalf("FindObjectsInit: %v", err)
		}
		objs, _, err := p.FindObjects(session, 20)
		if err != nil {
			t.Fatalf("FindObjects: %v", err)
		}
		if err := p.FindObjectsFinal(session); err != nil {
			t.Fatalf("FindObjectsFinal: %v", err)
		}
		kind := "public"
		if class == CKO_PRIVATE_KEY {
			kind = "private"
		}
		t.Logf("%s keys: %d", kind, len(objs))
		for _, obj := range objs {
			attrs, err := p.GetAttributeValue(session, obj, []*Attribute{
				{Type: CKA_KEY_TYPE},
				{Type: CKA_LABEL},
				{Type: CKA_ID},
			})
			if err != nil {
				t.Logf("  handle=%d GetAttributeValue: %v", obj, err)
				continue
			}
			t.Logf("  handle=%d type=%x label=%q id=%x", obj, attrs[0].Value, attrs[1].Value, attrs[2].Value)
		}
	}
}

func tpm2FindPrivateKey(t *testing.T, p *Ctx, session SessionHandle, keyType uint) ObjectHandle {
	t.Helper()
	if err := p.FindObjectsInit(session, []*Attribute{
		NewAttribute(CKA_CLASS, CKO_PRIVATE_KEY),
		NewAttribute(CKA_KEY_TYPE, keyType),
	}); err != nil {
		t.Fatalf("FindObjectsInit: %v", err)
	}
	objs, _, err := p.FindObjects(session, 1)
	if err != nil {
		t.Fatalf("FindObjects: %v", err)
	}
	if err := p.FindObjectsFinal(session); err != nil {
		t.Fatalf("FindObjectsFinal: %v", err)
	}
	if len(objs) == 0 {
		name := "RSA"
		if keyType == CKK_EC {
			name = "EC"
		}
		t.Skipf("no %s private key on TPM token", name)
	}
	return objs[0]
}

func tpm2FindPublicKeyByID(t *testing.T, p *Ctx, session SessionHandle, keyType uint, keyID []byte) ObjectHandle {
	t.Helper()
	if err := p.FindObjectsInit(session, []*Attribute{
		NewAttribute(CKA_CLASS, CKO_PUBLIC_KEY),
		NewAttribute(CKA_KEY_TYPE, keyType),
		NewAttribute(CKA_ID, keyID),
	}); err != nil {
		t.Fatalf("FindObjectsInit: %v", err)
	}
	objs, _, err := p.FindObjects(session, 1)
	if err != nil {
		t.Fatalf("FindObjects: %v", err)
	}
	if err := p.FindObjectsFinal(session); err != nil {
		t.Fatalf("FindObjectsFinal: %v", err)
	}
	if len(objs) == 0 {
		t.Fatal("matching public key not found")
	}
	return objs[0]
}

func TestTPM2SignRSA(t *testing.T) {
	p, _, session := tpm2Setup(t)

	priv := tpm2FindPrivateKey(t, p, session, CKK_RSA)

	// Get CKA_ID to find the matching public key.
	attrs, err := p.GetAttributeValue(session, priv, []*Attribute{{Type: CKA_ID}})
	if err != nil {
		t.Fatalf("GetAttributeValue CKA_ID: %v", err)
	}
	pub := tpm2FindPublicKeyByID(t, p, session, CKK_RSA, attrs[0].Value)

	data := []byte("hello from TPM")

	// Sign with CKM_SHA256_RSA_PKCS (hash-and-sign in one step).
	if err := p.SignInit(session, []*Mechanism{NewMechanism(CKM_SHA256_RSA_PKCS, nil)}, priv); err != nil {
		t.Fatalf("SignInit: %v", err)
	}
	sig, err := p.Sign(session, data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	t.Logf("RSA signature: %d bytes", len(sig))

	// Verify on-token.
	if err := p.VerifyInit(session, []*Mechanism{NewMechanism(CKM_SHA256_RSA_PKCS, nil)}, pub); err != nil {
		t.Fatalf("VerifyInit: %v", err)
	}
	if err := p.Verify(session, data, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// Also verify off-token with Go stdlib.
	rsaPub := extractRSAPublicKey(t, p, session, pub)
	hash := sha256.Sum256(data)
	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hash[:], sig); err != nil {
		t.Fatalf("Go stdlib rsa.VerifyPKCS1v15: %v", err)
	}
}

func TestTPM2SignECDSA(t *testing.T) {
	p, _, session := tpm2Setup(t)

	priv := tpm2FindPrivateKey(t, p, session, CKK_EC)

	attrs, err := p.GetAttributeValue(session, priv, []*Attribute{{Type: CKA_ID}})
	if err != nil {
		t.Fatalf("GetAttributeValue CKA_ID: %v", err)
	}
	pub := tpm2FindPublicKeyByID(t, p, session, CKK_EC, attrs[0].Value)

	// ECDSA signs a raw hash.
	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i)
	}

	if err := p.SignInit(session, []*Mechanism{NewMechanism(CKM_ECDSA, nil)}, priv); err != nil {
		t.Fatalf("SignInit: %v", err)
	}
	sig, err := p.Sign(session, hash)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	t.Logf("ECDSA signature: %d bytes", len(sig))

	if err := p.VerifyInit(session, []*Mechanism{NewMechanism(CKM_ECDSA, nil)}, pub); err != nil {
		t.Fatalf("VerifyInit: %v", err)
	}
	if err := p.Verify(session, hash, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// Also verify off-token with Go stdlib.
	ecPub := extractECPublicKey(t, p, session, pub)
	half := len(sig) / 2
	r := new(big.Int).SetBytes(sig[:half])
	s := new(big.Int).SetBytes(sig[half:])
	type ecdsaSig struct{ R, S *big.Int }
	derSig, err := asn1.Marshal(ecdsaSig{R: r, S: s})
	if err != nil {
		t.Fatalf("marshal ECDSA DER: %v", err)
	}
	if !ecdsa.VerifyASN1(ecPub, hash, derSig) {
		t.Fatal("Go stdlib ecdsa.VerifyASN1 failed")
	}
}

func TestTPM2GenerateRandom(t *testing.T) {
	p, _, session := tpm2Setup(t)

	rnd, err := p.GenerateRandom(session, 32)
	if err != nil {
		t.Fatalf("GenerateRandom: %v", err)
	}
	if len(rnd) != 32 {
		t.Fatalf("got %d bytes, want 32", len(rnd))
	}
	t.Logf("TPM random: %x", rnd)
}
