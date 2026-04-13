//go:build tpm2

// TPM2 integration tests for the signer package.
//
// These require the same setup as the root package tpm2 tests:
// a tpm2-pkcs11 token with RSA and EC keys. See pkcs11_tpm2_test.go
// for the full prerequisites.
//
// Run:
//
//	CGO_ENABLED=0 go test -tags tpm2 -v ./signer/
package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"os"
	"testing"

	pkcs11 "github.com/kradalby/gopkcs11"
)

func tpm2Lib(t *testing.T) string {
	t.Helper()
	lib := os.Getenv("TPM2_PKCS11_LIB")
	if lib == "" {
		t.Skip("TPM2_PKCS11_LIB not set")
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

// tpm2ReadPublicKey opens a session to the TPM token and reads the public key
// material for the first key of the given type.
func tpm2ReadPublicKey(t *testing.T, keyType uint) crypto.PublicKey {
	t.Helper()

	lib := tpm2Lib(t)
	label := tpm2TokenLabel()
	pin := tpm2PIN()

	// Clear any cached module from prior tests.
	modulesMu.Lock()
	delete(modules, lib)
	modulesMu.Unlock()

	p := pkcs11.New(lib)
	if p == nil {
		t.Fatalf("failed to load %s", lib)
	}
	if err := p.Initialize(); err != nil {
		if err.Error() != "CKR_CRYPTOKI_ALREADY_INITIALIZED" {
			t.Fatalf("Initialize: %v", err)
		}
	}
	defer func() {
		modulesMu.Lock()
		delete(modules, lib)
		modulesMu.Unlock()
		p.Finalize()
		p.Destroy()
	}()

	slots, err := p.GetSlotList(true)
	if err != nil {
		t.Fatalf("GetSlotList: %v", err)
	}

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
		t.Skipf("token %q not found", label)
	}

	session, err := p.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer p.CloseSession(session)

	if err := p.Login(session, pkcs11.CKU_USER, pin); err != nil {
		t.Fatalf("Login: %v", err)
	}
	defer p.Logout(session)

	// Find private key to get its CKA_ID.
	if err := p.FindObjectsInit(session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, keyType),
	}); err != nil {
		t.Fatalf("FindObjectsInit: %v", err)
	}
	objs, _, err := p.FindObjects(session, 1)
	if err != nil {
		t.Fatalf("FindObjects: %v", err)
	}
	p.FindObjectsFinal(session)
	if len(objs) == 0 {
		name := "RSA"
		if keyType == pkcs11.CKK_EC {
			name = "EC"
		}
		t.Skipf("no %s key on TPM token", name)
	}

	idAttrs, err := p.GetAttributeValue(session, objs[0], []*pkcs11.Attribute{
		{Type: pkcs11.CKA_ID},
	})
	if err != nil {
		t.Fatalf("GetAttributeValue: %v", err)
	}

	// Find matching public key.
	if err := p.FindObjectsInit(session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, keyType),
		pkcs11.NewAttribute(pkcs11.CKA_ID, idAttrs[0].Value),
	}); err != nil {
		t.Fatalf("FindObjectsInit pub: %v", err)
	}
	pubObjs, _, err := p.FindObjects(session, 1)
	if err != nil {
		t.Fatalf("FindObjects pub: %v", err)
	}
	p.FindObjectsFinal(session)
	if len(pubObjs) == 0 {
		t.Fatal("no matching public key")
	}

	switch keyType {
	case pkcs11.CKK_RSA:
		attrs, err := p.GetAttributeValue(session, pubObjs[0], []*pkcs11.Attribute{
			{Type: pkcs11.CKA_MODULUS},
			{Type: pkcs11.CKA_PUBLIC_EXPONENT},
		})
		if err != nil {
			t.Fatalf("GetAttributeValue RSA: %v", err)
		}
		n := new(big.Int).SetBytes(attrs[0].Value)
		e := new(big.Int).SetBytes(attrs[1].Value)
		return &rsa.PublicKey{N: n, E: int(e.Int64())}

	case pkcs11.CKK_EC:
		attrs, err := p.GetAttributeValue(session, pubObjs[0], []*pkcs11.Attribute{
			{Type: pkcs11.CKA_EC_POINT},
		})
		if err != nil {
			t.Fatalf("GetAttributeValue EC: %v", err)
		}
		var ecPoint []byte
		if _, err := asn1.Unmarshal(attrs[0].Value, &ecPoint); err != nil {
			t.Fatalf("unmarshal EC_POINT: %v", err)
		}
		x, y := elliptic.Unmarshal(elliptic.P256(), ecPoint) //nolint:staticcheck // needed for PKCS#11 EC point format
		if x == nil {
			t.Skip("EC point not P-256, skipping")
		}
		return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}

	default:
		t.Fatalf("unsupported key type: %d", keyType)
		return nil
	}
}

func TestTPM2SignerRSA(t *testing.T) {
	lib := tpm2Lib(t)
	pubKey := tpm2ReadPublicKey(t, pkcs11.CKK_RSA)

	k, err := New(lib, tpm2TokenLabel(), tpm2PIN(), pubKey)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(k.Destroy)

	msg := []byte("TPM2 signer RSA test")
	hash := sha256.Sum256(msg)
	sig, err := k.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	rsaPub := pubKey.(*rsa.PublicKey)
	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hash[:], sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	t.Logf("RSA PKCS#1v1.5 signature verified (%d bytes)", len(sig))
}

func TestTPM2SignerRSAPSS(t *testing.T) {
	lib := tpm2Lib(t)
	pubKey := tpm2ReadPublicKey(t, pkcs11.CKK_RSA)

	k, err := New(lib, tpm2TokenLabel(), tpm2PIN(), pubKey)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(k.Destroy)

	msg := []byte("TPM2 signer RSA-PSS test")
	hash := sha256.Sum256(msg)
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	sig, err := k.Sign(rand.Reader, hash[:], opts)
	if err != nil {
		t.Fatalf("Sign PSS: %v", err)
	}

	rsaPub := pubKey.(*rsa.PublicKey)
	if err := rsa.VerifyPSS(rsaPub, crypto.SHA256, hash[:], sig, opts); err != nil {
		t.Fatalf("VerifyPSS: %v", err)
	}
	t.Logf("RSA-PSS signature verified (%d bytes)", len(sig))
}

func TestTPM2SignerECDSA(t *testing.T) {
	lib := tpm2Lib(t)
	pubKey := tpm2ReadPublicKey(t, pkcs11.CKK_EC)

	k, err := New(lib, tpm2TokenLabel(), tpm2PIN(), pubKey)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(k.Destroy)

	msg := []byte("TPM2 signer ECDSA test")
	hash := sha256.Sum256(msg)
	sig, err := k.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	ecPub := pubKey.(*ecdsa.PublicKey)
	if !ecdsa.VerifyASN1(ecPub, hash[:], sig) {
		t.Fatal("ECDSA verification failed")
	}
	t.Logf("ECDSA signature verified (%d bytes)", len(sig))
}

func TestTPM2SignerCSR(t *testing.T) {
	lib := tpm2Lib(t)
	pubKey := tpm2ReadPublicKey(t, pkcs11.CKK_RSA)

	k, err := New(lib, tpm2TokenLabel(), tpm2PIN(), pubKey)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(k.Destroy)

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature invalid: %v", err)
	}
	t.Logf("CSR signed and verified with TPM-backed key")
}
