//go:build linux

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
	"path/filepath"
	"reflect"
	"testing"

	pkcs11 "github.com/kradalby/gopkcs11"
)

// ============================================================
// Mock context for unit tests
// ============================================================

type mockCtx struct {
	currentSearch []*pkcs11.Attribute
}

// RSA test key material.
var (
	testRSAKey    *rsa.PrivateKey
	testRSAPubKey *rsa.PublicKey
	testECKey     *ecdsa.PrivateKey
	testECPubKey  *ecdsa.PublicKey
)

func init() {
	var err error
	testRSAKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	testRSAPubKey = &testRSAKey.PublicKey

	testECKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	testECPubKey = &testECKey.PublicKey
}

const (
	mockRSAPubHandle  pkcs11.ObjectHandle  = 1
	mockRSAPrivHandle pkcs11.ObjectHandle  = 2
	mockECPubHandle   pkcs11.ObjectHandle  = 3
	mockECPrivHandle  pkcs11.ObjectHandle  = 4
	mockSessionHandle pkcs11.SessionHandle = 17
)

func (m *mockCtx) Initialize(_ ...pkcs11.InitializeOption) error { return nil }

func (m *mockCtx) GetSlotList(_ bool) ([]uint, error) {
	return []uint{7, 8, 9}, nil
}

func (m *mockCtx) GetTokenInfo(_ uint) (pkcs11.TokenInfo, error) {
	return pkcs11.TokenInfo{Label: "token label"}, nil
}

func (m *mockCtx) OpenSession(_, _ uint) (pkcs11.SessionHandle, error) {
	return mockSessionHandle, nil
}

func (m *mockCtx) CloseSession(_ pkcs11.SessionHandle) error { return nil }

func (m *mockCtx) Login(_ pkcs11.SessionHandle, _ uint, _ string) error { return nil }

func (m *mockCtx) Logout(_ pkcs11.SessionHandle) error { return nil }

func (m *mockCtx) FindObjectsInit(_ pkcs11.SessionHandle, temp []*pkcs11.Attribute) error {
	m.currentSearch = temp
	return nil
}

func (m *mockCtx) FindObjects(_ pkcs11.SessionHandle, _ int) ([]pkcs11.ObjectHandle, bool, error) {
	// Match templates to known objects.
	rsaPubTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, testRSAPubKey.N.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, big.NewInt(int64(testRSAPubKey.E)).Bytes()),
	}
	rsaPrivTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte("rsa-key-id")),
	}

	ecParams, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})
	ecPoint := elliptic.Marshal(testECPubKey.Curve, testECPubKey.X, testECPubKey.Y) //nolint:staticcheck // PKCS#11 requires uncompressed EC point format
	ecPointDER, _ := asn1.Marshal(ecPoint)
	ecPubTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, ecPointDER),
	}
	ecPrivTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte("ec-key-id")),
	}

	if matchTemplate(m.currentSearch, rsaPubTemplate) {
		return []pkcs11.ObjectHandle{mockRSAPubHandle}, true, nil
	}
	if matchTemplate(m.currentSearch, rsaPrivTemplate) {
		return []pkcs11.ObjectHandle{mockRSAPrivHandle}, true, nil
	}
	if matchTemplate(m.currentSearch, ecPubTemplate) {
		return []pkcs11.ObjectHandle{mockECPubHandle}, true, nil
	}
	if matchTemplate(m.currentSearch, ecPrivTemplate) {
		return []pkcs11.ObjectHandle{mockECPrivHandle}, true, nil
	}
	return nil, false, nil
}

func (m *mockCtx) FindObjectsFinal(_ pkcs11.SessionHandle) error { return nil }

func (m *mockCtx) GetAttributeValue(_ pkcs11.SessionHandle, o pkcs11.ObjectHandle, a []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	result := make([]*pkcs11.Attribute, len(a))
	for i, attr := range a {
		switch attr.Type {
		case pkcs11.CKA_ID:
			switch o {
			case mockRSAPubHandle:
				result[i] = pkcs11.NewAttribute(pkcs11.CKA_ID, []byte("rsa-key-id"))
			case mockECPubHandle:
				result[i] = pkcs11.NewAttribute(pkcs11.CKA_ID, []byte("ec-key-id"))
			default:
				result[i] = &pkcs11.Attribute{Type: pkcs11.CKA_ID}
			}
		case pkcs11.CKA_ALWAYS_AUTHENTICATE:
			result[i] = pkcs11.NewAttribute(pkcs11.CKA_ALWAYS_AUTHENTICATE, false)
		default:
			result[i] = &pkcs11.Attribute{Type: attr.Type}
		}
	}
	return result, nil
}

func (m *mockCtx) SignInit(_ pkcs11.SessionHandle, _ []*pkcs11.Mechanism, _ pkcs11.ObjectHandle) error {
	return nil
}

func (m *mockCtx) Sign(_ pkcs11.SessionHandle, message []byte) ([]byte, error) {
	// Return the message unchanged (identity function for testing).
	return message, nil
}

func matchTemplate(search, expected []*pkcs11.Attribute) bool {
	if len(search) != len(expected) {
		return false
	}
	for i := range search {
		if search[i].Type != expected[i].Type {
			return false
		}
		if !reflect.DeepEqual(search[i].Value, expected[i].Value) {
			return false
		}
	}
	return true
}

func setupMock(t *testing.T, pubKey crypto.PublicKey) *Key {
	t.Helper()
	k := &Key{
		module:     &mockCtx{},
		tokenLabel: "token label",
		pin:        "unused",
		publicKey:  pubKey,
	}
	if err := k.setup(); err != nil {
		t.Fatalf("setup: %v", err)
	}
	return k
}

// ============================================================
// Mock-based unit tests (ported from pkcs11key)
// ============================================================

func TestSignPKCS1(t *testing.T) {
	k := setupMock(t, testRSAPubKey)

	hash := sha256.Sum256([]byte("test"))
	sig, err := k.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// The mock returns the input unchanged. For PKCS#1v1.5,
	// the input is DigestInfo + hash.
	prefix, _ := digestInfoPrefix(crypto.SHA256)
	expected := make([]byte, len(prefix)+len(hash))
	copy(expected, prefix)
	copy(expected[len(prefix):], hash[:])

	if !reflect.DeepEqual(sig, expected) {
		t.Errorf("Signature mismatch")
	}
}

func TestSignPSS(t *testing.T) {
	k := setupMock(t, testRSAPubKey)

	hash := sha256.Sum256([]byte("test"))
	opts := &rsa.PSSOptions{
		SaltLength: 32,
		Hash:       crypto.SHA256,
	}
	sig, err := k.Sign(rand.Reader, hash[:], opts)
	if err != nil {
		t.Fatalf("Sign PSS: %v", err)
	}

	// The mock returns the raw hash (PSS doesn't prepend DigestInfo).
	if !reflect.DeepEqual(sig, hash[:]) {
		t.Errorf("PSS signature should be raw hash, got %d bytes", len(sig))
	}
}

func TestSignECDSAMock(t *testing.T) {
	k := setupMock(t, testECPubKey)

	hash := sha256.Sum256([]byte("test"))
	sig, err := k.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign ECDSA: %v", err)
	}

	// The mock returns the input as-is, then Sign() calls pkcs11ToRFC5480.
	// The hash is 32 bytes, which gets split into two 16-byte halves for r||s.
	if len(sig) == 0 {
		t.Error("Empty signature")
	}

	// Verify it's valid ASN.1.
	type ecdsaSig struct{ R, S *big.Int }
	var parsed ecdsaSig
	_, err = asn1.Unmarshal(sig, &parsed)
	if err != nil {
		t.Fatalf("Failed to unmarshal ECDSA signature: %v", err)
	}
}

func TestDestroyThenSign(t *testing.T) {
	k := setupMock(t, testRSAPubKey)
	k.Destroy()

	hash := sha256.Sum256([]byte("test"))
	_, err := k.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err == nil {
		t.Error("Expected error signing after Destroy")
	}
}

func TestInitializeBadModule(t *testing.T) {
	_, err := initialize("/dev/null")
	if err == nil {
		t.Error("Expected error loading /dev/null")
	}
}

func TestPKCS11ToRFC5480Signature(t *testing.T) {
	// Test round-trip: create r||s, convert to DER, parse back.
	r := big.NewInt(12345678)
	s := big.NewInt(87654321)

	// Pad to equal length.
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	maxLen := len(rBytes)
	if len(sBytes) > maxLen {
		maxLen = len(sBytes)
	}
	padded := make([]byte, maxLen*2)
	copy(padded[maxLen-len(rBytes):maxLen], rBytes)
	copy(padded[2*maxLen-len(sBytes):], sBytes)

	der, err := pkcs11ToRFC5480(padded)
	if err != nil {
		t.Fatalf("pkcs11ToRFC5480: %v", err)
	}

	type ecdsaSig struct{ R, S *big.Int }
	var parsed ecdsaSig
	_, err = asn1.Unmarshal(der, &parsed)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if parsed.R.Cmp(r) != 0 || parsed.S.Cmp(s) != 0 {
		t.Errorf("R=%s S=%s, want R=%s S=%s", parsed.R, parsed.S, r, s)
	}
}

// mockCtxFailsAlwaysAuthenticate returns CKR_ATTRIBUTE_TYPE_INVALID for
// CKA_ALWAYS_AUTHENTICATE.
type mockCtxFailsAlwaysAuthenticate struct {
	mockCtx
}

func (m *mockCtxFailsAlwaysAuthenticate) GetAttributeValue(sh pkcs11.SessionHandle, o pkcs11.ObjectHandle, a []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	for _, attr := range a {
		if attr.Type == pkcs11.CKA_ALWAYS_AUTHENTICATE {
			return nil, pkcs11.Error(pkcs11.CKR_ATTRIBUTE_TYPE_INVALID)
		}
	}
	return m.mockCtx.GetAttributeValue(sh, o, a)
}

func TestAttributeTypeInvalid(t *testing.T) {
	k := &Key{
		module:     &mockCtxFailsAlwaysAuthenticate{},
		tokenLabel: "token label",
		pin:        "unused",
		publicKey:  testRSAPubKey,
	}
	if err := k.setup(); err != nil {
		t.Fatalf("setup should succeed even without CKA_ALWAYS_AUTHENTICATE: %v", err)
	}
	if k.alwaysAuthenticate {
		t.Error("alwaysAuthenticate should be false when attribute is unsupported")
	}
}

func TestRSAPKCS1Params(t *testing.T) {
	msg := make([]byte, 32)
	mech, data, err := (&Key{publicKey: testRSAPubKey}).rsaSigningParams(msg, crypto.SHA256)
	if err != nil {
		t.Fatalf("rsaSigningParams: %v", err)
	}
	if mech[0].Mechanism != pkcs11.CKM_RSA_PKCS {
		t.Errorf("mechanism = %d, want CKM_RSA_PKCS", mech[0].Mechanism)
	}
	if mech[0].Parameter != nil {
		t.Error("PKCS#1v1.5 should have nil parameter")
	}
	prefix, _ := digestInfoPrefix(crypto.SHA256)
	if len(data) != len(prefix)+32 {
		t.Errorf("data length = %d, want %d", len(data), len(prefix)+32)
	}
}

func TestRSAPSSParams(t *testing.T) {
	msg := make([]byte, 32)
	opts := &rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256}
	mech, data, err := (&Key{publicKey: testRSAPubKey}).rsaSigningParams(msg, opts)
	if err != nil {
		t.Fatalf("rsaSigningParams: %v", err)
	}
	if mech[0].Mechanism != pkcs11.CKM_RSA_PKCS_PSS {
		t.Errorf("mechanism = %d, want CKM_RSA_PKCS_PSS", mech[0].Mechanism)
	}
	if mech[0].Parameter == nil {
		t.Error("PSS should have non-nil parameter")
	}
	if !reflect.DeepEqual(data, msg) {
		t.Error("PSS data should be raw hash")
	}
}

// ============================================================
// SoftHSM integration tests
// ============================================================

func libPath() string {
	lib := os.Getenv("SOFTHSM_LIB")
	if lib != "" {
		return lib
	}
	candidates := []string{
		"/usr/lib/softhsm/libsofthsm2.so",
		"/usr/lib64/softhsm/libsofthsm2.so",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return "/usr/lib/softhsm/libsofthsm2.so"
}

// clearModuleCache finalizes any cached module and clears the cache.
func clearModuleCache(t *testing.T) {
	t.Helper()
	lib := libPath()
	modulesMu.Lock()
	if m, ok := modules[lib]; ok {
		// The cached module is a *pkcs11.Ctx. Finalize it.
		if p, ok := m.(*pkcs11.Ctx); ok {
			p.Finalize()
			p.Destroy()
		}
		delete(modules, lib)
	}
	modulesMu.Unlock()
}

// setupSoftHSM creates a fresh SoftHSM token for integration testing.
// It returns the token label and user PIN.
func setupSoftHSM(t *testing.T) (string, string) {
	t.Helper()

	// Ensure no lingering module from a previous test.
	clearModuleCache(t)

	tokenDir := filepath.Join(t.TempDir(), "tokens")
	if err := os.MkdirAll(tokenDir, 0o755); err != nil {
		t.Fatal(err)
	}
	confPath := filepath.Join(t.TempDir(), "softhsm2.conf")
	conf := "directories.tokendir = " + tokenDir + "\nobjectstore.backend = file\nlog.level = INFO\nslots.removable = false\n"
	if err := os.WriteFile(confPath, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOFTHSM2_CONF", confPath)

	// Ensure cleanup after test.
	t.Cleanup(func() { clearModuleCache(t) })

	lib := libPath()

	p := pkcs11.New(lib)
	if p == nil {
		t.Skipf("Could not load %s", lib)
	}
	if err := p.Initialize(); err != nil {
		t.Fatal(err)
	}

	slots, err := p.GetSlotList(false)
	if err != nil || len(slots) == 0 {
		p.Finalize()
		p.Destroy()
		t.Fatal("No slots available")
	}

	soPin := "1234"
	userPin := "5678"
	tokenLabel := "signertest"

	if err := p.InitToken(slots[0], soPin, tokenLabel); err != nil {
		p.Finalize()
		p.Destroy()
		t.Fatalf("InitToken: %v", err)
	}

	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		p.Finalize()
		p.Destroy()
		t.Fatal(err)
	}
	if err := p.Login(session, pkcs11.CKU_SO, soPin); err != nil {
		p.Finalize()
		p.Destroy()
		t.Fatal(err)
	}
	if err := p.InitPIN(session, userPin); err != nil {
		p.Finalize()
		p.Destroy()
		t.Fatal(err)
	}
	p.Logout(session)
	p.CloseSession(session)

	// Finalize + Destroy so the signer's initialize() can start fresh.
	p.Finalize()
	p.Destroy()

	return tokenLabel, userPin
}

func generateRSAKeyAndGetPublic(t *testing.T, lib, tokenLabel, pin string) *rsa.PublicKey {
	t.Helper()

	p := pkcs11.New(lib)
	if p == nil {
		t.Fatalf("Could not load %s", lib)
	}
	if err := p.Initialize(); err != nil {
		// May already be initialized from setupSoftHSM's finalize/re-init cycle.
		if err.Error() != "CKR_CRYPTOKI_ALREADY_INITIALIZED" {
			t.Fatalf("Initialize: %v", err)
		}
	}
	defer func() {
		p.Finalize()
		p.Destroy()
		clearModuleCache(t)
	}()

	slots, err := p.GetSlotList(true)
	if err != nil || len(slots) == 0 {
		t.Fatal("No slots")
	}

	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Login(session, pkcs11.CKU_USER, pin); err != nil {
		t.Fatal(err)
	}
	defer func() { p.Logout(session); p.CloseSession(session) }()

	pubTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 2048),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "signerRSA"),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte("signer-rsa-id")),
	}
	privTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "signerRSA"),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte("signer-rsa-id")),
	}

	pub, _, err := p.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		pubTemplate, privTemplate)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	attrs, err := p.GetAttributeValue(session, pub, []*pkcs11.Attribute{
		{Type: pkcs11.CKA_MODULUS},
		{Type: pkcs11.CKA_PUBLIC_EXPONENT},
	})
	if err != nil {
		t.Fatal(err)
	}

	n := new(big.Int).SetBytes(attrs[0].Value)
	e := new(big.Int).SetBytes(attrs[1].Value)

	return &rsa.PublicKey{N: n, E: int(e.Int64())}
}

func TestIntegrationRSASignVerify(t *testing.T) {
	tokenLabel, pin := setupSoftHSM(t)
	lib := libPath()

	pubKey := generateRSAKeyAndGetPublic(t, lib, tokenLabel, pin)

	k, err := New(lib, tokenLabel, pin, pubKey)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(k.Destroy)

	// Sign with SHA-256 PKCS#1v1.5.
	msg := []byte("integration test message")
	hash := sha256.Sum256(msg)
	sig, err := k.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Verify using Go's standard crypto.
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func generateECKeyAndGetPublic(t *testing.T, lib, tokenLabel, pin string) *ecdsa.PublicKey {
	t.Helper()

	p := pkcs11.New(lib)
	if p == nil {
		t.Fatalf("Could not load %s", lib)
	}
	if err := p.Initialize(); err != nil {
		if err.Error() != "CKR_CRYPTOKI_ALREADY_INITIALIZED" {
			t.Fatalf("Initialize: %v", err)
		}
	}
	defer func() {
		p.Finalize()
		p.Destroy()
		clearModuleCache(t)
	}()

	slots, err := p.GetSlotList(true)
	if err != nil || len(slots) == 0 {
		t.Fatal("No slots")
	}

	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Login(session, pkcs11.CKU_USER, pin); err != nil {
		t.Fatal(err)
	}
	defer func() { p.Logout(session); p.CloseSession(session) }()

	ecParams, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})
	pubTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "signerEC"),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte("signer-ec-id")),
	}
	privTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "signerEC"),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte("signer-ec-id")),
	}

	pub, _, err := p.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
		pubTemplate, privTemplate)
	if err != nil {
		t.Fatalf("GenerateKeyPair EC: %v", err)
	}

	attrs, err := p.GetAttributeValue(session, pub, []*pkcs11.Attribute{
		{Type: pkcs11.CKA_EC_POINT},
	})
	if err != nil {
		t.Fatal(err)
	}

	// EC_POINT is DER-encoded OCTET STRING wrapping the uncompressed point.
	var ecPoint []byte
	if _, err := asn1.Unmarshal(attrs[0].Value, &ecPoint); err != nil {
		t.Fatal(err)
	}

	x, y := elliptic.Unmarshal(elliptic.P256(), ecPoint) //nolint:staticcheck // PKCS#11 returns uncompressed EC point format
	if x == nil {
		t.Fatal("Failed to unmarshal EC point")
	}

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}
}

func TestIntegrationECDSASignVerify(t *testing.T) {
	tokenLabel, pin := setupSoftHSM(t)
	lib := libPath()

	pubKey := generateECKeyAndGetPublic(t, lib, tokenLabel, pin)

	k, err := New(lib, tokenLabel, pin, pubKey)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(k.Destroy)

	msg := []byte("ECDSA integration test")
	hash := sha256.Sum256(msg)
	sig, err := k.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	ok := ecdsa.VerifyASN1(pubKey, hash[:], sig)
	if !ok {
		t.Fatal("ECDSA signature verification failed")
	}
}

func TestNewWithWrongPin(t *testing.T) {
	tokenLabel, _ := setupSoftHSM(t)
	lib := libPath()

	pubKey := &rsa.PublicKey{N: big.NewInt(1), E: 65537}

	_, err := New(lib, tokenLabel, "wrong-pin", pubKey)
	if err == nil {
		t.Error("Expected error with wrong PIN")
	}
}

func TestNewWithWrongLabel(t *testing.T) {
	setupSoftHSM(t)
	lib := libPath()

	pubKey := &rsa.PublicKey{N: big.NewInt(1), E: 65537}

	_, err := New(lib, "nonexistent-token", "1234", pubKey)
	if err == nil {
		t.Error("Expected error with wrong token label")
	}
}

func TestPublicKeyInterface(t *testing.T) {
	k := setupMock(t, testRSAPubKey)
	pub := k.Public()

	switch pub.(type) {
	case *rsa.PublicKey:
		// ok
	default:
		t.Errorf("Public() returned %T, want *rsa.PublicKey", pub)
	}
}

func TestKeyImplementsCryptoSigner(t *testing.T) {
	k := setupMock(t, testRSAPubKey)
	var _ crypto.Signer = k
}

func TestPoolImplementsCryptoSigner(t *testing.T) {
	// Verify at compile time that *Pool implements crypto.Signer.
	var _ crypto.Signer = (*Pool)(nil)
}

// Test that x509.CreateCertificateRequest works with our signer.
func TestIntegrationCSR(t *testing.T) {
	tokenLabel, pin := setupSoftHSM(t)
	lib := libPath()

	pubKey := generateRSAKeyAndGetPublic(t, lib, tokenLabel, pin)

	k, err := New(lib, tokenLabel, pin, pubKey)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(k.Destroy)

	csrTemplate := &x509.CertificateRequest{}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, k)
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
}
