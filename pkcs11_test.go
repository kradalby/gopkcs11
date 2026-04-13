//go:build linux

package pkcs11

import (
	"os"
	"path/filepath"
	"testing"
)

const pin = "1234"

func libPath() string {
	lib := os.Getenv("SOFTHSM_LIB")
	if lib != "" {
		return lib
	}
	// Common paths.
	candidates := []string{
		"/usr/lib/softhsm/libsofthsm2.so",
		"/usr/lib64/softhsm/libsofthsm2.so",
		"/usr/local/lib/softhsm/libsofthsm2.so",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return "/usr/lib/softhsm/libsofthsm2.so"
}

// setenv initializes the SoftHSM environment and returns a loaded Ctx.
func setenv(t *testing.T) *Ctx {
	t.Helper()

	// Setup SoftHSM token directory and config.
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

	lib := libPath()
	p := New(lib)
	if p == nil {
		t.Fatalf("Failed to load %s", lib)
	}
	t.Cleanup(func() { p.Destroy() })
	return p
}

// initToken initializes SoftHSM, creates a token, and sets the user PIN.
func initToken(t *testing.T, p *Ctx) uint {
	t.Helper()
	if err := p.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	slots, err := p.GetSlotList(false)
	if err != nil {
		t.Fatalf("GetSlotList: %v", err)
	}
	if len(slots) == 0 {
		t.Fatal("No slots available")
	}

	slotID := slots[0]
	if err := p.InitToken(slotID, pin, "TestToken"); err != nil {
		t.Fatalf("InitToken: %v", err)
	}

	// Open SO session to set user PIN.
	session, err := p.OpenSession(slotID, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	if err := p.Login(session, CKU_SO, pin); err != nil {
		t.Fatalf("Login SO: %v", err)
	}
	if err := p.InitPIN(session, pin); err != nil {
		t.Fatalf("InitPIN: %v", err)
	}
	if err := p.Logout(session); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if err := p.CloseSession(session); err != nil {
		t.Fatalf("CloseSession: %v", err)
	}

	// Re-fetch slots now that token is present.
	slots, err = p.GetSlotList(true)
	if err != nil {
		t.Fatalf("GetSlotList: %v", err)
	}
	if len(slots) == 0 {
		t.Fatal("No slots with tokens")
	}
	return slots[0]
}

// getSession returns a logged-in RW session.
func getSession(t *testing.T, p *Ctx, slotID uint) SessionHandle {
	t.Helper()
	session, err := p.OpenSession(slotID, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	if err := p.Login(session, CKU_USER, pin); err != nil {
		t.Fatalf("Login: %v", err)
	}
	return session
}

// finishSession logs out and closes the session.
func finishSession(t *testing.T, p *Ctx, session SessionHandle) {
	t.Helper()
	if err := p.Logout(session); err != nil {
		t.Logf("Logout: %v", err)
	}
	if err := p.CloseSession(session); err != nil {
		t.Logf("CloseSession: %v", err)
	}
}

func generateRSAKeyPair(t *testing.T, p *Ctx, session SessionHandle, label string, persistent bool) (ObjectHandle, ObjectHandle) {
	t.Helper()
	pubTemplate := []*Attribute{
		NewAttribute(CKA_CLASS, CKO_PUBLIC_KEY),
		NewAttribute(CKA_KEY_TYPE, CKK_RSA),
		NewAttribute(CKA_TOKEN, persistent),
		NewAttribute(CKA_VERIFY, true),
		NewAttribute(CKA_ENCRYPT, true),
		NewAttribute(CKA_WRAP, true),
		NewAttribute(CKA_MODULUS_BITS, 2048),
		NewAttribute(CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		NewAttribute(CKA_LABEL, label),
	}
	privTemplate := []*Attribute{
		NewAttribute(CKA_CLASS, CKO_PRIVATE_KEY),
		NewAttribute(CKA_KEY_TYPE, CKK_RSA),
		NewAttribute(CKA_TOKEN, persistent),
		NewAttribute(CKA_SIGN, true),
		NewAttribute(CKA_DECRYPT, true),
		NewAttribute(CKA_UNWRAP, true),
		NewAttribute(CKA_SENSITIVE, true),
		NewAttribute(CKA_EXTRACTABLE, false),
		NewAttribute(CKA_LABEL, label),
	}

	pub, priv, err := p.GenerateKeyPair(session,
		[]*Mechanism{NewMechanism(CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		pubTemplate, privTemplate)
	if err != nil {
		t.Fatalf("GenerateKeyPair RSA: %v", err)
	}
	return pub, priv
}

func generateECKeyPair(t *testing.T, p *Ctx, session SessionHandle, label string, persistent bool) (ObjectHandle, ObjectHandle) {
	t.Helper()
	// P-256 OID: 1.2.840.10045.3.1.7
	ecParams := []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}

	pubTemplate := []*Attribute{
		NewAttribute(CKA_CLASS, CKO_PUBLIC_KEY),
		NewAttribute(CKA_KEY_TYPE, CKK_EC),
		NewAttribute(CKA_TOKEN, persistent),
		NewAttribute(CKA_VERIFY, true),
		NewAttribute(CKA_EC_PARAMS, ecParams),
		NewAttribute(CKA_LABEL, label),
	}
	privTemplate := []*Attribute{
		NewAttribute(CKA_CLASS, CKO_PRIVATE_KEY),
		NewAttribute(CKA_KEY_TYPE, CKK_EC),
		NewAttribute(CKA_TOKEN, persistent),
		NewAttribute(CKA_SIGN, true),
		NewAttribute(CKA_SENSITIVE, true),
		NewAttribute(CKA_EXTRACTABLE, false),
		NewAttribute(CKA_LABEL, label),
	}

	pub, priv, err := p.GenerateKeyPair(session,
		[]*Mechanism{NewMechanism(CKM_EC_KEY_PAIR_GEN, nil)},
		pubTemplate, privTemplate)
	if err != nil {
		t.Fatalf("GenerateKeyPair EC: %v", err)
	}
	return pub, priv
}

func destroyObject(t *testing.T, p *Ctx, session SessionHandle, label string, class uint) {
	t.Helper()
	template := []*Attribute{
		NewAttribute(CKA_LABEL, label),
		NewAttribute(CKA_CLASS, class),
	}
	if err := p.FindObjectsInit(session, template); err != nil {
		t.Fatalf("FindObjectsInit: %v", err)
	}
	objs, _, err := p.FindObjects(session, 1)
	if err != nil {
		t.Fatalf("FindObjects: %v", err)
	}
	if err := p.FindObjectsFinal(session); err != nil {
		t.Fatalf("FindObjectsFinal: %v", err)
	}
	for _, obj := range objs {
		if err := p.DestroyObject(session, obj); err != nil {
			t.Fatalf("DestroyObject: %v", err)
		}
	}
}

// ============================================================
// Tests ported from miekg/pkcs11 + our additions
// ============================================================

func TestNew(t *testing.T) {
	if p := New(""); p != nil {
		t.Error("New with empty string should return nil")
	}
	if p := New("/does/not/exist"); p != nil {
		t.Error("New with non-existent path should return nil")
	}
	p := setenv(t)
	if p == nil {
		t.Fatal("New with valid module should return non-nil")
	}
}

func TestInitialize(t *testing.T) {
	p := setenv(t)
	if err := p.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	defer func() {
		if err := p.Finalize(); err != nil {
			t.Fatalf("Finalize: %v", err)
		}
	}()
}

func TestGetInfo(t *testing.T) {
	p := setenv(t)
	if err := p.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	defer p.Finalize()

	info, err := p.GetInfo()
	if err != nil {
		t.Fatalf("GetInfo: %v", err)
	}
	if info.ManufacturerID != "SoftHSM" {
		t.Errorf("ManufacturerID = %q, want %q", info.ManufacturerID, "SoftHSM")
	}
	t.Logf("CryptokiVersion: %d.%d", info.CryptokiVersion.Major, info.CryptokiVersion.Minor)
	t.Logf("ManufacturerID: %s", info.ManufacturerID)
	t.Logf("LibraryDescription: %s", info.LibraryDescription)
}

func TestGetSlotList(t *testing.T) {
	p := setenv(t)
	slotID := initToken(t, p)

	slots, err := p.GetSlotList(true)
	if err != nil {
		t.Fatalf("GetSlotList: %v", err)
	}
	if len(slots) == 0 {
		t.Fatal("Expected at least one slot")
	}
	t.Logf("Slots with tokens: %v (initialized slot: %d)", slots, slotID)
}

func TestGetSlotInfo(t *testing.T) {
	p := setenv(t)
	slotID := initToken(t, p)

	info, err := p.GetSlotInfo(slotID)
	if err != nil {
		t.Fatalf("GetSlotInfo: %v", err)
	}
	t.Logf("SlotDescription: %s", info.SlotDescription)
	t.Logf("ManufacturerID: %s", info.ManufacturerID)
}

func TestGetTokenInfo(t *testing.T) {
	p := setenv(t)
	slotID := initToken(t, p)

	info, err := p.GetTokenInfo(slotID)
	if err != nil {
		t.Fatalf("GetTokenInfo: %v", err)
	}
	if info.Label != "TestToken" {
		t.Errorf("Label = %q, want %q", info.Label, "TestToken")
	}
	t.Logf("Token Label: %s", info.Label)
	t.Logf("ManufacturerID: %s", info.ManufacturerID)
	t.Logf("Model: %s", info.Model)
}

func TestGetSessionInfo(t *testing.T) {
	p := setenv(t)
	slotID := initToken(t, p)
	session := getSession(t, p, slotID)
	defer finishSession(t, p, session)

	info, err := p.GetSessionInfo(session)
	if err != nil {
		t.Fatalf("GetSessionInfo: %v", err)
	}
	if info.State != CKS_RW_USER_FUNCTIONS {
		t.Errorf("State = %d, want %d (CKS_RW_USER_FUNCTIONS)", info.State, CKS_RW_USER_FUNCTIONS)
	}
}

func TestCloseAllSessions(t *testing.T) {
	p := setenv(t)
	slotID := initToken(t, p)

	s1, err := p.OpenSession(slotID, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	if err != nil {
		t.Fatalf("OpenSession 1: %v", err)
	}
	_, err = p.OpenSession(slotID, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	if err != nil {
		t.Fatalf("OpenSession 2: %v", err)
	}

	if err := p.CloseAllSessions(slotID); err != nil {
		t.Fatalf("CloseAllSessions: %v", err)
	}

	// Trying to use the closed session should fail.
	_, err = p.GetSessionInfo(s1)
	if err == nil {
		t.Error("Expected error using closed session")
	}
}

func TestGenerateKeyPair(t *testing.T) {
	p := setenv(t)
	slotID := initToken(t, p)
	session := getSession(t, p, slotID)
	defer finishSession(t, p, session)

	pub, priv := generateRSAKeyPair(t, p, session, "testkeypair", false)
	t.Logf("Public key handle: %d, Private key handle: %d", pub, priv)
}

func TestGenerateECKeyPair(t *testing.T) {
	p := setenv(t)
	slotID := initToken(t, p)
	session := getSession(t, p, slotID)
	defer finishSession(t, p, session)

	pub, priv := generateECKeyPair(t, p, session, "testeckeypair", false)
	t.Logf("EC Public key handle: %d, EC Private key handle: %d", pub, priv)
}

func TestFindObject(t *testing.T) {
	p := setenv(t)
	slotID := initToken(t, p)
	session := getSession(t, p, slotID)
	defer finishSession(t, p, session)

	label := "findme"
	generateRSAKeyPair(t, p, session, label, false)

	template := []*Attribute{
		NewAttribute(CKA_LABEL, label),
		NewAttribute(CKA_CLASS, CKO_PUBLIC_KEY),
	}
	if err := p.FindObjectsInit(session, template); err != nil {
		t.Fatalf("FindObjectsInit: %v", err)
	}
	objs, ok, err := p.FindObjects(session, 10)
	if err != nil {
		t.Fatalf("FindObjects: %v", err)
	}
	if !ok || len(objs) == 0 {
		t.Error("Expected to find at least one object")
	}
	if err := p.FindObjectsFinal(session); err != nil {
		t.Fatalf("FindObjectsFinal: %v", err)
	}
}

func TestFindObjectNotFound(t *testing.T) {
	p := setenv(t)
	slotID := initToken(t, p)
	session := getSession(t, p, slotID)
	defer finishSession(t, p, session)

	template := []*Attribute{
		NewAttribute(CKA_LABEL, "nonexistent-label-12345"),
	}
	if err := p.FindObjectsInit(session, template); err != nil {
		t.Fatalf("FindObjectsInit: %v", err)
	}
	objs, ok, err := p.FindObjects(session, 10)
	if err != nil {
		t.Fatalf("FindObjects: %v", err)
	}
	if ok || len(objs) != 0 {
		t.Error("Expected empty result for nonexistent label")
	}
	if err := p.FindObjectsFinal(session); err != nil {
		t.Fatalf("FindObjectsFinal: %v", err)
	}
}

func TestGetAttributeValue(t *testing.T) {
	p := setenv(t)
	slotID := initToken(t, p)
	session := getSession(t, p, slotID)
	defer finishSession(t, p, session)

	pub, _ := generateRSAKeyPair(t, p, session, "attrtest", false)

	attrs, err := p.GetAttributeValue(session, pub, []*Attribute{
		{Type: CKA_PUBLIC_EXPONENT},
		{Type: CKA_MODULUS_BITS},
		{Type: CKA_MODULUS},
		{Type: CKA_LABEL},
	})
	if err != nil {
		t.Fatalf("GetAttributeValue: %v", err)
	}
	for _, a := range attrs {
		t.Logf("Attribute 0x%X: %d bytes", a.Type, len(a.Value))
	}
	if len(attrs) != 4 {
		t.Errorf("Expected 4 attributes, got %d", len(attrs))
	}
	// Check label.
	if string(attrs[3].Value) != "attrtest" {
		t.Errorf("Label = %q, want %q", string(attrs[3].Value), "attrtest")
	}
}

func TestDestroyObject(t *testing.T) {
	p := setenv(t)
	slotID := initToken(t, p)
	session := getSession(t, p, slotID)
	defer finishSession(t, p, session)

	label := "destroyme"
	generateRSAKeyPair(t, p, session, label, true)

	destroyObject(t, p, session, label, CKO_PUBLIC_KEY)
	destroyObject(t, p, session, label, CKO_PRIVATE_KEY)
}

func TestSign(t *testing.T) {
	p := setenv(t)
	slotID := initToken(t, p)
	session := getSession(t, p, slotID)
	defer finishSession(t, p, session)

	_, priv := generateRSAKeyPair(t, p, session, "signtest", false)

	if err := p.SignInit(session, []*Mechanism{NewMechanism(CKM_SHA1_RSA_PKCS, nil)}, priv); err != nil {
		t.Fatalf("SignInit: %v", err)
	}

	data := []byte("hello world")
	sig, err := p.Sign(session, data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Error("Signature is empty")
	}
	t.Logf("Signature length: %d bytes", len(sig))
}

func TestSignVerifyRoundTrip(t *testing.T) {
	p := setenv(t)
	slotID := initToken(t, p)
	session := getSession(t, p, slotID)
	defer finishSession(t, p, session)

	pub, priv := generateRSAKeyPair(t, p, session, "signverify", false)

	data := []byte("test message for signing")

	if err := p.SignInit(session, []*Mechanism{NewMechanism(CKM_SHA1_RSA_PKCS, nil)}, priv); err != nil {
		t.Fatalf("SignInit: %v", err)
	}
	sig, err := p.Sign(session, data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if err := p.VerifyInit(session, []*Mechanism{NewMechanism(CKM_SHA1_RSA_PKCS, nil)}, pub); err != nil {
		t.Fatalf("VerifyInit: %v", err)
	}
	if err := p.Verify(session, data, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestSignECDSA(t *testing.T) {
	p := setenv(t)
	slotID := initToken(t, p)
	session := getSession(t, p, slotID)
	defer finishSession(t, p, session)

	pub, priv := generateECKeyPair(t, p, session, "ecdsasign", false)

	data := make([]byte, 32) // SHA-256 sized hash
	for i := range data {
		data[i] = byte(i)
	}

	if err := p.SignInit(session, []*Mechanism{NewMechanism(CKM_ECDSA, nil)}, priv); err != nil {
		t.Fatalf("SignInit: %v", err)
	}
	sig, err := p.Sign(session, data)
	if err != nil {
		t.Fatalf("Sign ECDSA: %v", err)
	}
	if len(sig) == 0 {
		t.Error("ECDSA Signature is empty")
	}

	if err := p.VerifyInit(session, []*Mechanism{NewMechanism(CKM_ECDSA, nil)}, pub); err != nil {
		t.Fatalf("VerifyInit: %v", err)
	}
	if err := p.Verify(session, data, sig); err != nil {
		t.Fatalf("Verify ECDSA: %v", err)
	}
}

func TestDigest(t *testing.T) {
	p := setenv(t)
	slotID := initToken(t, p)
	session := getSession(t, p, slotID)
	defer finishSession(t, p, session)

	if err := p.DigestInit(session, []*Mechanism{NewMechanism(CKM_SHA_1, nil)}); err != nil {
		t.Fatalf("DigestInit: %v", err)
	}

	hash, err := p.Digest(session, []byte("Hello"))
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if len(hash) != 20 {
		t.Errorf("SHA-1 hash length = %d, want 20", len(hash))
	}
}

func TestDigestUpdate(t *testing.T) {
	p := setenv(t)
	slotID := initToken(t, p)
	session := getSession(t, p, slotID)
	defer finishSession(t, p, session)

	if err := p.DigestInit(session, []*Mechanism{NewMechanism(CKM_SHA_1, nil)}); err != nil {
		t.Fatalf("DigestInit: %v", err)
	}
	if err := p.DigestUpdate(session, []byte("Hel")); err != nil {
		t.Fatalf("DigestUpdate 1: %v", err)
	}
	if err := p.DigestUpdate(session, []byte("lo")); err != nil {
		t.Fatalf("DigestUpdate 2: %v", err)
	}
	hash, err := p.DigestFinal(session)
	if err != nil {
		t.Fatalf("DigestFinal: %v", err)
	}
	if len(hash) != 20 {
		t.Errorf("SHA-1 hash length = %d, want 20", len(hash))
	}
}

func TestSymmetricEncryption(t *testing.T) {
	p := setenv(t)
	slotID := initToken(t, p)
	session := getSession(t, p, slotID)
	defer finishSession(t, p, session)

	// Generate an AES key.
	keyTemplate := []*Attribute{
		NewAttribute(CKA_CLASS, CKO_SECRET_KEY),
		NewAttribute(CKA_KEY_TYPE, CKK_AES),
		NewAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_ENCRYPT, true),
		NewAttribute(CKA_DECRYPT, true),
		NewAttribute(CKA_VALUE_LEN, 32),
	}
	key, err := p.GenerateKey(session,
		[]*Mechanism{NewMechanism(CKM_AES_KEY_GEN, nil)},
		keyTemplate)
	if err != nil {
		t.Fatalf("GenerateKey AES: %v", err)
	}

	t.Run("AES-ECB", func(t *testing.T) {
		// ECB: plaintext must be multiple of 16.
		plain := []byte("0123456789abcdef") // 16 bytes

		if err := p.EncryptInit(session, []*Mechanism{NewMechanism(CKM_AES_ECB, nil)}, key); err != nil {
			t.Fatalf("EncryptInit: %v", err)
		}
		cipher, err := p.Encrypt(session, plain)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}

		if err := p.DecryptInit(session, []*Mechanism{NewMechanism(CKM_AES_ECB, nil)}, key); err != nil {
			t.Fatalf("DecryptInit: %v", err)
		}
		decrypted, err := p.Decrypt(session, cipher)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}

		if string(decrypted) != string(plain) {
			t.Errorf("Decrypted = %q, want %q", decrypted, plain)
		}
	})

	t.Run("AES-CBC", func(t *testing.T) {
		iv := make([]byte, 16)
		plain := []byte("0123456789abcdef") // 16 bytes

		if err := p.EncryptInit(session, []*Mechanism{NewMechanism(CKM_AES_CBC, iv)}, key); err != nil {
			t.Fatalf("EncryptInit: %v", err)
		}
		cipher, err := p.Encrypt(session, plain)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}

		if err := p.DecryptInit(session, []*Mechanism{NewMechanism(CKM_AES_CBC, iv)}, key); err != nil {
			t.Fatalf("DecryptInit: %v", err)
		}
		decrypted, err := p.Decrypt(session, cipher)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}

		if string(decrypted) != string(plain) {
			t.Errorf("Decrypted = %q, want %q", decrypted, plain)
		}
	})

	t.Run("AES-CBC-PAD", func(t *testing.T) {
		iv := make([]byte, 16)
		// CBC-PAD handles non-block-aligned data.
		plain := []byte("hello, world!")

		if err := p.EncryptInit(session, []*Mechanism{NewMechanism(CKM_AES_CBC_PAD, iv)}, key); err != nil {
			t.Fatalf("EncryptInit: %v", err)
		}
		cipher, err := p.Encrypt(session, plain)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}

		if err := p.DecryptInit(session, []*Mechanism{NewMechanism(CKM_AES_CBC_PAD, iv)}, key); err != nil {
			t.Fatalf("DecryptInit: %v", err)
		}
		decrypted, err := p.Decrypt(session, cipher)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}

		if string(decrypted) != string(plain) {
			t.Errorf("Decrypted = %q, want %q", decrypted, plain)
		}
	})
}

func TestGetMechanismList(t *testing.T) {
	p := setenv(t)
	slotID := initToken(t, p)

	mechs, err := p.GetMechanismList(slotID)
	if err != nil {
		t.Fatalf("GetMechanismList: %v", err)
	}
	if len(mechs) == 0 {
		t.Error("Expected at least one mechanism")
	}
	t.Logf("Mechanisms supported: %d", len(mechs))
}

func TestGenerateRandom(t *testing.T) {
	p := setenv(t)
	slotID := initToken(t, p)
	session := getSession(t, p, slotID)
	defer finishSession(t, p, session)

	random, err := p.GenerateRandom(session, 32)
	if err != nil {
		t.Fatalf("GenerateRandom: %v", err)
	}
	if len(random) != 32 {
		t.Errorf("Random length = %d, want 32", len(random))
	}

	// Verify it's not all zeros (extremely unlikely for real random).
	allZero := true
	for _, b := range random {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Random bytes are all zeros")
	}
}

func TestDoubleInitialize(t *testing.T) {
	p := setenv(t)
	if err := p.Initialize(); err != nil {
		t.Fatalf("First Initialize: %v", err)
	}
	defer p.Finalize()

	// Second Initialize should return CKR_CRYPTOKI_ALREADY_INITIALIZED.
	err := p.Initialize()
	if err == nil {
		t.Error("Expected error from double Initialize")
	}
	pkcsErr, ok := err.(Error)
	if !ok {
		t.Fatalf("Expected pkcs11.Error, got %T", err)
	}
	if uint(pkcsErr) != CKR_CRYPTOKI_ALREADY_INITIALIZED {
		t.Errorf("Expected CKR_CRYPTOKI_ALREADY_INITIALIZED, got %v", err)
	}
}

func TestOperationAfterLogout(t *testing.T) {
	p := setenv(t)
	slotID := initToken(t, p)
	session := getSession(t, p, slotID)

	_, priv := generateRSAKeyPair(t, p, session, "logouttest", false)

	// Logout first.
	if err := p.Logout(session); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	// Sign should fail after logout since the private key requires login.
	err := p.SignInit(session, []*Mechanism{NewMechanism(CKM_SHA1_RSA_PKCS, nil)}, priv)
	if err == nil {
		t.Error("Expected error using private key after logout")
	}

	if err := p.CloseSession(session); err != nil {
		t.Fatalf("CloseSession: %v", err)
	}
}

func TestInvalidMechanism(t *testing.T) {
	p := setenv(t)
	slotID := initToken(t, p)
	session := getSession(t, p, slotID)
	defer finishSession(t, p, session)

	_, priv := generateRSAKeyPair(t, p, session, "invalidmech", false)

	// Use digest mechanism for signing - should fail.
	err := p.SignInit(session, []*Mechanism{NewMechanism(CKM_SHA_1, nil)}, priv)
	if err == nil {
		t.Error("Expected error using digest mechanism for signing")
	}
}

func TestSignRSAPSS(t *testing.T) {
	p := setenv(t)
	slotID := initToken(t, p)
	session := getSession(t, p, slotID)
	defer finishSession(t, p, session)

	pub, priv := generateRSAKeyPair(t, p, session, "psstest", false)

	pssParams := NewPSSParams(CKM_SHA256, CKG_MGF1_SHA256, 32)
	if err := p.SignInit(session, []*Mechanism{NewMechanism(CKM_RSA_PKCS_PSS, pssParams)}, priv); err != nil {
		t.Fatalf("SignInit PSS: %v", err)
	}

	hash := make([]byte, 32) // SHA-256 hash
	for i := range hash {
		hash[i] = byte(i)
	}

	sig, err := p.Sign(session, hash)
	if err != nil {
		t.Fatalf("Sign PSS: %v", err)
	}
	if len(sig) == 0 {
		t.Error("PSS Signature is empty")
	}

	if err := p.VerifyInit(session, []*Mechanism{NewMechanism(CKM_RSA_PKCS_PSS, pssParams)}, pub); err != nil {
		t.Fatalf("VerifyInit PSS: %v", err)
	}
	if err := p.Verify(session, hash, sig); err != nil {
		t.Fatalf("Verify PSS: %v", err)
	}
}
