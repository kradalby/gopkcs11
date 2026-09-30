//go:build linux

package pkcs11

import (
	"bytes"
	"testing"
)

// TestDigestConsistency verifies SHA-1 produces the correct well-known hash.
func TestDigestConsistency(t *testing.T) {
	p := setenv(t)
	slotID := initToken(t, p)
	session := getSession(t, p, slotID)
	defer finishSession(t, p, session)

	if err := p.DigestInit(session, []*Mechanism{NewMechanism(CKM_SHA_1, nil)}); err != nil {
		t.Fatalf("DigestInit: %v", err)
	}
	// SHA-1("Hello") = f7ff9e8b7bb2e09b70935a5d785e0cc5d9d0abf0
	hash, err := p.Digest(session, []byte("Hello"))
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	expected := []byte{0xf7, 0xff, 0x9e, 0x8b, 0x7b, 0xb2, 0xe0, 0x9b, 0x70, 0x93, 0x5a, 0x5d, 0x78, 0x5e, 0x0c, 0xc5, 0xd9, 0xd0, 0xab, 0xf0}
	if !bytes.Equal(hash, expected) {
		t.Errorf("SHA-1(Hello) = %x, want %x", hash, expected)
	}
}

// TestMultipleKeyPairsAndFind creates multiple keys and verifies find works correctly.
func TestMultipleKeyPairsAndFind(t *testing.T) {
	p := setenv(t)
	slotID := initToken(t, p)
	session := getSession(t, p, slotID)
	defer finishSession(t, p, session)

	labels := []string{"key-alpha", "key-beta", "key-gamma"}
	for _, label := range labels {
		generateRSAKeyPair(t, p, session, label, false)
	}

	for _, label := range labels {
		template := []*Attribute{
			NewAttribute(CKA_LABEL, label),
			NewAttribute(CKA_CLASS, CKO_PUBLIC_KEY),
		}
		if err := p.FindObjectsInit(session, template); err != nil {
			t.Fatalf("FindObjectsInit for %s: %v", label, err)
		}
		objs, ok, err := p.FindObjects(session, 10)
		if err != nil {
			t.Fatalf("FindObjects for %s: %v", label, err)
		}
		if !ok || len(objs) != 1 {
			t.Errorf("FindObjects for %s: got %d objects, want 1", label, len(objs))
		}
		if err := p.FindObjectsFinal(session); err != nil {
			t.Fatalf("FindObjectsFinal: %v", err)
		}
	}
}

// TestEncryptDecryptMultiPart tests multi-part AES-CBC-PAD encrypt/decrypt.
func TestEncryptDecryptMultiPart(t *testing.T) {
	p := setenv(t)
	slotID := initToken(t, p)
	session := getSession(t, p, slotID)
	defer finishSession(t, p, session)

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
		t.Fatalf("GenerateKey: %v", err)
	}

	iv := make([]byte, 16)

	// Multi-part encrypt.
	if err := p.EncryptInit(session, []*Mechanism{NewMechanism(CKM_AES_CBC_PAD, iv)}, key); err != nil {
		t.Fatalf("EncryptInit: %v", err)
	}
	part1, err := p.EncryptUpdate(session, []byte("Hello, "))
	if err != nil {
		t.Fatalf("EncryptUpdate 1: %v", err)
	}
	part2, err := p.EncryptUpdate(session, []byte("World!"))
	if err != nil {
		t.Fatalf("EncryptUpdate 2: %v", err)
	}
	final, err := p.EncryptFinal(session)
	if err != nil {
		t.Fatalf("EncryptFinal: %v", err)
	}

	cipher := append(append(part1, part2...), final...)

	// Decrypt in one shot.
	if err := p.DecryptInit(session, []*Mechanism{NewMechanism(CKM_AES_CBC_PAD, iv)}, key); err != nil {
		t.Fatalf("DecryptInit: %v", err)
	}
	plain, err := p.Decrypt(session, cipher)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if string(plain) != "Hello, World!" {
		t.Errorf("Decrypted = %q, want %q", plain, "Hello, World!")
	}
}

// TestEmptyDigest tests digesting empty input.
func TestEmptyDigest(t *testing.T) {
	p := setenv(t)
	slotID := initToken(t, p)
	session := getSession(t, p, slotID)
	defer finishSession(t, p, session)

	if err := p.DigestInit(session, []*Mechanism{NewMechanism(CKM_SHA256, nil)}); err != nil {
		t.Fatalf("DigestInit: %v", err)
	}
	hash, err := p.Digest(session, []byte{})
	if err != nil {
		t.Fatalf("Digest empty: %v", err)
	}
	// SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
	if len(hash) != 32 {
		t.Errorf("SHA-256 empty hash length = %d, want 32", len(hash))
	}
	if hash[0] != 0xe3 {
		t.Errorf("SHA-256 empty hash[0] = 0x%02x, want 0xe3", hash[0])
	}
}

// TestLargeAttribute tests writing and reading a large attribute value.
func TestLargeAttribute(t *testing.T) {
	p := setenv(t)
	slotID := initToken(t, p)
	session := getSession(t, p, slotID)
	defer finishSession(t, p, session)

	largeValue := make([]byte, 4096)
	for i := range largeValue {
		largeValue[i] = byte(i % 256)
	}

	template := []*Attribute{
		NewAttribute(CKA_CLASS, CKO_DATA),
		NewAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_LABEL, "large-attr-test"),
		NewAttribute(CKA_VALUE, largeValue),
	}
	obj, err := p.CreateObject(session, template)
	if err != nil {
		t.Fatalf("CreateObject: %v", err)
	}

	attrs, err := p.GetAttributeValue(session, obj, []*Attribute{
		{Type: CKA_VALUE},
	})
	if err != nil {
		t.Fatalf("GetAttributeValue: %v", err)
	}
	if len(attrs) != 1 {
		t.Fatalf("Expected 1 attribute, got %d", len(attrs))
	}
	if !bytes.Equal(attrs[0].Value, largeValue) {
		t.Errorf("Large attribute value mismatch: got %d bytes, want %d", len(attrs[0].Value), len(largeValue))
	}
}

func generateAESKey(t *testing.T, p *Ctx, session SessionHandle) ObjectHandle {
	t.Helper()
	key, err := p.GenerateKey(session,
		[]*Mechanism{NewMechanism(CKM_AES_KEY_GEN, nil)},
		[]*Attribute{
			NewAttribute(CKA_CLASS, CKO_SECRET_KEY),
			NewAttribute(CKA_KEY_TYPE, CKK_AES),
			NewAttribute(CKA_TOKEN, false),
			NewAttribute(CKA_ENCRYPT, true),
			NewAttribute(CKA_DECRYPT, true),
			NewAttribute(CKA_VALUE_LEN, 32),
		})
	if err != nil {
		t.Fatalf("GenerateKey AES: %v", err)
	}
	return key
}

// TestMultiPartGCMDecrypt covers AEAD modules that withhold all plaintext
// until DecryptFinal, so Final output is as large as the whole message.
func TestMultiPartGCMDecrypt(t *testing.T) {
	p := setenv(t)
	slotID := initToken(t, p)
	session := getSession(t, p, slotID)
	defer finishSession(t, p, session)
	key := generateAESKey(t, p, session)

	plain := bytes.Repeat([]byte("A"), 1000)
	iv := make([]byte, 12)
	gcm := func() []*Mechanism {
		return []*Mechanism{NewMechanism(CKM_AES_GCM, NewGCMParams(iv, nil, 128))}
	}

	if err := p.EncryptInit(session, gcm(), key); err != nil {
		t.Fatalf("EncryptInit: %v", err)
	}
	cipher, err := p.Encrypt(session, plain)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if err := p.DecryptInit(session, gcm(), key); err != nil {
		t.Fatalf("DecryptInit: %v", err)
	}
	part, err := p.DecryptUpdate(session, cipher)
	if err != nil {
		t.Fatalf("DecryptUpdate: %v", err)
	}
	final, err := p.DecryptFinal(session)
	if err != nil {
		t.Fatalf("DecryptFinal: %v", err)
	}
	if got := append(part, final...); !bytes.Equal(got, plain) {
		t.Errorf("decrypted %d bytes, want %d", len(got), len(plain))
	}

	// A failed Final leaves the operation active and the session unusable.
	if err := p.DecryptInit(session, gcm(), key); err != nil {
		t.Fatalf("DecryptInit after Final: %v", err)
	}
}

// TestMultiPartEmptyOutput checks that calls whose output is empty still
// reach the module; skipping them leaves the operation active.
func TestMultiPartEmptyOutput(t *testing.T) {
	p := setenv(t)
	slotID := initToken(t, p)
	session := getSession(t, p, slotID)
	defer finishSession(t, p, session)
	key := generateAESKey(t, p, session)

	ecb := []*Mechanism{NewMechanism(CKM_AES_ECB, nil)}
	plain := []byte("0123456789abcdef")

	if err := p.EncryptInit(session, ecb, key); err != nil {
		t.Fatalf("EncryptInit: %v", err)
	}
	cipher, err := p.EncryptUpdate(session, plain)
	if err != nil {
		t.Fatalf("EncryptUpdate: %v", err)
	}
	final, err := p.EncryptFinal(session)
	if err != nil {
		t.Fatalf("EncryptFinal: %v", err)
	}
	if len(final) != 0 {
		t.Errorf("EncryptFinal = %d bytes, want 0", len(final))
	}

	if err := p.DecryptInit(session, ecb, key); err != nil {
		t.Fatalf("DecryptInit after EncryptFinal: %v", err)
	}
	got, err := p.Decrypt(session, cipher)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("Decrypt = %q, want %q", got, plain)
	}

	// Empty plaintext: Decrypt produces nothing but must still finish.
	iv := make([]byte, 12)
	gcm := func() []*Mechanism {
		return []*Mechanism{NewMechanism(CKM_AES_GCM, NewGCMParams(iv, nil, 128))}
	}
	if err := p.EncryptInit(session, gcm(), key); err != nil {
		t.Fatalf("EncryptInit GCM: %v", err)
	}
	tag, err := p.Encrypt(session, nil)
	if err != nil {
		t.Fatalf("Encrypt GCM: %v", err)
	}
	if err := p.DecryptInit(session, gcm(), key); err != nil {
		t.Fatalf("DecryptInit GCM: %v", err)
	}
	empty, err := p.Decrypt(session, tag)
	if err != nil {
		t.Fatalf("Decrypt GCM: %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("Decrypt GCM = %d bytes, want 0", len(empty))
	}
	if err := p.DecryptInit(session, gcm(), key); err != nil {
		t.Fatalf("DecryptInit after empty Decrypt: %v", err)
	}
}
