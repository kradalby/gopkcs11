//go:build linux

// Package signer implements [crypto.Signer] on top of a PKCS#11 token.
// It is API-compatible with github.com/letsencrypt/pkcs11key/v4.
package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"

	pkcs11 "github.com/kradalby/gopkcs11"
)

// ctx is the subset of *pkcs11.Ctx methods used by this package.
// Defining it as an interface enables testing with mocks.
type ctx interface {
	CloseSession(sh pkcs11.SessionHandle) error
	FindObjectsFinal(sh pkcs11.SessionHandle) error
	FindObjectsInit(sh pkcs11.SessionHandle, temp []*pkcs11.Attribute) error
	FindObjects(sh pkcs11.SessionHandle, max int) ([]pkcs11.ObjectHandle, bool, error)
	GetAttributeValue(sh pkcs11.SessionHandle, o pkcs11.ObjectHandle, a []*pkcs11.Attribute) ([]*pkcs11.Attribute, error)
	GetSlotList(tokenPresent bool) ([]uint, error)
	GetTokenInfo(slotID uint) (pkcs11.TokenInfo, error)
	Initialize(opts ...pkcs11.InitializeOption) error
	Login(sh pkcs11.SessionHandle, userType uint, pin string) error
	Logout(sh pkcs11.SessionHandle) error
	OpenSession(slotID, flags uint) (pkcs11.SessionHandle, error)
	SignInit(sh pkcs11.SessionHandle, m []*pkcs11.Mechanism, o pkcs11.ObjectHandle) error
	Sign(sh pkcs11.SessionHandle, message []byte) ([]byte, error)
}

// modulesMu protects the modules map and is also used as a global lock
// for alwaysAuthenticate login/logout cycles.
var modulesMu sync.Mutex

// modules caches initialized PKCS#11 modules by path.
var modules = make(map[string]ctx)

// initialize loads and initializes the PKCS#11 module at the given path.
// Subsequent calls with the same path return the cached module.
func initialize(modulePath string) (ctx, error) {
	modulesMu.Lock()
	defer modulesMu.Unlock()

	if m, ok := modules[modulePath]; ok {
		return m, nil
	}

	p := pkcs11.New(modulePath)
	if p == nil {
		return nil, fmt.Errorf("pkcs11key: failed to load module %q", modulePath)
	}
	if err := p.Initialize(); err != nil {
		return nil, fmt.Errorf("pkcs11key: initialize: %w", err)
	}
	modules[modulePath] = p
	return p, nil
}

// Key implements [crypto.Signer] using a private key stored on a PKCS#11 token.
type Key struct {
	module             ctx
	tokenLabel         string
	pin                string
	publicKey          crypto.PublicKey
	privateKeyHandle   pkcs11.ObjectHandle
	session            *pkcs11.SessionHandle
	sessionMu          sync.Mutex
	alwaysAuthenticate bool
}

// New creates a Key backed by a PKCS#11 private key.
// The publicKey must match a key stored on the token identified by tokenLabel.
func New(modulePath, tokenLabel, pin string, publicKey crypto.PublicKey) (*Key, error) {
	module, err := initialize(modulePath)
	if err != nil {
		return nil, err
	}

	k := &Key{
		module:     module,
		tokenLabel: tokenLabel,
		pin:        pin,
		publicKey:  publicKey,
	}
	if err := k.setup(); err != nil {
		return nil, err
	}
	return k, nil
}

// setup opens a session, logs in, and finds the private key matching the
// configured public key.
func (k *Key) setup() error {
	session, err := k.openSession()
	if err != nil {
		return err
	}
	k.session = &session

	pubKeyID, err := k.getPublicKeyID(session)
	if err != nil {
		k.module.CloseSession(session) //nolint:errcheck,gosec // cleanup on error path (G104)
		k.session = nil
		return err
	}

	privHandle, alwaysAuth, err := k.getPrivateKey(session, pubKeyID)
	if err != nil {
		k.module.CloseSession(session) //nolint:errcheck,gosec // cleanup on error path (G104)
		k.session = nil
		return err
	}
	k.privateKeyHandle = privHandle
	k.alwaysAuthenticate = alwaysAuth
	return nil
}

// openSession finds the slot matching tokenLabel, opens a session, and logs in.
func (k *Key) openSession() (pkcs11.SessionHandle, error) {
	slots, err := k.module.GetSlotList(true)
	if err != nil {
		return 0, fmt.Errorf("pkcs11key: GetSlotList: %w", err)
	}

	for _, slotID := range slots {
		tokenInfo, err := k.module.GetTokenInfo(slotID)
		if err != nil {
			continue
		}
		if tokenInfo.Label != k.tokenLabel {
			continue
		}

		session, err := k.module.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION)
		if err != nil {
			return 0, fmt.Errorf("pkcs11key: OpenSession: %w", err)
		}

		err = k.module.Login(session, pkcs11.CKU_USER, k.pin)
		if err != nil {
			// CKR_USER_ALREADY_LOGGED_IN is not an error.
			if !errors.Is(err, pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN)) {
				k.module.CloseSession(session) //nolint:errcheck,gosec // cleanup on error path (G104)
				return 0, fmt.Errorf("pkcs11key: Login: %w", err)
			}
		}
		return session, nil
	}
	return 0, fmt.Errorf("pkcs11key: token %q not found", k.tokenLabel)
}

// findObject searches for a single object matching the given template.
func (k *Key) findObject(session pkcs11.SessionHandle, template []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	if err := k.module.FindObjectsInit(session, template); err != nil {
		return 0, fmt.Errorf("pkcs11key: FindObjectsInit: %w", err)
	}
	objs, _, err := k.module.FindObjects(session, 1)
	if err != nil {
		k.module.FindObjectsFinal(session) //nolint:errcheck,gosec // cleanup (G104)
		return 0, fmt.Errorf("pkcs11key: FindObjects: %w", err)
	}
	if err := k.module.FindObjectsFinal(session); err != nil {
		return 0, fmt.Errorf("pkcs11key: FindObjectsFinal: %w", err)
	}
	if len(objs) == 0 {
		return 0, fmt.Errorf("pkcs11key: object not found")
	}
	return objs[0], nil
}

// getPublicKeyID finds the public key on the token that matches our
// crypto.PublicKey and returns its CKA_ID.
func (k *Key) getPublicKeyID(session pkcs11.SessionHandle) ([]byte, error) {
	var template []*pkcs11.Attribute

	switch pub := k.publicKey.(type) {
	case *rsa.PublicKey:
		template = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS, pub.N.Bytes()),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, big.NewInt(int64(pub.E)).Bytes()),
		}
	case *ecdsa.PublicKey:
		ecParams, err := ecCurveToParams(pub.Curve)
		if err != nil {
			return nil, err
		}
		ecPoint := elliptic.Marshal(pub.Curve, pub.X, pub.Y) //nolint:staticcheck // PKCS#11 requires uncompressed EC point format; crypto/ecdh doesn't expose raw X/Y
		// PKCS#11 stores EC_POINT as DER-encoded OCTET STRING.
		ecPointDER, err := asn1.Marshal(ecPoint)
		if err != nil {
			return nil, fmt.Errorf("pkcs11key: marshal EC point: %w", err)
		}
		template = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, ecPointDER),
		}
	default:
		return nil, fmt.Errorf("pkcs11key: unsupported public key type %T", k.publicKey)
	}

	obj, err := k.findObject(session, template)
	if err != nil {
		return nil, fmt.Errorf("pkcs11key: public key not found on token: %w", err)
	}

	attrs, err := k.module.GetAttributeValue(session, obj, []*pkcs11.Attribute{
		{Type: pkcs11.CKA_ID},
	})
	if err != nil {
		return nil, fmt.Errorf("pkcs11key: GetAttributeValue CKA_ID: %w", err)
	}
	if len(attrs) == 0 || len(attrs[0].Value) == 0 {
		return nil, fmt.Errorf("pkcs11key: public key has no CKA_ID")
	}
	return attrs[0].Value, nil
}

// getPrivateKey finds the private key with the matching CKA_ID and checks
// the CKA_ALWAYS_AUTHENTICATE attribute.
func (k *Key) getPrivateKey(session pkcs11.SessionHandle, keyID []byte) (pkcs11.ObjectHandle, bool, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
	}

	obj, err := k.findObject(session, template)
	if err != nil {
		return 0, false, fmt.Errorf("pkcs11key: private key not found: %w", err)
	}

	alwaysAuth := false
	attrs, err := k.module.GetAttributeValue(session, obj, []*pkcs11.Attribute{
		{Type: pkcs11.CKA_ALWAYS_AUTHENTICATE},
	})
	if err != nil {
		// Some tokens don't support CKA_ALWAYS_AUTHENTICATE.
		if !errors.Is(err, pkcs11.Error(pkcs11.CKR_ATTRIBUTE_TYPE_INVALID)) {
			return 0, false, fmt.Errorf("pkcs11key: GetAttributeValue: %w", err)
		}
	} else if len(attrs) > 0 && len(attrs[0].Value) > 0 {
		alwaysAuth = attrs[0].Value[0] != 0
	}

	return obj, alwaysAuth, nil
}

// Public returns the public key corresponding to the PKCS#11 private key.
func (k *Key) Public() crypto.PublicKey {
	return k.publicKey
}

// Sign implements [crypto.Signer.Sign].
func (k *Key) Sign(_ io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	k.sessionMu.Lock()
	defer k.sessionMu.Unlock()

	if k.session == nil {
		return nil, errors.New("pkcs11key: session is nil (key destroyed?)")
	}

	if k.alwaysAuthenticate {
		modulesMu.Lock()
		k.module.Logout(*k.session) //nolint:errcheck,gosec // best-effort (G104)
		if err := k.module.Login(*k.session, pkcs11.CKU_USER, k.pin); err != nil {
			modulesMu.Unlock()
			return nil, fmt.Errorf("pkcs11key: re-login: %w", err)
		}
		modulesMu.Unlock()
	}

	mechanism, signData, err := k.signingParams(msg, opts)
	if err != nil {
		return nil, err
	}

	if err := k.module.SignInit(*k.session, mechanism, k.privateKeyHandle); err != nil {
		return nil, fmt.Errorf("pkcs11key: SignInit: %w", err)
	}

	sig, err := k.module.Sign(*k.session, signData)
	if err != nil {
		return nil, fmt.Errorf("pkcs11key: Sign: %w", err)
	}

	// For ECDSA, convert from PKCS#11 r||s format to DER-encoded ASN.1.
	if _, ok := k.publicKey.(*ecdsa.PublicKey); ok {
		return pkcs11ToRFC5480(sig)
	}
	return sig, nil
}

// signingParams determines the PKCS#11 mechanism and prepares the data to sign.
func (k *Key) signingParams(msg []byte, opts crypto.SignerOpts) ([]*pkcs11.Mechanism, []byte, error) {
	switch k.publicKey.(type) {
	case *rsa.PublicKey:
		return k.rsaSigningParams(msg, opts)
	case *ecdsa.PublicKey:
		return []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, msg, nil
	default:
		return nil, nil, fmt.Errorf("pkcs11key: unsupported key type %T", k.publicKey)
	}
}

// rsaSigningParams determines the RSA signing mechanism and data.
func (k *Key) rsaSigningParams(msg []byte, opts crypto.SignerOpts) ([]*pkcs11.Mechanism, []byte, error) {
	// RSA-PSS
	if pssOpts, ok := opts.(*rsa.PSSOptions); ok {
		hashAlg, mgf, err := pssHashToMechanism(pssOpts.HashFunc())
		if err != nil {
			return nil, nil, err
		}
		saltLen := pssOpts.SaltLength
		if saltLen == rsa.PSSSaltLengthAuto || saltLen == rsa.PSSSaltLengthEqualsHash {
			saltLen = pssOpts.HashFunc().Size()
		}
		params := pkcs11.NewPSSParams(hashAlg, mgf, uint(saltLen))
		return []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_PSS, params)}, msg, nil
	}

	// RSA PKCS#1 v1.5: prepend DigestInfo.
	prefix, err := digestInfoPrefix(opts.HashFunc())
	if err != nil {
		return nil, nil, err
	}
	signData := make([]byte, len(prefix)+len(msg))
	copy(signData, prefix)
	copy(signData[len(prefix):], msg)
	return []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}, signData, nil
}

// Destroy closes the PKCS#11 session.
func (k *Key) Destroy() {
	k.sessionMu.Lock()
	defer k.sessionMu.Unlock()
	if k.session != nil {
		k.module.CloseSession(*k.session) //nolint:errcheck,gosec // cleanup (G104)
		k.session = nil
	}
}

// Pool wraps multiple Key instances for concurrent signing.
type Pool struct {
	signers    []*Key
	totalCount int
	cond       *sync.Cond
}

// NewPool creates a Pool of n Key instances for concurrent signing.
func NewPool(n int, modulePath, tokenLabel, pin string, publicKey crypto.PublicKey) (*Pool, error) {
	if n < 1 {
		return nil, fmt.Errorf("pkcs11key: pool size must be >= 1")
	}

	keys := make([]*Key, 0, n)
	for range n {
		k, err := New(modulePath, tokenLabel, pin, publicKey)
		if err != nil {
			// Destroy any already-created keys to avoid PIN lockout.
			for _, prev := range keys {
				prev.Destroy()
			}
			return nil, err
		}
		keys = append(keys, k)
	}

	return &Pool{
		signers:    keys,
		totalCount: n,
		cond:       sync.NewCond(&sync.Mutex{}),
	}, nil
}

// Public returns the public key.
func (p *Pool) Public() crypto.PublicKey {
	return p.signers[0].Public()
}

// Sign acquires an available Key from the pool and signs.
func (p *Pool) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	p.cond.L.Lock()
	for len(p.signers) == 0 {
		p.cond.Wait()
	}
	k := p.signers[0]
	p.signers = p.signers[1:]
	p.cond.L.Unlock()

	sig, err := k.Sign(rand, msg, opts)

	p.cond.L.Lock()
	p.signers = append(p.signers, k)
	p.cond.L.Unlock()
	p.cond.Signal()

	return sig, err
}

// Destroy destroys all keys in the pool.
func (p *Pool) Destroy() {
	for _, k := range p.signers {
		k.Destroy()
	}
}

// --- helpers ---

// digestInfoPrefix returns the DER-encoded DigestInfo prefix for PKCS#1v1.5.
func digestInfoPrefix(hash crypto.Hash) ([]byte, error) {
	// These are the standard ASN.1 DigestInfo prefixes from PKCS#1.
	switch hash {
	case crypto.SHA1:
		return []byte{0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14}, nil
	case crypto.SHA224:
		return []byte{0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c}, nil
	case crypto.SHA256:
		return []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}, nil
	case crypto.SHA384:
		return []byte{0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30}, nil
	case crypto.SHA512:
		return []byte{0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40}, nil
	default:
		return nil, fmt.Errorf("pkcs11key: unsupported hash for PKCS#1v1.5: %v", hash)
	}
}

// pssHashToMechanism maps a hash function to CKM_* and CKG_MGF1_* constants.
func pssHashToMechanism(hash crypto.Hash) (uint, uint, error) {
	switch hash {
	case crypto.SHA1:
		return pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1, nil
	case crypto.SHA224:
		return pkcs11.CKM_SHA224, pkcs11.CKG_MGF1_SHA224, nil
	case crypto.SHA256:
		return pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256, nil
	case crypto.SHA384:
		return pkcs11.CKM_SHA384, pkcs11.CKG_MGF1_SHA384, nil
	case crypto.SHA512:
		return pkcs11.CKM_SHA512, pkcs11.CKG_MGF1_SHA512, nil
	default:
		return 0, 0, fmt.Errorf("pkcs11key: unsupported hash for PSS: %v", hash)
	}
}

// ecCurveToParams returns the DER-encoded OID for the given elliptic curve.
func ecCurveToParams(curve elliptic.Curve) ([]byte, error) {
	switch curve {
	case elliptic.P224():
		return asn1.Marshal(asn1.ObjectIdentifier{1, 3, 132, 0, 33})
	case elliptic.P256():
		return asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})
	case elliptic.P384():
		return asn1.Marshal(asn1.ObjectIdentifier{1, 3, 132, 0, 34})
	case elliptic.P521():
		return asn1.Marshal(asn1.ObjectIdentifier{1, 3, 132, 0, 35})
	default:
		return nil, fmt.Errorf("pkcs11key: unsupported EC curve")
	}
}

// pkcs11ToRFC5480 converts a PKCS#11 ECDSA signature (r||s concatenation)
// to the RFC 5480 DER-encoded ASN.1 format used by Go's crypto/ecdsa.
func pkcs11ToRFC5480(sig []byte) ([]byte, error) {
	if len(sig) == 0 || len(sig)%2 != 0 {
		return nil, fmt.Errorf("pkcs11key: invalid ECDSA signature length %d", len(sig))
	}
	half := len(sig) / 2
	r := new(big.Int).SetBytes(sig[:half])
	s := new(big.Int).SetBytes(sig[half:])

	type ecdsaSig struct {
		R, S *big.Int
	}
	return asn1.Marshal(ecdsaSig{R: r, S: s})
}
