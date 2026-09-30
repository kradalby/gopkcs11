//go:build linux

package signer

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pkcs11 "github.com/kradalby/gopkcs11"
)

// appLoginCtx models PKCS#11 login state, which belongs to the application,
// not the session: a Logout on any session logs every session out.
type appLoginCtx struct {
	mockCtx
	loggedIn atomic.Bool
}

func (a *appLoginCtx) Login(pkcs11.SessionHandle, uint, string) error {
	// Checking the PIN takes a while, keeping the token logged out meanwhile.
	time.Sleep(50 * time.Microsecond)
	a.loggedIn.Store(true)
	return nil
}

func (a *appLoginCtx) Logout(pkcs11.SessionHandle) error {
	a.loggedIn.Store(false)
	return nil
}

// FindObjects hides private objects while logged out, as tokens do.
func (a *appLoginCtx) FindObjects(sh pkcs11.SessionHandle, n int) ([]pkcs11.ObjectHandle, bool, error) {
	objs, ok, err := a.mockCtx.FindObjects(sh, n)
	time.Sleep(50 * time.Microsecond)
	if len(objs) > 0 && objs[0] == mockRSAPrivHandle && !a.loggedIn.Load() {
		return nil, false, err
	}
	return objs, ok, err
}

func (a *appLoginCtx) SignInit(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error {
	// Widen the window between Login and signing.
	time.Sleep(50 * time.Microsecond)
	if !a.loggedIn.Load() {
		return pkcs11.Error(pkcs11.CKR_USER_NOT_LOGGED_IN)
	}
	return nil
}

func (a *appLoginCtx) Sign(_ pkcs11.SessionHandle, msg []byte) ([]byte, error) {
	if !a.loggedIn.Load() {
		return nil, pkcs11.Error(pkcs11.CKR_USER_NOT_LOGGED_IN)
	}
	return msg, nil
}

// Keys on one token, always-authenticate or not, must not sign while
// another key's re-login has the token logged out.
func TestAlwaysAuthenticateConcurrentSign(t *testing.T) {
	module := &appLoginCtx{}
	keys := make([]*Key, 4)
	for i := range keys {
		keys[i] = newAppLoginKey(t, module, i%2 == 0)
	}

	hash := sha256.Sum256([]byte("test"))
	var failures atomic.Int64
	var wg sync.WaitGroup
	for _, k := range keys {
		wg.Go(func() {
			for range 100 {
				if _, err := k.Sign(rand.Reader, hash[:], crypto.SHA256); err != nil {
					failures.Add(1)
				}
			}
		})
	}
	wg.Wait()

	if n := failures.Load(); n > 0 {
		t.Errorf("%d of %d signs failed; another key logged out mid-sign", n, 100*len(keys))
	}
}

// Setup finds the private key, so it must not run mid re-login either.
func TestSetupDuringAlwaysAuthenticateSign(t *testing.T) {
	module := &appLoginCtx{}
	signer := newAppLoginKey(t, module, true)

	hash := sha256.Sum256([]byte("test"))
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
				_, _ = signer.Sign(rand.Reader, hash[:], crypto.SHA256) // only its logouts matter
			}
		}
	})

	var failures int
	for range 50 {
		k := &Key{module: module, tokenLabel: "token label", pin: "unused", publicKey: testRSAPubKey}
		if err := k.setup(); err != nil {
			failures++
		}
	}
	close(stop)
	wg.Wait()

	if failures > 0 {
		t.Errorf("%d of 50 setups failed; token logged out mid-setup", failures)
	}
}

func newAppLoginKey(t *testing.T, module *appLoginCtx, alwaysAuth bool) *Key {
	t.Helper()
	k := &Key{module: module, tokenLabel: "token label", pin: "unused", publicKey: testRSAPubKey}
	if err := k.setup(); err != nil {
		t.Fatalf("setup: %v", err)
	}
	k.alwaysAuthenticate = alwaysAuth
	return k
}
