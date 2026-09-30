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

// blockingCtx parks Sign until released, holding its key checked out.
type blockingCtx struct {
	mockCtx
	entered chan struct{}
	release chan struct{}
}

func (b *blockingCtx) Sign(_ pkcs11.SessionHandle, msg []byte) ([]byte, error) {
	b.entered <- struct{}{}
	<-b.release
	return msg, nil
}

func newBlockingKey(t *testing.T) (*Key, *blockingCtx) {
	t.Helper()
	bc := &blockingCtx{entered: make(chan struct{}, 1), release: make(chan struct{})}
	k := &Key{module: bc, tokenLabel: "token label", pin: "unused", publicKey: testRSAPubKey}
	if err := k.setup(); err != nil {
		t.Fatalf("setup: %v", err)
	}
	return k, bc
}

func isDestroyed(k *Key) bool {
	k.sessionMu.Lock()
	defer k.sessionMu.Unlock()
	return k.session == nil
}

// crypto/tls calls Public during handshakes, possibly while every key is busy.
func TestPoolPublicWhileAllKeysBusy(t *testing.T) {
	k, bc := newBlockingKey(t)
	p := newPool(testRSAPubKey, []*Key{k})

	hash := sha256.Sum256([]byte("test"))
	signed := make(chan struct{})
	go func() {
		defer close(signed)
		p.Sign(rand.Reader, hash[:], crypto.SHA256)
	}()
	<-bc.entered
	defer func() {
		close(bc.release)
		<-signed
	}()

	if got := p.Public(); got != testRSAPubKey {
		t.Errorf("Public() = %v, want pool's public key", got)
	}
}

func TestPoolDestroyWaitsForCheckedOutKeys(t *testing.T) {
	busy, bc := newBlockingKey(t)
	idle := setupMock(t, testRSAPubKey)
	p := newPool(testRSAPubKey, []*Key{busy, idle})

	hash := sha256.Sum256([]byte("test"))
	var wg sync.WaitGroup
	// Keys are handed out in order, so this checks out busy.
	wg.Go(func() { p.Sign(rand.Reader, hash[:], crypto.SHA256) })
	<-bc.entered

	destroyed := make(chan struct{})
	go func() {
		defer close(destroyed)
		p.Destroy()
	}()

	select {
	case <-destroyed:
		t.Error("Destroy returned while a key was checked out")
	case <-time.After(50 * time.Millisecond):
	}

	close(bc.release)
	<-destroyed
	wg.Wait()

	for i, k := range []*Key{busy, idle} {
		if !isDestroyed(k) {
			t.Errorf("key %d session still open after Destroy", i)
		}
	}

	if _, err := p.Sign(rand.Reader, hash[:], crypto.SHA256); err == nil {
		t.Error("Sign after Destroy succeeded")
	}
}
