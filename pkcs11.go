//go:build linux

// Package pkcs11 provides a CGO-free Go binding to the PKCS#11 cryptographic
// token interface standard (v2.40). It uses github.com/ebitengine/purego to
// load and call functions from PKCS#11 shared libraries at runtime.
//
// This package is API-compatible with github.com/miekg/pkcs11.
package pkcs11

import (
	"runtime"
	"unsafe"

	"github.com/ebitengine/purego"
)

// Ctx is the main PKCS#11 context. It holds a loaded PKCS#11 module and
// provides methods to call all PKCS#11 functions.
type Ctx struct {
	fl *functionList
}

// New loads the PKCS#11 shared library at the given path and returns a Ctx.
// Returns nil if the module cannot be loaded.
func New(module string) *Ctx {
	fl, err := loadModule(module)
	if err != nil {
		return nil
	}
	return &Ctx{fl: fl}
}

// Destroy releases the PKCS#11 module.
func (c *Ctx) Destroy() {
	if c.fl != nil {
		c.fl.close()
		c.fl = nil
	}
}

// Initialize calls C_Initialize to initialize the PKCS#11 library.
func (c *Ctx) Initialize(opts ...InitializeOption) error {
	args := initializeArgs{flags: CKF_OS_LOCKING_OK}
	for _, opt := range opts {
		opt(&args)
	}

	// CK_C_INITIALIZE_ARGS layout:
	//   CreateMutex   func ptr (8)
	//   DestroyMutex  func ptr (8)
	//   LockMutex     func ptr (8)
	//   UnlockMutex   func ptr (8)
	//   flags         CK_FLAGS (8)
	//   pReserved     CK_VOID_PTR (8)
	var cArgs [48]byte
	*(*uintptr)(unsafe.Pointer(&cArgs[32])) = uintptr(args.flags)
	if args.reserved != nil {
		*(*uintptr)(unsafe.Pointer(&cArgs[40])) = uintptr(args.reserved)
	}

	var pinner runtime.Pinner
	pinner.Pin(&cArgs[0])
	defer pinner.Unpin()

	rv, _, _ := purego.SyscallN(c.fl.C_Initialize, uintptr(unsafe.Pointer(&cArgs[0])))
	return toError(rv)
}

// Finalize calls C_Finalize to shut down the PKCS#11 library.
func (c *Ctx) Finalize() error {
	rv, _, _ := purego.SyscallN(c.fl.C_Finalize, 0)
	return toError(rv)
}

// GetInfo calls C_GetInfo and returns general library information.
func (c *Ctx) GetInfo() (Info, error) {
	// CK_INFO layout (64-bit Linux):
	//   offset 0:  cryptokiVersion CK_VERSION (2 bytes)
	//   offset 2:  manufacturerID CK_UTF8CHAR[32] (byte-aligned, no padding)
	//   offset 34: padding (6 bytes to align CK_FLAGS to 8)
	//   offset 40: flags CK_FLAGS (CK_ULONG = 8 bytes)
	//   offset 48: libraryDescription CK_UTF8CHAR[32]
	//   offset 80: libraryVersion CK_VERSION (2 bytes)
	//   offset 82: padding (6 bytes for struct alignment)
	//   Total: 88 bytes
	var buf [88]byte
	var pinner runtime.Pinner
	pinner.Pin(&buf[0])
	defer pinner.Unpin()

	rv, _, _ := purego.SyscallN(c.fl.C_GetInfo, uintptr(unsafe.Pointer(&buf[0])))
	if err := toError(rv); err != nil {
		return Info{}, err
	}

	return Info{
		CryptokiVersion:    Version{Major: buf[0], Minor: buf[1]},
		ManufacturerID:     trimPaddedString(buf[2:34]),
		Flags:              uint(*(*uintptr)(unsafe.Pointer(&buf[40]))),
		LibraryDescription: trimPaddedString(buf[48:80]),
		LibraryVersion:     Version{Major: buf[80], Minor: buf[81]},
	}, nil
}

// GetSlotList calls C_GetSlotList and returns available slot IDs.
func (c *Ctx) GetSlotList(tokenPresent bool) ([]uint, error) {
	var present uintptr
	if tokenPresent {
		present = 1
	}

	// First call: get count.
	var count uintptr
	var pinner runtime.Pinner
	pinner.Pin(&count)
	rv, _, _ := purego.SyscallN(c.fl.C_GetSlotList, present, 0, uintptr(unsafe.Pointer(&count)))
	pinner.Unpin()
	if err := toError(rv); err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, nil
	}

	// Second call: get slot IDs.
	slots := make([]uintptr, count)
	pinner.Pin(&slots[0])
	pinner.Pin(&count)
	rv, _, _ = purego.SyscallN(c.fl.C_GetSlotList, present, uintptr(unsafe.Pointer(&slots[0])), uintptr(unsafe.Pointer(&count)))
	pinner.Unpin()
	if err := toError(rv); err != nil {
		return nil, err
	}

	result := make([]uint, count)
	for i := range count {
		result[i] = uint(slots[i])
	}
	return result, nil
}

// GetSlotInfo calls C_GetSlotInfo for the given slot.
func (c *Ctx) GetSlotInfo(slotID uint) (SlotInfo, error) {
	// CK_SLOT_INFO layout:
	//   slotDescription CK_UTF8CHAR[64]
	//   manufacturerID  CK_UTF8CHAR[32]
	//   flags           CK_FLAGS (8)
	//   hardwareVersion CK_VERSION (2)
	//   pad (6)
	//   firmwareVersion CK_VERSION (2)
	//   pad (6)
	var buf [128]byte
	var pinner runtime.Pinner
	pinner.Pin(&buf[0])
	defer pinner.Unpin()

	rv, _, _ := purego.SyscallN(c.fl.C_GetSlotInfo, uintptr(slotID), uintptr(unsafe.Pointer(&buf[0])))
	if err := toError(rv); err != nil {
		return SlotInfo{}, err
	}

	return SlotInfo{
		SlotDescription: trimPaddedString(buf[0:64]),
		ManufacturerID:  trimPaddedString(buf[64:96]),
		Flags:           uint(*(*uintptr)(unsafe.Pointer(&buf[96]))),
		HardwareVersion: Version{Major: buf[104], Minor: buf[105]},
		FirmwareVersion: Version{Major: buf[106], Minor: buf[107]},
	}, nil
}

// GetTokenInfo calls C_GetTokenInfo for the given slot.
func (c *Ctx) GetTokenInfo(slotID uint) (TokenInfo, error) {
	// CK_TOKEN_INFO layout (64-bit):
	//   label[32], manufacturerID[32], model[16], serialNumber[16]
	//   flags(8)
	//   ulMaxSessionCount(8), ulSessionCount(8), ulMaxRwSessionCount(8), ulRwSessionCount(8)
	//   ulMaxPinLen(8), ulMinPinLen(8)
	//   ulTotalPublicMemory(8), ulFreePublicMemory(8)
	//   ulTotalPrivateMemory(8), ulFreePrivateMemory(8)
	//   hardwareVersion(2), firmwareVersion(2)
	//   utcTime[16]
	var buf [256]byte
	var pinner runtime.Pinner
	pinner.Pin(&buf[0])
	defer pinner.Unpin()

	rv, _, _ := purego.SyscallN(c.fl.C_GetTokenInfo, uintptr(slotID), uintptr(unsafe.Pointer(&buf[0])))
	if err := toError(rv); err != nil {
		return TokenInfo{}, err
	}

	off := 96 // after label(32)+mfr(32)+model(16)+serial(16)
	return TokenInfo{
		Label:              trimPaddedString(buf[0:32]),
		ManufacturerID:     trimPaddedString(buf[32:64]),
		Model:              trimPaddedString(buf[64:80]),
		SerialNumber:       trimPaddedString(buf[80:96]),
		Flags:              readUintptr(buf[:], off),
		MaxSessionCount:    readUintptr(buf[:], off+8),
		SessionCount:       readUintptr(buf[:], off+16),
		MaxRwSessionCount:  readUintptr(buf[:], off+24),
		RwSessionCount:     readUintptr(buf[:], off+32),
		MaxPinLen:          readUintptr(buf[:], off+40),
		MinPinLen:          readUintptr(buf[:], off+48),
		TotalPublicMemory:  readUintptr(buf[:], off+56),
		FreePublicMemory:   readUintptr(buf[:], off+64),
		TotalPrivateMemory: readUintptr(buf[:], off+72),
		FreePrivateMemory:  readUintptr(buf[:], off+80),
		HardwareVersion:    Version{Major: buf[off+88], Minor: buf[off+89]},
		FirmwareVersion:    Version{Major: buf[off+90], Minor: buf[off+91]},
		UTCTime:            trimPaddedString(buf[off+92 : off+108]),
	}, nil
}

func readUintptr(buf []byte, off int) uint {
	return uint(*(*uintptr)(unsafe.Pointer(&buf[off])))
}

// GetMechanismList calls C_GetMechanismList for the given slot.
func (c *Ctx) GetMechanismList(slotID uint) ([]*Mechanism, error) {
	var count uintptr
	var pinner runtime.Pinner
	pinner.Pin(&count)
	rv, _, _ := purego.SyscallN(c.fl.C_GetMechanismList, uintptr(slotID), 0, uintptr(unsafe.Pointer(&count)))
	pinner.Unpin()
	if err := toError(rv); err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, nil
	}

	mechs := make([]uintptr, count)
	pinner.Pin(&mechs[0])
	pinner.Pin(&count)
	rv, _, _ = purego.SyscallN(c.fl.C_GetMechanismList, uintptr(slotID), uintptr(unsafe.Pointer(&mechs[0])), uintptr(unsafe.Pointer(&count)))
	pinner.Unpin()
	if err := toError(rv); err != nil {
		return nil, err
	}

	result := make([]*Mechanism, count)
	for i := range count {
		result[i] = &Mechanism{Mechanism: uint(mechs[i])}
	}
	return result, nil
}

// GetMechanismInfo calls C_GetMechanismInfo for the given slot and mechanism.
func (c *Ctx) GetMechanismInfo(slotID uint, m []*Mechanism) (MechanismInfo, error) {
	if len(m) == 0 {
		return MechanismInfo{}, Error(CKR_ARGUMENTS_BAD)
	}
	// CK_MECHANISM_INFO: ulMinKeySize(8) + ulMaxKeySize(8) + flags(8) = 24
	var buf [24]byte
	var pinner runtime.Pinner
	pinner.Pin(&buf[0])
	defer pinner.Unpin()

	rv, _, _ := purego.SyscallN(c.fl.C_GetMechanismInfo, uintptr(slotID), uintptr(m[0].Mechanism), uintptr(unsafe.Pointer(&buf[0])))
	if err := toError(rv); err != nil {
		return MechanismInfo{}, err
	}
	return MechanismInfo{
		MinKeySize: uint(*(*uintptr)(unsafe.Pointer(&buf[0]))),
		MaxKeySize: uint(*(*uintptr)(unsafe.Pointer(&buf[8]))),
		Flags:      uint(*(*uintptr)(unsafe.Pointer(&buf[16]))),
	}, nil
}

// InitToken calls C_InitToken.
func (c *Ctx) InitToken(slotID uint, pin, label string) error {
	pinBytes := []byte(pin)
	var pPin uintptr
	var pinner runtime.Pinner
	if len(pinBytes) > 0 {
		pinner.Pin(&pinBytes[0])
		pPin = uintptr(unsafe.Pointer(&pinBytes[0]))
	}
	labelBytes := padString(label, 32)
	pinner.Pin(&labelBytes[0])
	defer pinner.Unpin()

	rv, _, _ := purego.SyscallN(c.fl.C_InitToken, uintptr(slotID), pPin, uintptr(len(pinBytes)), uintptr(unsafe.Pointer(&labelBytes[0])))
	return toError(rv)
}

// InitPIN calls C_InitPIN.
func (c *Ctx) InitPIN(sh SessionHandle, pin string) error {
	pinBytes := []byte(pin)
	var pPin uintptr
	var pinner runtime.Pinner
	if len(pinBytes) > 0 {
		pinner.Pin(&pinBytes[0])
		pPin = uintptr(unsafe.Pointer(&pinBytes[0]))
	}
	defer pinner.Unpin()

	rv, _, _ := purego.SyscallN(c.fl.C_InitPIN, uintptr(sh), pPin, uintptr(len(pinBytes)))
	return toError(rv)
}

// SetPIN calls C_SetPIN.
func (c *Ctx) SetPIN(sh SessionHandle, oldpin, newpin string) error {
	oldBytes := []byte(oldpin)
	newBytes := []byte(newpin)
	var pOld, pNew uintptr
	var pinner runtime.Pinner
	if len(oldBytes) > 0 {
		pinner.Pin(&oldBytes[0])
		pOld = uintptr(unsafe.Pointer(&oldBytes[0]))
	}
	if len(newBytes) > 0 {
		pinner.Pin(&newBytes[0])
		pNew = uintptr(unsafe.Pointer(&newBytes[0]))
	}
	defer pinner.Unpin()

	rv, _, _ := purego.SyscallN(c.fl.C_SetPIN, uintptr(sh), pOld, uintptr(len(oldBytes)), pNew, uintptr(len(newBytes)))
	return toError(rv)
}

// OpenSession calls C_OpenSession.
func (c *Ctx) OpenSession(slotID, flags uint) (SessionHandle, error) {
	var sh uintptr
	var pinner runtime.Pinner
	pinner.Pin(&sh)
	defer pinner.Unpin()

	rv, _, _ := purego.SyscallN(c.fl.C_OpenSession, uintptr(slotID), uintptr(flags), 0, 0, uintptr(unsafe.Pointer(&sh)))
	if err := toError(rv); err != nil {
		return 0, err
	}
	return SessionHandle(sh), nil
}

// CloseSession calls C_CloseSession.
func (c *Ctx) CloseSession(sh SessionHandle) error {
	rv, _, _ := purego.SyscallN(c.fl.C_CloseSession, uintptr(sh))
	return toError(rv)
}

// CloseAllSessions calls C_CloseAllSessions for a slot.
func (c *Ctx) CloseAllSessions(slotID uint) error {
	rv, _, _ := purego.SyscallN(c.fl.C_CloseAllSessions, uintptr(slotID))
	return toError(rv)
}

// GetSessionInfo calls C_GetSessionInfo.
func (c *Ctx) GetSessionInfo(sh SessionHandle) (SessionInfo, error) {
	// CK_SESSION_INFO: slotID(8) + state(8) + flags(8) + deviceError(8) = 32
	var buf [32]byte
	var pinner runtime.Pinner
	pinner.Pin(&buf[0])
	defer pinner.Unpin()

	rv, _, _ := purego.SyscallN(c.fl.C_GetSessionInfo, uintptr(sh), uintptr(unsafe.Pointer(&buf[0])))
	if err := toError(rv); err != nil {
		return SessionInfo{}, err
	}
	return SessionInfo{
		SlotID:      uint(*(*uintptr)(unsafe.Pointer(&buf[0]))),
		State:       uint(*(*uintptr)(unsafe.Pointer(&buf[8]))),
		Flags:       uint(*(*uintptr)(unsafe.Pointer(&buf[16]))),
		DeviceError: uint(*(*uintptr)(unsafe.Pointer(&buf[24]))),
	}, nil
}

// GetOperationState calls C_GetOperationState.
func (c *Ctx) GetOperationState(sh SessionHandle) ([]byte, error) {
	var length uintptr
	var pinner runtime.Pinner
	pinner.Pin(&length)
	rv, _, _ := purego.SyscallN(c.fl.C_GetOperationState, uintptr(sh), 0, uintptr(unsafe.Pointer(&length)))
	pinner.Unpin()
	if err := toError(rv); err != nil {
		return nil, err
	}

	state := make([]byte, length)
	pinner.Pin(&state[0])
	pinner.Pin(&length)
	rv, _, _ = purego.SyscallN(c.fl.C_GetOperationState, uintptr(sh), uintptr(unsafe.Pointer(&state[0])), uintptr(unsafe.Pointer(&length)))
	pinner.Unpin()
	if err := toError(rv); err != nil {
		return nil, err
	}
	return state[:length], nil
}

// SetOperationState calls C_SetOperationState.
func (c *Ctx) SetOperationState(sh SessionHandle, state []byte, encryptKey, authKey ObjectHandle) error {
	var pState uintptr
	var pinner runtime.Pinner
	if len(state) > 0 {
		pinner.Pin(&state[0])
		pState = uintptr(unsafe.Pointer(&state[0]))
	}
	defer pinner.Unpin()

	rv, _, _ := purego.SyscallN(c.fl.C_SetOperationState, uintptr(sh), pState, uintptr(len(state)), uintptr(encryptKey), uintptr(authKey))
	return toError(rv)
}

// Login calls C_Login.
func (c *Ctx) Login(sh SessionHandle, userType uint, pin string) error {
	pinBytes := []byte(pin)
	var pPin uintptr
	var pinner runtime.Pinner
	if len(pinBytes) > 0 {
		pinner.Pin(&pinBytes[0])
		pPin = uintptr(unsafe.Pointer(&pinBytes[0]))
	}
	defer pinner.Unpin()

	rv, _, _ := purego.SyscallN(c.fl.C_Login, uintptr(sh), uintptr(userType), pPin, uintptr(len(pinBytes)))
	return toError(rv)
}

// Logout calls C_Logout.
func (c *Ctx) Logout(sh SessionHandle) error {
	rv, _, _ := purego.SyscallN(c.fl.C_Logout, uintptr(sh))
	return toError(rv)
}

// CreateObject calls C_CreateObject.
func (c *Ctx) CreateObject(sh SessionHandle, temp []*Attribute) (ObjectHandle, error) {
	var a arena
	defer a.free()

	attrPtr, attrLen := a.marshalAttributes(temp)
	var obj uintptr
	a.pinner.Pin(&obj)

	rv, _, _ := purego.SyscallN(c.fl.C_CreateObject, uintptr(sh), attrPtr, attrLen, uintptr(unsafe.Pointer(&obj)))
	if err := toError(rv); err != nil {
		return 0, err
	}
	return ObjectHandle(obj), nil
}

// CopyObject calls C_CopyObject.
func (c *Ctx) CopyObject(sh SessionHandle, o ObjectHandle, temp []*Attribute) (ObjectHandle, error) {
	var a arena
	defer a.free()

	attrPtr, attrLen := a.marshalAttributes(temp)
	var obj uintptr
	a.pinner.Pin(&obj)

	rv, _, _ := purego.SyscallN(c.fl.C_CopyObject, uintptr(sh), uintptr(o), attrPtr, attrLen, uintptr(unsafe.Pointer(&obj)))
	if err := toError(rv); err != nil {
		return 0, err
	}
	return ObjectHandle(obj), nil
}

// DestroyObject calls C_DestroyObject.
func (c *Ctx) DestroyObject(sh SessionHandle, oh ObjectHandle) error {
	rv, _, _ := purego.SyscallN(c.fl.C_DestroyObject, uintptr(sh), uintptr(oh))
	return toError(rv)
}

// GetObjectSize calls C_GetObjectSize.
func (c *Ctx) GetObjectSize(sh SessionHandle, oh ObjectHandle) (uint, error) {
	var size uintptr
	var pinner runtime.Pinner
	pinner.Pin(&size)
	defer pinner.Unpin()

	rv, _, _ := purego.SyscallN(c.fl.C_GetObjectSize, uintptr(sh), uintptr(oh), uintptr(unsafe.Pointer(&size)))
	if err := toError(rv); err != nil {
		return 0, err
	}
	return uint(size), nil
}

// GetAttributeValue calls C_GetAttributeValue using a two-pass approach:
// first to get sizes, then to read values.
func (c *Ctx) GetAttributeValue(sh SessionHandle, o ObjectHandle, a []*Attribute) ([]*Attribute, error) {
	var ar arena
	defer ar.free()

	// First pass: query sizes.
	queryPtr, queryLen, queryBuf := ar.marshalAttributesForQuery(a)
	rv, _, _ := purego.SyscallN(c.fl.C_GetAttributeValue, uintptr(sh), uintptr(o), queryPtr, queryLen)
	if err := toError(rv); err != nil {
		return nil, err
	}

	sizes := querySizes(queryBuf, len(a))

	// Second pass: allocate buffers and read values.
	var ar2 arena
	defer ar2.free()
	attrPtr, attrLen, attrBuf, _ := ar2.marshalAttributesWithBuffers(a, sizes)
	rv, _, _ = purego.SyscallN(c.fl.C_GetAttributeValue, uintptr(sh), uintptr(o), attrPtr, attrLen)
	if err := toError(rv); err != nil {
		return nil, err
	}

	return unmarshalAttributes(attrBuf, len(a)), nil
}

// SetAttributeValue calls C_SetAttributeValue.
func (c *Ctx) SetAttributeValue(sh SessionHandle, o ObjectHandle, a []*Attribute) error {
	var ar arena
	defer ar.free()

	attrPtr, attrLen := ar.marshalAttributes(a)
	rv, _, _ := purego.SyscallN(c.fl.C_SetAttributeValue, uintptr(sh), uintptr(o), attrPtr, attrLen)
	return toError(rv)
}

// FindObjectsInit calls C_FindObjectsInit.
func (c *Ctx) FindObjectsInit(sh SessionHandle, temp []*Attribute) error {
	var a arena
	defer a.free()

	attrPtr, attrLen := a.marshalAttributes(temp)
	rv, _, _ := purego.SyscallN(c.fl.C_FindObjectsInit, uintptr(sh), attrPtr, attrLen)
	return toError(rv)
}

// FindObjects calls C_FindObjects and returns up to maxObjects objects.
func (c *Ctx) FindObjects(sh SessionHandle, maxObjects int) ([]ObjectHandle, bool, error) {
	objs := make([]uintptr, maxObjects)
	var count uintptr
	var pinner runtime.Pinner
	pinner.Pin(&objs[0])
	pinner.Pin(&count)
	defer pinner.Unpin()

	rv, _, _ := purego.SyscallN(c.fl.C_FindObjects, uintptr(sh), uintptr(unsafe.Pointer(&objs[0])), uintptr(maxObjects), uintptr(unsafe.Pointer(&count)))
	if err := toError(rv); err != nil {
		return nil, false, err
	}

	result := make([]ObjectHandle, count)
	for i := range count {
		result[i] = ObjectHandle(objs[i])
	}
	return result, count > 0, nil
}

// FindObjectsFinal calls C_FindObjectsFinal.
func (c *Ctx) FindObjectsFinal(sh SessionHandle) error {
	rv, _, _ := purego.SyscallN(c.fl.C_FindObjectsFinal, uintptr(sh))
	return toError(rv)
}

// EncryptInit calls C_EncryptInit.
func (c *Ctx) EncryptInit(sh SessionHandle, m []*Mechanism, o ObjectHandle) error {
	var a arena
	defer a.free()
	mechPtr := a.marshalMechanism(m)
	rv, _, _ := purego.SyscallN(c.fl.C_EncryptInit, uintptr(sh), mechPtr, uintptr(o))
	return toError(rv)
}

// Encrypt calls C_Encrypt using a two-pass approach.
func (c *Ctx) Encrypt(sh SessionHandle, message []byte) ([]byte, error) {
	return c.twoPassOutput(c.fl.C_Encrypt, uintptr(sh), message)
}

// EncryptUpdate calls C_EncryptUpdate.
func (c *Ctx) EncryptUpdate(sh SessionHandle, plain []byte) ([]byte, error) {
	return c.updateOutput(c.fl.C_EncryptUpdate, uintptr(sh), plain)
}

// EncryptFinal calls C_EncryptFinal.
func (c *Ctx) EncryptFinal(sh SessionHandle) ([]byte, error) {
	return c.finalOutput(c.fl.C_EncryptFinal, uintptr(sh))
}

// DecryptInit calls C_DecryptInit.
func (c *Ctx) DecryptInit(sh SessionHandle, m []*Mechanism, o ObjectHandle) error {
	var a arena
	defer a.free()
	mechPtr := a.marshalMechanism(m)
	rv, _, _ := purego.SyscallN(c.fl.C_DecryptInit, uintptr(sh), mechPtr, uintptr(o))
	return toError(rv)
}

// Decrypt calls C_Decrypt using a two-pass approach.
func (c *Ctx) Decrypt(sh SessionHandle, cipher []byte) ([]byte, error) {
	return c.twoPassOutput(c.fl.C_Decrypt, uintptr(sh), cipher)
}

// DecryptUpdate calls C_DecryptUpdate.
func (c *Ctx) DecryptUpdate(sh SessionHandle, cipher []byte) ([]byte, error) {
	return c.updateOutput(c.fl.C_DecryptUpdate, uintptr(sh), cipher)
}

// DecryptFinal calls C_DecryptFinal.
func (c *Ctx) DecryptFinal(sh SessionHandle) ([]byte, error) {
	return c.finalOutput(c.fl.C_DecryptFinal, uintptr(sh))
}

// DigestInit calls C_DigestInit.
func (c *Ctx) DigestInit(sh SessionHandle, m []*Mechanism) error {
	var a arena
	defer a.free()
	mechPtr := a.marshalMechanism(m)
	rv, _, _ := purego.SyscallN(c.fl.C_DigestInit, uintptr(sh), mechPtr)
	return toError(rv)
}

// Digest calls C_Digest using a two-pass approach.
func (c *Ctx) Digest(sh SessionHandle, message []byte) ([]byte, error) {
	return c.twoPassOutput(c.fl.C_Digest, uintptr(sh), message)
}

// DigestUpdate calls C_DigestUpdate.
func (c *Ctx) DigestUpdate(sh SessionHandle, message []byte) error {
	var pinner runtime.Pinner
	var pMsg uintptr
	if len(message) > 0 {
		pinner.Pin(&message[0])
		pMsg = uintptr(unsafe.Pointer(&message[0]))
	}
	defer pinner.Unpin()

	rv, _, _ := purego.SyscallN(c.fl.C_DigestUpdate, uintptr(sh), pMsg, uintptr(len(message)))
	return toError(rv)
}

// DigestKey calls C_DigestKey.
func (c *Ctx) DigestKey(sh SessionHandle, key ObjectHandle) error {
	rv, _, _ := purego.SyscallN(c.fl.C_DigestKey, uintptr(sh), uintptr(key))
	return toError(rv)
}

// DigestFinal calls C_DigestFinal.
func (c *Ctx) DigestFinal(sh SessionHandle) ([]byte, error) {
	return c.twoPassOutputNoInput(c.fl.C_DigestFinal, uintptr(sh))
}

// SignInit calls C_SignInit.
func (c *Ctx) SignInit(sh SessionHandle, m []*Mechanism, o ObjectHandle) error {
	var a arena
	defer a.free()
	mechPtr := a.marshalMechanism(m)
	rv, _, _ := purego.SyscallN(c.fl.C_SignInit, uintptr(sh), mechPtr, uintptr(o))
	return toError(rv)
}

// Sign calls C_Sign using a two-pass approach.
func (c *Ctx) Sign(sh SessionHandle, message []byte) ([]byte, error) {
	return c.twoPassOutput(c.fl.C_Sign, uintptr(sh), message)
}

// SignUpdate calls C_SignUpdate.
func (c *Ctx) SignUpdate(sh SessionHandle, message []byte) error {
	var pinner runtime.Pinner
	var pMsg uintptr
	if len(message) > 0 {
		pinner.Pin(&message[0])
		pMsg = uintptr(unsafe.Pointer(&message[0]))
	}
	defer pinner.Unpin()

	rv, _, _ := purego.SyscallN(c.fl.C_SignUpdate, uintptr(sh), pMsg, uintptr(len(message)))
	return toError(rv)
}

// SignFinal calls C_SignFinal.
func (c *Ctx) SignFinal(sh SessionHandle) ([]byte, error) {
	return c.twoPassOutputNoInput(c.fl.C_SignFinal, uintptr(sh))
}

// SignRecoverInit calls C_SignRecoverInit.
func (c *Ctx) SignRecoverInit(sh SessionHandle, m []*Mechanism, key ObjectHandle) error {
	var a arena
	defer a.free()
	mechPtr := a.marshalMechanism(m)
	rv, _, _ := purego.SyscallN(c.fl.C_SignRecoverInit, uintptr(sh), mechPtr, uintptr(key))
	return toError(rv)
}

// SignRecover calls C_SignRecover.
func (c *Ctx) SignRecover(sh SessionHandle, data []byte) ([]byte, error) {
	return c.twoPassOutput(c.fl.C_SignRecover, uintptr(sh), data)
}

// VerifyInit calls C_VerifyInit.
func (c *Ctx) VerifyInit(sh SessionHandle, m []*Mechanism, key ObjectHandle) error {
	var a arena
	defer a.free()
	mechPtr := a.marshalMechanism(m)
	rv, _, _ := purego.SyscallN(c.fl.C_VerifyInit, uintptr(sh), mechPtr, uintptr(key))
	return toError(rv)
}

// Verify calls C_Verify.
func (c *Ctx) Verify(sh SessionHandle, data, signature []byte) error {
	var pinner runtime.Pinner
	var pData, pSig uintptr
	if len(data) > 0 {
		pinner.Pin(&data[0])
		pData = uintptr(unsafe.Pointer(&data[0]))
	}
	if len(signature) > 0 {
		pinner.Pin(&signature[0])
		pSig = uintptr(unsafe.Pointer(&signature[0]))
	}
	defer pinner.Unpin()

	rv, _, _ := purego.SyscallN(c.fl.C_Verify, uintptr(sh), pData, uintptr(len(data)), pSig, uintptr(len(signature)))
	return toError(rv)
}

// VerifyUpdate calls C_VerifyUpdate.
func (c *Ctx) VerifyUpdate(sh SessionHandle, part []byte) error {
	var pinner runtime.Pinner
	var pPart uintptr
	if len(part) > 0 {
		pinner.Pin(&part[0])
		pPart = uintptr(unsafe.Pointer(&part[0]))
	}
	defer pinner.Unpin()

	rv, _, _ := purego.SyscallN(c.fl.C_VerifyUpdate, uintptr(sh), pPart, uintptr(len(part)))
	return toError(rv)
}

// VerifyFinal calls C_VerifyFinal.
func (c *Ctx) VerifyFinal(sh SessionHandle, signature []byte) error {
	var pinner runtime.Pinner
	var pSig uintptr
	if len(signature) > 0 {
		pinner.Pin(&signature[0])
		pSig = uintptr(unsafe.Pointer(&signature[0]))
	}
	defer pinner.Unpin()

	rv, _, _ := purego.SyscallN(c.fl.C_VerifyFinal, uintptr(sh), pSig, uintptr(len(signature)))
	return toError(rv)
}

// VerifyRecoverInit calls C_VerifyRecoverInit.
func (c *Ctx) VerifyRecoverInit(sh SessionHandle, m []*Mechanism, key ObjectHandle) error {
	var a arena
	defer a.free()
	mechPtr := a.marshalMechanism(m)
	rv, _, _ := purego.SyscallN(c.fl.C_VerifyRecoverInit, uintptr(sh), mechPtr, uintptr(key))
	return toError(rv)
}

// VerifyRecover calls C_VerifyRecover.
func (c *Ctx) VerifyRecover(sh SessionHandle, signature []byte) ([]byte, error) {
	return c.twoPassOutput(c.fl.C_VerifyRecover, uintptr(sh), signature)
}

// DigestEncryptUpdate calls C_DigestEncryptUpdate.
func (c *Ctx) DigestEncryptUpdate(sh SessionHandle, part []byte) ([]byte, error) {
	return c.twoPassOutput(c.fl.C_DigestEncryptUpdate, uintptr(sh), part)
}

// DecryptDigestUpdate calls C_DecryptDigestUpdate.
func (c *Ctx) DecryptDigestUpdate(sh SessionHandle, cipher []byte) ([]byte, error) {
	return c.twoPassOutput(c.fl.C_DecryptDigestUpdate, uintptr(sh), cipher)
}

// SignEncryptUpdate calls C_SignEncryptUpdate.
func (c *Ctx) SignEncryptUpdate(sh SessionHandle, part []byte) ([]byte, error) {
	return c.twoPassOutput(c.fl.C_SignEncryptUpdate, uintptr(sh), part)
}

// DecryptVerifyUpdate calls C_DecryptVerifyUpdate.
func (c *Ctx) DecryptVerifyUpdate(sh SessionHandle, cipher []byte) ([]byte, error) {
	return c.twoPassOutput(c.fl.C_DecryptVerifyUpdate, uintptr(sh), cipher)
}

// GenerateKey calls C_GenerateKey.
func (c *Ctx) GenerateKey(sh SessionHandle, m []*Mechanism, temp []*Attribute) (ObjectHandle, error) {
	var a arena
	defer a.free()

	mechPtr := a.marshalMechanism(m)
	attrPtr, attrLen := a.marshalAttributes(temp)
	var key uintptr
	a.pinner.Pin(&key)

	rv, _, _ := purego.SyscallN(c.fl.C_GenerateKey, uintptr(sh), mechPtr, attrPtr, attrLen, uintptr(unsafe.Pointer(&key)))
	if err := toError(rv); err != nil {
		return 0, err
	}
	return ObjectHandle(key), nil
}

// GenerateKeyPair calls C_GenerateKeyPair.
func (c *Ctx) GenerateKeyPair(sh SessionHandle, m []*Mechanism, public, private []*Attribute) (ObjectHandle, ObjectHandle, error) {
	var a arena
	defer a.free()

	mechPtr := a.marshalMechanism(m)
	pubPtr, pubLen := a.marshalAttributes(public)
	privPtr, privLen := a.marshalAttributes(private)

	var pubKey, privKey uintptr
	a.pinner.Pin(&pubKey)
	a.pinner.Pin(&privKey)

	rv, _, _ := purego.SyscallN(c.fl.C_GenerateKeyPair, uintptr(sh), mechPtr, pubPtr, pubLen, privPtr, privLen, uintptr(unsafe.Pointer(&pubKey)), uintptr(unsafe.Pointer(&privKey)))
	if err := toError(rv); err != nil {
		return 0, 0, err
	}
	return ObjectHandle(pubKey), ObjectHandle(privKey), nil
}

// WrapKey calls C_WrapKey.
func (c *Ctx) WrapKey(sh SessionHandle, m []*Mechanism, wrappingkey, key ObjectHandle) ([]byte, error) {
	var a arena
	defer a.free()

	mechPtr := a.marshalMechanism(m)

	// First pass: get size.
	var length uintptr
	a.pinner.Pin(&length)
	rv, _, _ := purego.SyscallN(c.fl.C_WrapKey, uintptr(sh), mechPtr, uintptr(wrappingkey), uintptr(key), 0, uintptr(unsafe.Pointer(&length)))
	if err := toError(rv); err != nil {
		return nil, err
	}

	// Second pass: get data.
	out := make([]byte, length)
	a.pinner.Pin(&out[0])
	rv, _, _ = purego.SyscallN(c.fl.C_WrapKey, uintptr(sh), mechPtr, uintptr(wrappingkey), uintptr(key), uintptr(unsafe.Pointer(&out[0])), uintptr(unsafe.Pointer(&length)))
	if err := toError(rv); err != nil {
		return nil, err
	}
	return out[:length], nil
}

// UnwrapKey calls C_UnwrapKey.
func (c *Ctx) UnwrapKey(sh SessionHandle, m []*Mechanism, unwrappingkey ObjectHandle, wrappedkey []byte, a2 []*Attribute) (ObjectHandle, error) {
	var a arena
	defer a.free()

	mechPtr := a.marshalMechanism(m)
	attrPtr, attrLen := a.marshalAttributes(a2)

	var pWrap uintptr
	if len(wrappedkey) > 0 {
		a.pinner.Pin(&wrappedkey[0])
		pWrap = uintptr(unsafe.Pointer(&wrappedkey[0]))
	}

	var key uintptr
	a.pinner.Pin(&key)

	rv, _, _ := purego.SyscallN(c.fl.C_UnwrapKey, uintptr(sh), mechPtr, uintptr(unwrappingkey), pWrap, uintptr(len(wrappedkey)), attrPtr, attrLen, uintptr(unsafe.Pointer(&key)))
	if err := toError(rv); err != nil {
		return 0, err
	}
	return ObjectHandle(key), nil
}

// DeriveKey calls C_DeriveKey.
func (c *Ctx) DeriveKey(sh SessionHandle, m []*Mechanism, basekey ObjectHandle, a2 []*Attribute) (ObjectHandle, error) {
	var a arena
	defer a.free()

	mechPtr := a.marshalMechanism(m)
	attrPtr, attrLen := a.marshalAttributes(a2)

	var key uintptr
	a.pinner.Pin(&key)

	rv, _, _ := purego.SyscallN(c.fl.C_DeriveKey, uintptr(sh), mechPtr, uintptr(basekey), attrPtr, attrLen, uintptr(unsafe.Pointer(&key)))
	if err := toError(rv); err != nil {
		return 0, err
	}
	return ObjectHandle(key), nil
}

// SeedRandom calls C_SeedRandom.
func (c *Ctx) SeedRandom(sh SessionHandle, seed []byte) error {
	var pinner runtime.Pinner
	var pSeed uintptr
	if len(seed) > 0 {
		pinner.Pin(&seed[0])
		pSeed = uintptr(unsafe.Pointer(&seed[0]))
	}
	defer pinner.Unpin()

	rv, _, _ := purego.SyscallN(c.fl.C_SeedRandom, uintptr(sh), pSeed, uintptr(len(seed)))
	return toError(rv)
}

// GenerateRandom calls C_GenerateRandom.
func (c *Ctx) GenerateRandom(sh SessionHandle, length int) ([]byte, error) {
	buf := make([]byte, length)
	var pinner runtime.Pinner
	pinner.Pin(&buf[0])
	defer pinner.Unpin()

	rv, _, _ := purego.SyscallN(c.fl.C_GenerateRandom, uintptr(sh), uintptr(unsafe.Pointer(&buf[0])), uintptr(length))
	if err := toError(rv); err != nil {
		return nil, err
	}
	return buf, nil
}

// WaitForSlotEvent calls C_WaitForSlotEvent in a goroutine and returns
// a channel that receives the event.
func (c *Ctx) WaitForSlotEvent(flags uint) chan SlotEvent {
	ch := make(chan SlotEvent, 1)
	go func() {
		var slotID uintptr
		var pinner runtime.Pinner
		pinner.Pin(&slotID)
		rv, _, _ := purego.SyscallN(c.fl.C_WaitForSlotEvent, uintptr(flags), uintptr(unsafe.Pointer(&slotID)), 0)
		pinner.Unpin()
		if toError(rv) == nil {
			ch <- SlotEvent{SlotID: uint(slotID)}
		}
		close(ch)
	}()
	return ch
}

// twoPassOutput handles the common PKCS#11 two-pass pattern for functions that
// take input data and produce output data. First call with NULL output to get
// size, then call again with allocated buffer.
func (c *Ctx) twoPassOutput(fn, sh uintptr, input []byte) ([]byte, error) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	// Some PKCS#11 implementations reject NULL pointers even with length 0.
	// Use a dummy byte to guarantee a valid pointer for empty input.
	var dummy [1]byte
	var pInput uintptr
	if len(input) > 0 {
		pinner.Pin(&input[0])
		pInput = uintptr(unsafe.Pointer(&input[0]))
	} else {
		pinner.Pin(&dummy[0])
		pInput = uintptr(unsafe.Pointer(&dummy[0]))
	}

	// First pass: get output size.
	var outLen uintptr
	pinner.Pin(&outLen)
	rv, _, _ := purego.SyscallN(fn, sh, pInput, uintptr(len(input)), 0, uintptr(unsafe.Pointer(&outLen)))
	if err := toError(rv); err != nil {
		return nil, err
	}

	// Second pass: read output.
	if outLen == 0 {
		return nil, nil
	}
	out := make([]byte, outLen)
	pinner.Pin(&out[0])
	rv, _, _ = purego.SyscallN(fn, sh, pInput, uintptr(len(input)), uintptr(unsafe.Pointer(&out[0])), uintptr(unsafe.Pointer(&outLen)))
	if err := toError(rv); err != nil {
		return nil, err
	}
	return out[:outLen], nil
}

// twoPassOutputNoInput handles the two-pass pattern for functions that produce
// output without input data (e.g., EncryptFinal, DigestFinal).
func (c *Ctx) twoPassOutputNoInput(fn, sh uintptr) ([]byte, error) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	// First pass: get output size.
	var outLen uintptr
	pinner.Pin(&outLen)
	rv, _, _ := purego.SyscallN(fn, sh, 0, uintptr(unsafe.Pointer(&outLen)))
	if err := toError(rv); err != nil {
		return nil, err
	}

	// Second pass: read output.
	if outLen == 0 {
		return nil, nil
	}
	out := make([]byte, outLen)
	pinner.Pin(&out[0])
	rv, _, _ = purego.SyscallN(fn, sh, uintptr(unsafe.Pointer(&out[0])), uintptr(unsafe.Pointer(&outLen)))
	if err := toError(rv); err != nil {
		return nil, err
	}
	return out[:outLen], nil
}

// updateOutput handles multi-part Update functions (EncryptUpdate, DecryptUpdate).
// These are NOT two-pass: the output is produced incrementally and may be empty
// if the implementation is buffering. We allocate an output buffer equal to the
// input size plus one block (to handle padding), make a single call, and return
// whatever was written.
func (c *Ctx) updateOutput(fn, sh uintptr, input []byte) ([]byte, error) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	var pInput uintptr
	if len(input) > 0 {
		pinner.Pin(&input[0])
		pInput = uintptr(unsafe.Pointer(&input[0]))
	}

	// Allocate output buffer. For block ciphers, output can be up to
	// input_len + block_size. Use input_len + 32 as a generous upper bound.
	outBufLen := len(input) + 32
	out := make([]byte, outBufLen)
	pinner.Pin(&out[0])

	outLen := uintptr(outBufLen)
	pinner.Pin(&outLen)

	rv, _, _ := purego.SyscallN(fn, sh, pInput, uintptr(len(input)), uintptr(unsafe.Pointer(&out[0])), uintptr(unsafe.Pointer(&outLen)))
	if err := toError(rv); err != nil {
		return nil, err
	}
	return out[:outLen], nil
}

// finalOutput handles multi-part Final functions (EncryptFinal, DecryptFinal).
// Similar to updateOutput but with no input data.
func (c *Ctx) finalOutput(fn, sh uintptr) ([]byte, error) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	// For Final, the output is at most one block. 256 bytes is generous.
	out := make([]byte, 256)
	pinner.Pin(&out[0])

	outLen := uintptr(256)
	pinner.Pin(&outLen)

	rv, _, _ := purego.SyscallN(fn, sh, uintptr(unsafe.Pointer(&out[0])), uintptr(unsafe.Pointer(&outLen)))
	if err := toError(rv); err != nil {
		return nil, err
	}
	return out[:outLen], nil
}

// padString pads a string with spaces to the given length.
func padString(s string, length int) []byte {
	b := make([]byte, length)
	for i := range b {
		b[i] = ' '
	}
	copy(b, s)
	return b
}
