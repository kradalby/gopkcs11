//go:build linux

package pkcs11

import (
	"encoding/binary"
	"fmt"
	"time"
	"unsafe"
)

// SessionHandle identifies a PKCS#11 session.
type SessionHandle uint

// ObjectHandle identifies a PKCS#11 object.
type ObjectHandle uint

// Version represents a PKCS#11 version number.
type Version struct {
	Major byte
	Minor byte
}

// Info holds general information about the Cryptoki library.
type Info struct {
	CryptokiVersion    Version
	ManufacturerID     string
	Flags              uint
	LibraryDescription string
	LibraryVersion     Version
}

// SlotInfo holds information about a slot.
type SlotInfo struct {
	SlotDescription string
	ManufacturerID  string
	Flags           uint
	HardwareVersion Version
	FirmwareVersion Version
}

// TokenInfo holds information about a token.
type TokenInfo struct {
	Label              string
	ManufacturerID     string
	Model              string
	SerialNumber       string
	Flags              uint
	MaxSessionCount    uint
	SessionCount       uint
	MaxRwSessionCount  uint
	RwSessionCount     uint
	MaxPinLen          uint
	MinPinLen          uint
	TotalPublicMemory  uint
	FreePublicMemory   uint
	TotalPrivateMemory uint
	FreePrivateMemory  uint
	HardwareVersion    Version
	FirmwareVersion    Version
	UTCTime            string
}

// SessionInfo holds information about a session.
type SessionInfo struct {
	SlotID      uint
	State       uint
	Flags       uint
	DeviceError uint
}

// MechanismInfo holds information about a mechanism.
type MechanismInfo struct {
	MinKeySize uint
	MaxKeySize uint
	Flags      uint
}

// SlotEvent is returned by WaitForSlotEvent.
type SlotEvent struct {
	SlotID uint
}

// Attribute represents a PKCS#11 attribute with a type and raw byte value.
type Attribute struct {
	Type  uint
	Value []byte
}

// NewAttribute creates an Attribute from various Go types.
// Supported types: bool, int, uint, uint32, uint64, string, []byte, time.Time.
func NewAttribute(typ uint, x interface{}) *Attribute {
	a := &Attribute{Type: typ}
	switch v := x.(type) {
	case bool:
		if v {
			a.Value = []byte{1}
		} else {
			a.Value = []byte{0}
		}
	case int:
		a.Value = uintToBytes(uint64(v))
	case uint:
		a.Value = uintToBytes(uint64(v))
	case uint32:
		a.Value = uintToBytes(uint64(v))
	case uint64:
		a.Value = uintToBytes(v)
	case string:
		a.Value = []byte(v)
	case []byte:
		a.Value = v
	case time.Time:
		a.Value = []byte(v.Format("20060102150405") + "00")
	default:
		panic(fmt.Sprintf("pkcs11: unsupported attribute value type %T", x))
	}
	return a
}

func uintToBytes(v uint64) []byte {
	// CK_ULONG is native-endian, pointer-sized.
	if unsafe.Sizeof(uintptr(0)) == 8 {
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, v)
		return b
	}
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(v))
	return b
}

// Mechanism represents a PKCS#11 mechanism with optional parameters.
type Mechanism struct {
	Mechanism uint
	Parameter []byte
	generator interface{}
}

// NewMechanism creates a Mechanism. The parameter x can be nil, []byte,
// *GCMParams, *OAEPParams, *ECDH1DeriveParams, or *RSAAESKeyWrapParams.
func NewMechanism(mech uint, x interface{}) *Mechanism {
	m := &Mechanism{Mechanism: mech}
	switch v := x.(type) {
	case nil:
		// no parameter
	case []byte:
		m.Parameter = v
	case *GCMParams, *OAEPParams, *ECDH1DeriveParams:
		m.generator = v
	default:
		panic(fmt.Sprintf("pkcs11: unsupported mechanism parameter type %T", x))
	}
	return m
}

// InitializeOption configures the call to C_Initialize.
type InitializeOption func(*initializeArgs)

type initializeArgs struct {
	flags    uint
	reserved unsafe.Pointer
}

// InitializeWithFlags returns an option that sets the initialization flags.
func InitializeWithFlags(flags uint) InitializeOption {
	return func(a *initializeArgs) {
		a.flags = flags
	}
}

// InitializeWithReserved returns an option that sets the pReserved field.
func InitializeWithReserved(reserved unsafe.Pointer) InitializeOption {
	return func(a *initializeArgs) {
		a.reserved = reserved
	}
}

// trimPaddedString trims trailing spaces from a fixed-width PKCS#11 string field.
func trimPaddedString(b []byte) string {
	end := len(b)
	for end > 0 && b[end-1] == ' ' {
		end--
	}
	return string(b[:end])
}
