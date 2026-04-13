//go:build linux

package pkcs11

import "fmt"

// Error represents a PKCS#11 return value (CK_RV) that indicates failure.
type Error uint

func (e Error) Error() string {
	if s, ok := strerror[uint(e)]; ok {
		return s
	}
	return fmt.Sprintf("pkcs11: 0x%08X", uint(e))
}

// toError converts a raw CK_RV return value to an error.
// Returns nil when rv == CKR_OK.
func toError(rv uintptr) error {
	if rv == CKR_OK {
		return nil
	}
	return Error(rv)
}
