//go:build linux

package pkcs11

import (
	"runtime"
	"unsafe"
)

// ckULONG is the size of CK_ULONG on the current platform.
const ckULONGSize = unsafe.Sizeof(uintptr(0))

// ckAttributeSize is the size of a CK_ATTRIBUTE struct:
//
//	CK_ATTRIBUTE_TYPE type;    (CK_ULONG = 8 bytes on 64-bit)
//	CK_VOID_PTR       pValue; (pointer  = 8 bytes on 64-bit)
//	CK_ULONG          ulValueLen; (CK_ULONG = 8 bytes on 64-bit)
const ckAttributeSize = 3 * ckULONGSize // 24 bytes on 64-bit

// ckMechanismSize is the size of a CK_MECHANISM struct:
//
//	CK_MECHANISM_TYPE mechanism;      (CK_ULONG = 8 bytes)
//	CK_VOID_PTR       pParameter;    (pointer = 8 bytes)
//	CK_ULONG          ulParameterLen; (CK_ULONG = 8 bytes)
const ckMechanismSize = 3 * ckULONGSize // 24 bytes on 64-bit

// arena manages pinned Go memory for C-compatible struct arrays passed to
// PKCS#11 functions via purego.SyscallN.
type arena struct {
	pinner runtime.Pinner
}

func (a *arena) free() {
	a.pinner.Unpin()
}

// pinNonNull pins s and returns its address for a C call. Empty slices get a
// placeholder: some modules reject NULL even with a zero length.
func pinNonNull[T any](p *runtime.Pinner, s []T) uintptr {
	if len(s) == 0 {
		s = make([]T, 1)
	}
	p.Pin(&s[0])
	return uintptr(unsafe.Pointer(&s[0]))
}

// marshalAttributes converts Go []*Attribute into a contiguous C-compatible
// CK_ATTRIBUTE array. Returns the pointer to the array and its length.
// The caller must keep the returned slices alive until after the C call.
func (a *arena) marshalAttributes(attrs []*Attribute) (uintptr, uintptr) {
	if len(attrs) == 0 {
		return 0, 0
	}

	// Allocate contiguous memory for the CK_ATTRIBUTE array.
	buf := make([]byte, len(attrs)*int(ckAttributeSize))
	a.pinner.Pin(&buf[0])

	// Keep value slices alive.
	values := make([][]byte, len(attrs))

	for i, attr := range attrs {
		off := i * int(ckAttributeSize)
		// type
		*(*uintptr)(unsafe.Pointer(&buf[off])) = uintptr(attr.Type)
		// pValue
		if len(attr.Value) > 0 {
			values[i] = attr.Value
			a.pinner.Pin(&values[i][0])
			*(*uintptr)(unsafe.Pointer(&buf[off+int(ckULONGSize)])) = uintptr(unsafe.Pointer(&values[i][0]))
		}
		// ulValueLen
		*(*uintptr)(unsafe.Pointer(&buf[off+2*int(ckULONGSize)])) = uintptr(len(attr.Value))
	}

	return uintptr(unsafe.Pointer(&buf[0])), uintptr(len(attrs))
}

// marshalAttributesForQuery creates a CK_ATTRIBUTE array where pValue is NULL
// and ulValueLen is 0, used for the first pass of C_GetAttributeValue to
// query the required buffer sizes.
func (a *arena) marshalAttributesForQuery(attrs []*Attribute) (uintptr, uintptr, []byte) {
	if len(attrs) == 0 {
		return 0, 0, nil
	}

	buf := make([]byte, len(attrs)*int(ckAttributeSize))
	a.pinner.Pin(&buf[0])

	for i, attr := range attrs {
		off := i * int(ckAttributeSize)
		*(*uintptr)(unsafe.Pointer(&buf[off])) = uintptr(attr.Type)
		// pValue = NULL (0), ulValueLen = 0 — already zero-initialized
	}

	return uintptr(unsafe.Pointer(&buf[0])), uintptr(len(attrs)), buf
}

// marshalAttributesWithBuffers creates a CK_ATTRIBUTE array where pValue
// points to pre-allocated buffers of the given sizes.
func (a *arena) marshalAttributesWithBuffers(attrs []*Attribute, sizes []uintptr) (uintptr, uintptr, []byte, [][]byte) {
	if len(attrs) == 0 {
		return 0, 0, nil, nil
	}

	buf := make([]byte, len(attrs)*int(ckAttributeSize))
	a.pinner.Pin(&buf[0])

	values := make([][]byte, len(attrs))

	for i, attr := range attrs {
		off := i * int(ckAttributeSize)
		*(*uintptr)(unsafe.Pointer(&buf[off])) = uintptr(attr.Type)

		sz := sizes[i]
		if sz > 0 {
			values[i] = make([]byte, sz)
			a.pinner.Pin(&values[i][0])
			*(*uintptr)(unsafe.Pointer(&buf[off+int(ckULONGSize)])) = uintptr(unsafe.Pointer(&values[i][0]))
		}
		*(*uintptr)(unsafe.Pointer(&buf[off+2*int(ckULONGSize)])) = sz
	}

	return uintptr(unsafe.Pointer(&buf[0])), uintptr(len(attrs)), buf, values
}

// unmarshalAttributes reads back the CK_ATTRIBUTE array filled by the second
// C_GetAttributeValue pass. Values come from the Go buffers the array points
// at, never from pValue: turning a uintptr back into a Go pointer is invalid
// and checkptr aborts on it.
func unmarshalAttributes(buf []byte, values [][]byte) []*Attribute {
	result := make([]*Attribute, len(values))
	for i, v := range values {
		off := i * int(ckAttributeSize)
		typ := *(*uintptr)(unsafe.Pointer(&buf[off]))
		valueLen := *(*uintptr)(unsafe.Pointer(&buf[off+2*int(ckULONGSize)]))

		attr := &Attribute{Type: uint(typ)}
		if valueLen > 0 && valueLen <= uintptr(len(v)) {
			attr.Value = v[:valueLen]
		}
		result[i] = attr
	}
	return result
}

// querySizes reads back ulValueLen from each CK_ATTRIBUTE in the buffer.
func querySizes(buf []byte, count int) []uintptr {
	sizes := make([]uintptr, count)
	for i := range count {
		off := i*int(ckAttributeSize) + 2*int(ckULONGSize)
		sizes[i] = *(*uintptr)(unsafe.Pointer(&buf[off]))
	}
	return sizes
}

// marshalMechanism converts a Go []*Mechanism into a C-compatible
// CK_MECHANISM struct pointer. PKCS#11 functions take a single mechanism,
// but the API uses []*Mechanism for compatibility with miekg/pkcs11.
func (a *arena) marshalMechanism(mechs []*Mechanism) uintptr {
	if len(mechs) == 0 {
		return 0
	}
	m := mechs[0]

	// Resolve parameter bytes from generator if needed.
	var paramBytes []byte
	switch g := m.generator.(type) {
	case *GCMParams:
		paramBytes = g.marshal()
		a.pinner.Pin(&paramBytes[0])
	case *OAEPParams:
		paramBytes = g.marshal()
		a.pinner.Pin(&paramBytes[0])
	case *ECDH1DeriveParams:
		paramBytes = g.marshal()
		a.pinner.Pin(&paramBytes[0])
	default:
		paramBytes = m.Parameter
	}

	buf := make([]byte, int(ckMechanismSize))
	a.pinner.Pin(&buf[0])

	*(*uintptr)(unsafe.Pointer(&buf[0])) = uintptr(m.Mechanism)
	if len(paramBytes) > 0 {
		a.pinner.Pin(&paramBytes[0])
		*(*uintptr)(unsafe.Pointer(&buf[int(ckULONGSize)])) = uintptr(unsafe.Pointer(&paramBytes[0]))
	}
	*(*uintptr)(unsafe.Pointer(&buf[2*int(ckULONGSize)])) = uintptr(len(paramBytes))

	return uintptr(unsafe.Pointer(&buf[0]))
}
