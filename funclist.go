//go:build linux

package pkcs11

import (
	"fmt"
	"runtime"
	"unsafe"

	"github.com/ebitengine/purego"
)

// functionList holds function pointers extracted from the PKCS#11
// CK_FUNCTION_LIST structure loaded from the shared library.
type functionList struct {
	handle uintptr // dlopen handle; kept alive for the library's lifetime

	C_Initialize          uintptr
	C_Finalize            uintptr
	C_GetInfo             uintptr
	C_GetFunctionList     uintptr
	C_GetSlotList         uintptr
	C_GetSlotInfo         uintptr
	C_GetTokenInfo        uintptr
	C_GetMechanismList    uintptr
	C_GetMechanismInfo    uintptr
	C_InitToken           uintptr
	C_InitPIN             uintptr
	C_SetPIN              uintptr
	C_OpenSession         uintptr
	C_CloseSession        uintptr
	C_CloseAllSessions    uintptr
	C_GetSessionInfo      uintptr
	C_GetOperationState   uintptr
	C_SetOperationState   uintptr
	C_Login               uintptr
	C_Logout              uintptr
	C_CreateObject        uintptr
	C_CopyObject          uintptr
	C_DestroyObject       uintptr
	C_GetObjectSize       uintptr
	C_GetAttributeValue   uintptr
	C_SetAttributeValue   uintptr
	C_FindObjectsInit     uintptr
	C_FindObjects         uintptr
	C_FindObjectsFinal    uintptr
	C_EncryptInit         uintptr
	C_Encrypt             uintptr
	C_EncryptUpdate       uintptr
	C_EncryptFinal        uintptr
	C_DecryptInit         uintptr
	C_Decrypt             uintptr
	C_DecryptUpdate       uintptr
	C_DecryptFinal        uintptr
	C_DigestInit          uintptr
	C_Digest              uintptr
	C_DigestUpdate        uintptr
	C_DigestKey           uintptr
	C_DigestFinal         uintptr
	C_SignInit            uintptr
	C_Sign                uintptr
	C_SignUpdate          uintptr
	C_SignFinal           uintptr
	C_SignRecoverInit     uintptr
	C_SignRecover         uintptr
	C_VerifyInit          uintptr
	C_Verify              uintptr
	C_VerifyUpdate        uintptr
	C_VerifyFinal         uintptr
	C_VerifyRecoverInit   uintptr
	C_VerifyRecover       uintptr
	C_DigestEncryptUpdate uintptr
	C_DecryptDigestUpdate uintptr
	C_SignEncryptUpdate   uintptr
	C_DecryptVerifyUpdate uintptr
	C_GenerateKey         uintptr
	C_GenerateKeyPair     uintptr
	C_WrapKey             uintptr
	C_UnwrapKey           uintptr
	C_DeriveKey           uintptr
	C_SeedRandom          uintptr
	C_GenerateRandom      uintptr
	C_GetFunctionStatus   uintptr
	C_CancelFunction      uintptr
	C_WaitForSlotEvent    uintptr
}

// loadModule opens the PKCS#11 shared library at the given path,
// resolves C_GetFunctionList, and populates a functionList.
//
// When CGO_ENABLED=0, the Go dynamic linker may not have the same library
// search paths as the system linker. If the initial dlopen fails because a
// dependency cannot be found, we resolve the library's dependencies via ldd
// output paths embedded at build time... but actually that's impractical.
// Instead we attempt dlopen, and if it fails, we try loading common
// dependency locations with RTLD_GLOBAL so subsequent loads find them.
func loadModule(module string) (*functionList, error) {
	if module == "" {
		return nil, fmt.Errorf("pkcs11: module path is empty")
	}

	handle, err := purego.Dlopen(module, purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err != nil {
		// Without CGO, the Go process may lack standard library search paths.
		// Pre-load common system library directories so transitive deps resolve.
		preloadSystemLibs()
		handle, err = purego.Dlopen(module, purego.RTLD_LAZY)
		if err != nil {
			return nil, fmt.Errorf("pkcs11: dlopen %s: %w", module, err)
		}
	}

	sym, err := purego.Dlsym(handle, "C_GetFunctionList")
	if err != nil {
		purego.Dlclose(handle) //nolint:errcheck,gosec // cleanup on error path; nothing to do if close fails (G104)
		return nil, fmt.Errorf("pkcs11: dlsym C_GetFunctionList: %w", err)
	}

	// Call C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
	// It returns CK_RV and writes a pointer to CK_FUNCTION_LIST into ppFunctionList.
	var flPtr uintptr
	rv, _, _ := purego.SyscallN(sym, uintptr(unsafe.Pointer(&flPtr)))
	if err := toError(rv); err != nil {
		purego.Dlclose(handle) //nolint:errcheck,gosec // cleanup on error path; nothing to do if close fails (G104)
		return nil, fmt.Errorf("pkcs11: C_GetFunctionList: %w", err)
	}
	if flPtr == 0 {
		purego.Dlclose(handle) //nolint:errcheck,gosec // cleanup on error path; nothing to do if close fails (G104)
		return nil, fmt.Errorf("pkcs11: C_GetFunctionList returned nil")
	}
	runtime.KeepAlive(&flPtr)

	fl := &functionList{handle: handle}
	readFunctionList(flPtr, fl)

	return fl, nil
}

// readFunctionList reads the CK_FUNCTION_LIST structure from memory at ptr
// and fills the Go functionList struct.
//
// CK_FUNCTION_LIST layout on 64-bit Linux:
//
//	offset 0: CK_VERSION (2 bytes) + 6 bytes padding
//	offset 8: C_Initialize (8 bytes)
//	offset 16: C_Finalize (8 bytes)
//	... 68 function pointers total, each 8 bytes ...
func readFunctionList(ptr uintptr, fl *functionList) {
	// Each function pointer is at offset 8 + (index * 8).
	readPtr := func(offset uintptr) uintptr {
		return *(*uintptr)(unsafe.Pointer(ptr + offset))
	}

	fl.C_Initialize = readPtr(8)
	fl.C_Finalize = readPtr(16)
	fl.C_GetInfo = readPtr(24)
	fl.C_GetFunctionList = readPtr(32)
	fl.C_GetSlotList = readPtr(40)
	fl.C_GetSlotInfo = readPtr(48)
	fl.C_GetTokenInfo = readPtr(56)
	fl.C_GetMechanismList = readPtr(64)
	fl.C_GetMechanismInfo = readPtr(72)
	fl.C_InitToken = readPtr(80)
	fl.C_InitPIN = readPtr(88)
	fl.C_SetPIN = readPtr(96)
	fl.C_OpenSession = readPtr(104)
	fl.C_CloseSession = readPtr(112)
	fl.C_CloseAllSessions = readPtr(120)
	fl.C_GetSessionInfo = readPtr(128)
	fl.C_GetOperationState = readPtr(136)
	fl.C_SetOperationState = readPtr(144)
	fl.C_Login = readPtr(152)
	fl.C_Logout = readPtr(160)
	fl.C_CreateObject = readPtr(168)
	fl.C_CopyObject = readPtr(176)
	fl.C_DestroyObject = readPtr(184)
	fl.C_GetObjectSize = readPtr(192)
	fl.C_GetAttributeValue = readPtr(200)
	fl.C_SetAttributeValue = readPtr(208)
	fl.C_FindObjectsInit = readPtr(216)
	fl.C_FindObjects = readPtr(224)
	fl.C_FindObjectsFinal = readPtr(232)
	fl.C_EncryptInit = readPtr(240)
	fl.C_Encrypt = readPtr(248)
	fl.C_EncryptUpdate = readPtr(256)
	fl.C_EncryptFinal = readPtr(264)
	fl.C_DecryptInit = readPtr(272)
	fl.C_Decrypt = readPtr(280)
	fl.C_DecryptUpdate = readPtr(288)
	fl.C_DecryptFinal = readPtr(296)
	fl.C_DigestInit = readPtr(304)
	fl.C_Digest = readPtr(312)
	fl.C_DigestUpdate = readPtr(320)
	fl.C_DigestKey = readPtr(328)
	fl.C_DigestFinal = readPtr(336)
	fl.C_SignInit = readPtr(344)
	fl.C_Sign = readPtr(352)
	fl.C_SignUpdate = readPtr(360)
	fl.C_SignFinal = readPtr(368)
	fl.C_SignRecoverInit = readPtr(376)
	fl.C_SignRecover = readPtr(384)
	fl.C_VerifyInit = readPtr(392)
	fl.C_Verify = readPtr(400)
	fl.C_VerifyUpdate = readPtr(408)
	fl.C_VerifyFinal = readPtr(416)
	fl.C_VerifyRecoverInit = readPtr(424)
	fl.C_VerifyRecover = readPtr(432)
	fl.C_DigestEncryptUpdate = readPtr(440)
	fl.C_DecryptDigestUpdate = readPtr(448)
	fl.C_SignEncryptUpdate = readPtr(456)
	fl.C_DecryptVerifyUpdate = readPtr(464)
	fl.C_GenerateKey = readPtr(472)
	fl.C_GenerateKeyPair = readPtr(480)
	fl.C_WrapKey = readPtr(488)
	fl.C_UnwrapKey = readPtr(496)
	fl.C_DeriveKey = readPtr(504)
	fl.C_SeedRandom = readPtr(512)
	fl.C_GenerateRandom = readPtr(520)
	fl.C_GetFunctionStatus = readPtr(528)
	fl.C_CancelFunction = readPtr(536)
	fl.C_WaitForSlotEvent = readPtr(544)
}

func (fl *functionList) close() {
	if fl.handle != 0 {
		purego.Dlclose(fl.handle) //nolint:errcheck,gosec // best-effort cleanup; nothing useful to do on error (G104)
		fl.handle = 0
	}
}

// preloadSystemLibs loads common shared library directories with RTLD_GLOBAL
// so that transitive dependencies of PKCS#11 modules can be resolved.
// This is necessary when CGO_ENABLED=0 because the Go runtime does not
// configure the dynamic linker's default search paths the same way a
// C-linked binary would.
func preloadSystemLibs() {
	// Common library paths on 64-bit Linux systems.
	libDirs := []string{
		"/lib/x86_64-linux-gnu",
		"/usr/lib/x86_64-linux-gnu",
		"/lib/aarch64-linux-gnu",
		"/usr/lib/aarch64-linux-gnu",
		"/lib64",
		"/usr/lib64",
	}

	// Libraries commonly needed by PKCS#11 modules.
	libs := []string{
		"libstdc++.so.6",
		"libcrypto.so.3",
		"libcrypto.so.1.1",
		"libssl.so.3",
		"libssl.so.1.1",
	}

	for _, dir := range libDirs {
		for _, lib := range libs {
			path := dir + "/" + lib
			// Ignore errors; we're just trying to make symbols available.
			purego.Dlopen(path, purego.RTLD_LAZY|purego.RTLD_GLOBAL) //nolint:errcheck,gosec // best-effort preload (G104)
		}
	}
}
