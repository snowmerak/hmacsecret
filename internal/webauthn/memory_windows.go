//go:build windows

package webauthn

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const maxResultBytes = 1 << 20

func utf16Pointer(value string) (*uint16, error) {
	ptr, err := windows.UTF16PtrFromString(value)
	if err != nil {
		return nil, fmt.Errorf("encode UTF-16 string: %w", err)
	}
	return ptr, nil
}

func bytePointer(value []byte) unsafe.Pointer {
	if len(value) == 0 {
		return nil
	}
	return unsafe.Pointer(&value[0])
}

func structPointer[T any](value *T) unsafe.Pointer {
	if value == nil {
		return nil
	}
	return unsafe.Pointer(value)
}

func callPointer[T any](value *T) uintptr {
	return uintptr(structPointer(value))
}

func copyResultBytes(ptr unsafe.Pointer, size uint32, field string) ([]byte, error) {
	if size == 0 {
		return nil, nil
	}
	if ptr == nil {
		return nil, fmt.Errorf("%s: non-zero size with nil pointer", field)
	}
	if size > maxResultBytes {
		return nil, fmt.Errorf("%s: result is too large: %d bytes", field, size)
	}
	src := unsafe.Slice((*byte)(ptr), int(size))
	return append([]byte(nil), src...), nil
}
