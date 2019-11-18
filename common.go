package raztracer

import (
	"encoding/binary"
	"unsafe"
)

// SizeofPtr contains the size of a pointer of the current architecture
const (
	SizeofPtr = unsafe.Sizeof(0)
)

// ByteOrder is initialized with the byte order of the current architecture
var ByteOrder binary.ByteOrder

// ReadAddress reads a pointer from a byte slice
func ReadAddress(data []byte) uintptr {
	if len(data) < int(SizeofPtr) {
		return 0
	}

	if SizeofPtr == 4 {
		return uintptr(ByteOrder.Uint32(data))
	}

	return uintptr(ByteOrder.Uint64(data))
}

func init() {
	ByteOrder = getByteOrder()
}

func getByteOrder() binary.ByteOrder {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	case [2]byte{0xCD, 0xAB}:
		return binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		return binary.BigEndian
	default:
		panic("Could not determine native endianness.")
	}
}
