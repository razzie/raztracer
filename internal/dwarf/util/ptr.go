package util

import (
	"bytes"
	"encoding/binary"
	"unsafe"
)

// Data Format
const (
	DW_EH_PE_absptr  = 0x00
	DW_EH_PE_uleb128 = 0x01
	DW_EH_PE_udata2  = 0x02
	DW_EH_PE_udata4  = 0x03
	DW_EH_PE_udata8  = 0x04
	DW_EH_PE_sleb128 = 0x09
	DW_EH_PE_sdata2  = 0x0A
	DW_EH_PE_sdata4  = 0x0B
	DW_EH_PE_sdata8  = 0x0C
)

// Data Application
const (
	DW_EH_PE_pcrel   = 0x10
	DW_EH_PE_textrel = 0x20
	DW_EH_PE_datarel = 0x30
	DW_EH_PE_funcrel = 0x40
	DW_EH_PE_aligned = 0x50
)

// Special
const (
	DW_EH_PE_omit = 0xFF
)

// DecodePointer decodes a pointer using the given encoding
func DecodePointer(encoding byte, order binary.ByteOrder, pc uint64, addr *bytes.Buffer) (result uint64) {
	if encoding == DW_EH_PE_omit {
		return 0
	}

	// The following are defined in the DWARF Exception Header Encodings
	// section 10.5.1. For some reason, GCC adds a 0x80 to the upper 4 bits
	// that are not documented in the LSB. Thefore, only 3 of the upper 4 bits
	// are actually used.

	switch encoding & 0x70 {
	case DW_EH_PE_absptr:
		// do nothing

	case DW_EH_PE_pcrel:
		result += pc

	case DW_EH_PE_textrel:
		panic("DW_EH_PE_textrel pointer encodings not supported")

	case DW_EH_PE_datarel:
		panic("DW_EH_PE_datarel pointer encodings not supported")

	case DW_EH_PE_funcrel:
		panic("DW_EH_PE_funcrel pointer encodings not supported")

	case DW_EH_PE_aligned:
		panic("DW_EH_PE_aligned pointer encodings not supported")

	default:
		panic("unknown upper pointer encoding bits")
	}

	switch encoding & 0x0F {
	case DW_EH_PE_absptr:
		if unsafe.Sizeof(0) == 4 {
			var ptr uint32
			binary.Read(addr, order, &ptr)
			result += uint64(ptr)
		} else {
			var ptr uint64
			binary.Read(addr, order, &ptr)
			result += ptr
		}

	case DW_EH_PE_uleb128:
		ptr, _ := DecodeULEB128(addr)
		result += ptr

	case DW_EH_PE_udata2:
		var ptr uint16
		binary.Read(addr, order, &ptr)
		result += uint64(ptr)

	case DW_EH_PE_udata4:
		var ptr uint32
		binary.Read(addr, order, &ptr)
		result += uint64(ptr)

	case DW_EH_PE_udata8:
		var ptr uint64
		binary.Read(addr, order, &ptr)
		result += ptr

	case DW_EH_PE_sleb128:
		ptr, _ := DecodeSLEB128(addr)
		result = addOffset(result, ptr)

	case DW_EH_PE_sdata2:
		var ptr int16
		binary.Read(addr, order, &ptr)
		result = addOffset(result, int64(ptr))

	case DW_EH_PE_sdata4:
		var ptr int32
		binary.Read(addr, order, &ptr)
		result = addOffset(result, int64(ptr))

	case DW_EH_PE_sdata8:
		var ptr int64
		binary.Read(addr, order, &ptr)
		result = addOffset(result, ptr)

	default:
		panic("unknown lower pointer encoding bits")
	}

	return result
}

func addOffset(value uint64, offset int64) uint64 {
	if offset >= 0 {
		return value + uint64(offset)
	}

	if value >= uint64(-offset) {
		return value - uint64(-offset)
	}

	panic("attempted to add an offset that would result in overflow")
}
