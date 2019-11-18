package raztracer

import (
	"bytes"
	"encoding/binary"
)

// LocEntry contains dwarf instructions for locations between lowpc and highpc
type LocEntry struct {
	lowpc        uintptr
	highpc       uintptr
	instructions []byte
}

// LocList is a list of location entries mapped to PC
type LocList map[int64][]LocEntry

// NewLocList returns a new LocList
func NewLocList(data []byte, order binary.ByteOrder) LocList {
	loclist := make(LocList)
	rdr := bytes.NewBuffer(data)
	ptrSize := int(SizeofPtr)

	readAddr := func() uint64 {
		data := rdr.Next(ptrSize)
		if len(data) < ptrSize {
			return 0
		}

		if ptrSize == 4 {
			addr := order.Uint32(data)
			if addr == ^uint32(0) {
				return ^uint64(0)
			}

			return uint64(addr)
		}

		return order.Uint64(data)
	}

	var entries []LocEntry
	var offset int64

	for rdr.Len() > 0 {
		lowpc := readAddr()
		highpc := readAddr()

		if lowpc == 0 && highpc == 0 {
			loclist[offset] = entries
			entries = make([]LocEntry, 0)
			offset = int64(rdr.Cap() - rdr.Len())
			continue
		}

		instrlen := order.Uint16(rdr.Next(2))
		instr := rdr.Next(int(instrlen))

		entry := LocEntry{
			lowpc:        uintptr(lowpc),
			highpc:       uintptr(highpc),
			instructions: instr}
		entries = append(entries, entry)
	}

	return loclist
}

// FindEntry returns a matching LocEntry or an error if not found
func (l LocList) FindEntry(offset int64, relpc uintptr) (*LocEntry, error) {
	entries, found := l[offset]

	if !found {
		for off, ent := range l {
			if offset >= off {
				entries = ent
			}
		}
	}

	for _, entry := range entries {
		if relpc >= entry.lowpc && relpc < entry.highpc {
			return &entry, nil
		}
	}

	return nil, Errorf("no loclist entry for relative pc: %#x (offset: %#x)", relpc, offset)
}
