package data

import (
	"bytes"
	"debug/dwarf"
	"fmt"

	"github.com/razzie/raztracer/custom/op"
	"github.com/razzie/raztracer/common"
)

// Location contains every information required to read a variable
type Location struct {
	instructions []byte
	address      uintptr
	pieces       []op.Piece
	regs         *op.DwarfRegisters
}

// NewLocation returns a new Location
func NewLocation(de *DebugEntry, attr dwarf.Attr, pc uintptr) (*Location, error) {
	name := de.Name()

	a := de.Val(attr)
	if a == nil {
		return nil, common.Errorf("%s: missing attribute '%v'", name, attr)
	}

	switch a.(type) {
	case []byte:
		return &Location{instructions: a.([]byte)}, nil

	case int64: // loclist offset
		instr, err := de.data.GetLoclistEntry(pc, a.(int64))
		return &Location{instructions: instr}, common.Error(err)

	default:
		return nil, common.Errorf("%s: could not interpret location for %v", name, attr)
	}
}

func (loc *Location) parse(regs *op.DwarfRegisters) error {
	addr, pieces, err := op.ExecuteStackProgram(*regs, loc.instructions)
	loc.address = uintptr(addr)
	loc.pieces = pieces
	loc.regs = regs
	return common.Error(err)
}

// Read reads and returns the data in binary form at the location
func (loc *Location) Read(pid int, regs *op.DwarfRegisters) ([]byte, error) {
	if len(loc.instructions) == 0 {
		return nil, common.Errorf("no location instructions")
	}

	err := loc.parse(regs)
	if err != nil {
		return nil, common.Error(err)
	}

	proc := common.Process(pid)

	if len(loc.pieces) == 0 {
		data := make([]byte, common.SizeofPtr)
		err := proc.PeekData(uintptr(loc.address), data)
		return data, common.Error(err)
	}

	var data []byte
	for _, piece := range loc.pieces {
		if piece.IsRegister {
			val := loc.regs.Uint64Val(piece.RegNum)
			buf := make([]byte, common.SizeofPtr)

			if common.SizeofPtr == 4 {
				common.ByteOrder.PutUint32(buf, uint32(val))
			} else {
				common.ByteOrder.PutUint64(buf, val)
			}

			data = append(data, buf...)
		} else {
			buf := make([]byte, piece.Size)
			err := proc.PeekData(uintptr(piece.Addr), buf)
			if err != nil {
				return data, common.Error(err)
			}

			data = append(data, buf...)
		}
	}

	return data, nil
}

// String returns the location as a string
func (loc *Location) String() (ret string) {
	if loc.instructions[0] == byte(op.DW_OP_addr) {
		addr := common.ReadAddress(loc.instructions[1:])
		return fmt.Sprintf("%#x", addr)
	}

	defer func() {
		if r := recover(); r != nil {
			ret = fmt.Sprint(loc.instructions)
		}
	}()

	var buf bytes.Buffer
	op.PrettyPrint(&buf, loc.instructions)
	return buf.String()
}
