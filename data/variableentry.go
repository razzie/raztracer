package data

import (
	"debug/dwarf"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/razzie/raztracer/common"
	"github.com/razzie/raztracer/custom/dwarf/op"
)

// VariableEntry contains debug information about a variable
type VariableEntry struct {
	entry      DebugEntry
	staticBase uintptr
	IsPointer  bool   `json:"-"`
	Name       string `json:"name"`
	Type       string `json:"type,omitempty"`
	Size       int64  `json:"-"`
	DerefSize  int64  `json:"size,omitempty"`
	Location   string `json:"location,omitempty"`
	Value      string `json:"value,omitempty"`
	Error      string `json:"error,omitempty"`
}

// NewVariableEntry returns a new VariableEntry
func NewVariableEntry(de DebugEntry) (*VariableEntry, error) {
	if de.entry.Tag != dwarf.TagVariable && de.entry.Tag != dwarf.TagFormalParameter {
		return nil, nil
	}

	var size, derefSize int64
	var typeName string
	var IsPointer bool

	name := de.Name()
	typ, _ := de.Type()
	if typ != nil {
		size = typ.Size()

		switch typ.entry.Tag {
		case dwarf.TagPointerType, dwarf.TagReferenceType:
			IsPointer = true
			subtype, _ := typ.Type()
			if subtype != nil {
				typeName = subtype.Name() + "*"
				derefSize = subtype.Size()
			} else {
				typeName = "void*"
			}

		default:
			typeName = typ.Name()
		}
	}

	if size == 0 {
		size = int64(common.SizeofPtr)
	}

	if derefSize == 0 {
		derefSize = size
	}

	return &VariableEntry{
		entry:      de,
		staticBase: de.data.staticBase,
		IsPointer:  IsPointer,
		Name:       name,
		Type:       typeName,
		Size:       size,
		DerefSize:  derefSize,
	}, nil
}

// ReadValue updates the current location and value based on PC and registers
func (v *VariableEntry) ReadValue(pid int, pc uintptr, regs *op.DwarfRegisters) {
	v.Location = ""
	v.Value = ""
	v.Error = ""

	if v.Size == 0 && !v.IsPointer {
		return
	}

	loc, err := v.entry.Location(dwarf.AttrLocation, pc)
	if err != nil {
		v.Error = fmt.Sprint(err)
		return
	}

	v.Location = loc.String()

	data, err := loc.Read(pid, regs)
	if err != nil {
		v.Error = fmt.Sprint(err)
		return
	}

	if v.IsPointer {
		addr := common.ReadAddress(data)
		v.Value = fmt.Sprintf("%#x : ", addr)

		if isStringType(v.Type) {
			v.Size = 0
			data, err := readString(pid, uintptr(addr))
			if err != nil {
				v.Error = fmt.Sprint(err)
				return
			}

			v.Value += string(data)
			return
		}

		data = make([]byte, v.Size)
		err = common.Process(pid).PeekData(uintptr(addr), data)
		if err != nil {
			v.Error = fmt.Sprint(err)
			return
		}
	}

	if len(data) > int(v.Size) {
		data = data[:v.Size]
	}

	v.Value += "0x" + hex.EncodeToString(data)
	return
}

// String returns the variable entry as a string
func (v *VariableEntry) String() string {
	if v.Value == "" {
		return v.Name
	}

	return v.Name + "=" + strings.Split(v.Value, "\n")[0]
}

func isStringType(typeName string) bool {
	switch typeName {
	case "char*":
		return true

	default:
		return false
	}
}

func readString(pid int, addr uintptr) ([]byte, error) {
	str := make([]byte, 0)
	proc := common.Process(pid)

	for {
		var buf [common.SizeofPtr]byte

		err := proc.PeekData(addr, buf[:])
		if err != nil {
			if len(str) == 0 {
				return nil, common.Error(err)
			}
			break
		}
		addr += uintptr(len(buf))

		for i, c := range buf {
			if c == 0 {
				str = append(str, buf[:i]...)
				return str, nil
			}
		}

		str = append(str, buf[:]...)

		if len(str) > 256 {
			break
		}
	}

	return str, nil
}
