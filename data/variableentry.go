package data

import (
	"debug/dwarf"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/go-delve/delve/pkg/dwarf/op"
	"github.com/razzie/raztracer/common"
)

// VariableEntry contains debug information about a variable
type VariableEntry struct {
	entry      DebugEntry
	staticBase uintptr
	cfaOffset  uintptr
	isPtr      bool
	Name       string `json:"name"`
	Type       string `json:"type,omitempty"`
	Size       int64  `json:"-"`
	DerefSize  int64  `json:"size,omitempty"`
	Address    string `json:"address,omitempty"`
	Value      string `json:"value,omitempty"`
	Error      string `json:"error,omitempty"`
}

// NewVariableEntry returns a new VariableEntry
func NewVariableEntry(de DebugEntry, staticBase uintptr) (*VariableEntry, error) {
	if de.entry.Tag != dwarf.TagVariable && de.entry.Tag != dwarf.TagFormalParameter {
		return nil, nil
	}

	var size, derefSize int64
	var typeName string
	var isPtr bool

	name := de.Name()
	typ, _ := de.Type()
	if typ != nil {
		size = typ.Size()

		switch typ.entry.Tag {
		case dwarf.TagPointerType, dwarf.TagReferenceType:
			isPtr = true
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
		staticBase: staticBase,
		isPtr:      isPtr,
		Name:       name,
		Type:       typeName,
		Size:       size,
		DerefSize:  derefSize,
	}, nil
}

// ReadValue updates the current address an value based on PC and registers
func (v *VariableEntry) ReadValue(pid int, pc uintptr, regs *op.DwarfRegisters) {
	v.Address = ""
	v.Value = ""
	v.Error = ""

	if v.Size == 0 && !v.isPtr {
		return
	}

	loc, err := v.entry.Location(dwarf.AttrLocation, pc)
	if err != nil {
		addr := uintptr(regs.CFA) + v.cfaOffset
		loc = &Location{address: addr}
		v.Address = fmt.Sprintf("no location - assume cfa+%#x", v.cfaOffset)
	} else {
		v.Address = loc.String()
	}

	data, err := loc.Read(pid, regs)
	if err != nil {
		v.Error = fmt.Sprint(err)
		return
	}

	if v.isPtr {
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
