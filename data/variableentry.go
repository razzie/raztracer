package data

import (
	"debug/dwarf"

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

// GetValue returns the current location and raw value of the variable based on PC and registers
func (v *VariableEntry) GetValue(pid int, pc uintptr, regs *op.DwarfRegisters) (*Location, []byte, *common.TracedError) {
	if v.Size == 0 && !v.IsPointer {
		return nil, nil, nil
	}

	loc, err := v.entry.Location(dwarf.AttrLocation, pc)
	if err != nil {
		return nil, nil, common.Error(err)
	}

	data, err := loc.Read(pid, regs)
	if err != nil {
		return loc, nil, common.Error(err)
	}

	return loc, data, nil
}
