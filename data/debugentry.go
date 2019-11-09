package data

import (
	"debug/dwarf"

	"github.com/razzie/raztracer/common"
)

// DebugEntry is a wrapper for dwarf.Entry for easier data access
type DebugEntry struct {
	data  *DebugData
	entry *dwarf.Entry
}

// Val returns the value for the given dwarf attribute
func (de *DebugEntry) Val(attr dwarf.Attr) interface{} {
	return de.entry.Val(attr)
}

// Name returns the name of the entry
func (de *DebugEntry) name() string {
	name, ok := de.Val(dwarf.AttrName).(string)
	if !ok {
		return "?"
	}

	return name
}

// Size returns the size of the entry
func (de *DebugEntry) Size() int64 {
	size, _ := de.Val(dwarf.AttrByteSize).(int64)
	return size
}

// LowPC returns the low program counter of the entry
func (de *DebugEntry) LowPC() uintptr {
	lowpc, _ := de.Val(dwarf.AttrLowpc).(uint64)
	return uintptr(lowpc)
}

// HighPC returns the high program counter of the entry
func (de *DebugEntry) HighPC() uintptr {
	highpc, _ := de.Val(dwarf.AttrHighpc).(uint64)
	return uintptr(highpc)
}

// Children returns the child entries of this entry
func (de *DebugEntry) Children(maxDepth int) ([]DebugEntry, error) {
	reader := de.data.dwarfData.Reader()
	reader.Seek(de.entry.Offset)
	entries := make([]DebugEntry, 0)
	depth := 0

	for entry, err := reader.Next(); entry != nil; entry, err = reader.Next() {
		if err != nil {
			return nil, common.Error(err)
		}

		if entry.Tag == 0 {
			depth--

			if depth < 0 {
				return entries, nil
			}
		}

		if depth <= maxDepth || maxDepth < 0 {
			entries = append(entries, DebugEntry{de.data, entry})
		}

		if entry.Children {
			depth++
		}
	}

	return entries, nil
}

// Type returns the type entry of this entry
func (de *DebugEntry) Type() (*DebugEntry, error) {
	name := de.name()
	typeOff, ok := de.Val(dwarf.AttrType).(dwarf.Offset)
	if !ok {
		return nil, common.Errorf("%s doesn't have a type", name)
	}

	reader := de.data.dwarfData.Reader()
	reader.Seek(typeOff)
	typeEntry, _ := reader.Next()
	if typeEntry == nil {
		return nil, common.Errorf("%s: type entry not found at offset: %d", name, typeOff)
	}

	typ := &DebugEntry{de.data, typeEntry}

	if typeEntry.Tag == dwarf.TagConstType {
		return typ.Type()
	}

	return typ, nil
}

