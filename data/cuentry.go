package data

import (
	"debug/dwarf"
	"fmt"

	"github.com/razzie/raztracer/common"
	"github.com/razzie/raztracer/custom/dwarf/op"
)

// CUEntry contains debug information about a compilation unit
type CUEntry struct {
	entry      DebugEntry
	functions  []*FunctionEntry
	globals    []*VariableEntry
	Ranges     [][2]uintptr
	LowPC      uintptr
	HighPC     uintptr
	StaticBase uintptr
}

// NewCUEntry returns a new CUEntry
func NewCUEntry(de DebugEntry) (*CUEntry, error) {
	if de.entry.Tag != dwarf.TagCompileUnit {
		return nil, common.Errorf("%s is not a compilation unit", de.Name())
	}

	ranges, err := de.Ranges()
	if err != nil {
		return nil, common.Error(err)
	}

	if len(ranges) == 0 {
		return nil, common.Errorf("%s CU doesn't have ranges", de.Name())
	}

	return &CUEntry{
		entry:      de,
		Ranges:     ranges,
		LowPC:      de.LowPC(),
		HighPC:     de.HighPC(),
		StaticBase: de.data.staticBase,
	}, nil
}

// ContainsPC returns whether this compilation unit covers the given program counter
func (cu *CUEntry) ContainsPC(pc uintptr) bool {
	for _, lowhigh := range cu.Ranges {
		lowpc := lowhigh[0] + cu.StaticBase
		highpc := lowhigh[1] + cu.StaticBase
		if pc >= lowpc && pc < highpc {
			return true
		}
	}
	return false
}

// FindEntry returns the debug entry from PC
func (cu *CUEntry) FindEntry(pc uintptr) (*DebugEntry, error) {
	children, err := cu.entry.Children(-1)
	if err != nil {
		return nil, common.Error(err)
	}

	for _, entry := range children {
		ranges, _ := entry.Ranges()
		for _, lowhigh := range ranges {
			lowpc := lowhigh[0] + cu.StaticBase
			highpc := lowhigh[1] + cu.StaticBase
			if pc >= lowpc && pc < highpc {
				return &entry, nil
			}
		}
	}

	return nil, common.Errorf("no debug entry at pc:%#x", pc)
}

// GetFunctions returns the function debug entries that belongs to this CU
func (cu *CUEntry) GetFunctions() ([]*FunctionEntry, error) {
	if cu.functions != nil {
		return cu.functions, nil
	}

	children, err := cu.entry.Children(-1)
	if err != nil {
		return nil, common.Error(err)
	}

	funcs := make([]*FunctionEntry, 0)

	for _, de := range children {
		if de.entry.Tag != dwarf.TagSubprogram {
			continue
		}

		_, hasName := de.Val(dwarf.AttrName).(string)
		if !hasName {
			continue
		}

		f, err := NewFunctionEntry(de)
		if err != nil {
			fmt.Println(common.Error(err))
			continue
		}

		funcs = append(funcs, f)
	}

	cu.functions = funcs
	return funcs, nil
}

// GetGlobals returns the global variable entries that belong to this CU
func (cu *CUEntry) GetGlobals() ([]*VariableEntry, error) {
	if cu.globals != nil {
		return cu.globals, nil
	}

	children, err := cu.entry.Children(-1)
	if err != nil {
		return nil, common.Error(err)
	}

	lowpc := cu.Ranges[0][0]
	vars := make([]*VariableEntry, 0)

	for _, de := range children {
		if de.entry.Tag != dwarf.TagVariable {
			continue
		}

		_, hasName := de.Val(dwarf.AttrName).(string)
		if !hasName {
			continue
		}

		loc, _ := de.Location(dwarf.AttrLocation, lowpc)
		if loc != nil && len(loc.instructions) > 0 {
			firstOp := op.Opcode(loc.instructions[0])
			if firstOp != op.DW_OP_addr {
				continue
			}
		} else {
			continue
		}

		v, err := NewVariableEntry(de)
		if err != nil {
			fmt.Println(common.Error(err))
			continue
		}

		if v == nil || v.Size == 0 {
			continue
		}

		vars = append(vars, v)
	}

	cu.globals = vars
	return vars, nil
}
