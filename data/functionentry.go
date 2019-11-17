package data

import (
	"debug/dwarf"
	"debug/elf"
	"fmt"

	"github.com/razzie/raztracer/common"
	"github.com/razzie/raztracer/custom/dwarf/op"
)

// FunctionEntry contains debug information about a function
type FunctionEntry struct {
	entry             DebugEntry
	variables         []*VariableEntry
	globals           []*VariableEntry
	Name              string
	HighPC            uintptr
	LowPC             uintptr
	StaticBase        uintptr
	BreakpointAddress uintptr
	Lib               *common.SharedLibrary
}

// NewFunctionEntry returns a new FunctionEntry
func NewFunctionEntry(de DebugEntry) (*FunctionEntry, error) {
	name := de.Name()

	if de.entry.Tag != dwarf.TagSubprogram {
		return nil, common.Errorf("%s is not a function entry", name)
	}

	fn := &FunctionEntry{
		entry:      de,
		Name:       name,
		HighPC:     de.HighPC(),
		LowPC:      de.LowPC(),
		StaticBase: de.data.staticBase,
	}

	fn.BreakpointAddress, _ = fn.getBreakpointAddress()

	return fn, nil
}

// NewLibFunctionEntry returns a dummy FunctionEntry for a library function
func NewLibFunctionEntry(lib *common.SharedLibrary, symbol elf.Symbol) (*FunctionEntry, error) {
	lowpc := uintptr(symbol.Value)
	highpc := lowpc + uintptr(symbol.Size)

	return &FunctionEntry{
		Name:              symbol.Name,
		LowPC:             lowpc,
		HighPC:            highpc,
		StaticBase:        lib.StaticBase,
		BreakpointAddress: lowpc,
		Lib:               lib,
	}, nil
}

// GetVariables returns the variables in a function
func (fn *FunctionEntry) GetVariables() ([]*VariableEntry, error) {
	if fn.entry.data == nil {
		return nil, nil
	}

	if fn.variables != nil {
		return fn.variables, nil
	}

	children, err := fn.entry.Children(1)
	if err != nil {
		return nil, common.Error(err)
	}

	vars := make([]*VariableEntry, 0)
	var errors []error
	var cfaOffset uintptr
	var varCount int

	for _, entry := range children {
		if len(vars) > 0 && entry.entry.Tag != dwarf.TagFormalParameter {
			break
		}

		v, err := NewVariableEntry(entry)
		if err != nil {
			errors = append(errors, err)
			continue
		}
		if v == nil {
			continue
		}

		varCount++
		cfaOffset += uintptr(v.Size)

		// do not add return value
		isret, _ := v.entry.Val(dwarf.AttrVarParam).(bool)
		if isret {
			continue
		}

		if len(v.Name) == 0 {
			v.Name = fmt.Sprintf("#%d", varCount)
		}

		vars = append(vars, v)
	}

	// calculating cfaOffsets in backwards order
	for _, v := range vars {
		cfaOffset -= uintptr(v.Size)
		v.cfaOffset = cfaOffset
	}

	fn.variables = vars
	return vars, common.MergeErrors(errors)
}

// GetFrameBase returns the frame base at PC
func (fn *FunctionEntry) GetFrameBase(pc uintptr, regs *op.DwarfRegisters) (uintptr, error) {
	if pc > fn.StaticBase {
		pc -= fn.StaticBase
	}

	if fn.entry.data == nil {
		return 0, common.Errorf("no debug data")
	}

	loc, err := fn.entry.Location(dwarf.AttrFrameBase, pc)
	if err != nil {
		return 0, common.Error(err)
	}

	err = loc.parse(regs)
	return loc.address, common.Error(err)
}

func (fn *FunctionEntry) getBreakpointAddress() (uintptr, error) {
	line, err := NewLineEntry(fn.LowPC, fn.entry.data)
	if err != nil {
		return fn.LowPC, common.Error(err)
	}

	for line, err = line.Next(); line != nil; line, err = line.Next() {
		if err != nil {
			return fn.LowPC, common.Error(err)
		}

		if line.IsStmt {
			return line.Address, nil
		}
	}

	return fn.LowPC, common.Errorf("no suitable breakpoint location for %#x", fn.LowPC)
}
