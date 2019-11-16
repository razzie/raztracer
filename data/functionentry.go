package data

import (
	"debug/dwarf"
	"fmt"

	"github.com/razzie/raztracer/common"
	"github.com/razzie/raztracer/custom/dwarf/op"
)

// FunctionEntry contains debug information about a function
type FunctionEntry struct {
	entry      DebugEntry
	variables  []*VariableEntry
	Name       string
	HighPC     uintptr
	LowPC      uintptr
	StaticBase uintptr
}

// NewFunctionEntry returns a new FunctionEntry
func NewFunctionEntry(de DebugEntry, staticBase uintptr) (*FunctionEntry, error) {
	name := de.Name()

	if de.entry.Tag != dwarf.TagSubprogram {
		return nil, common.Errorf("%s is not a function entry", name)
	}

	return &FunctionEntry{
		entry:      de,
		Name:       name,
		HighPC:     de.HighPC(),
		LowPC:      de.LowPC(),
		StaticBase: staticBase,
	}, nil
}

// NewFunctionEntryFromPC returns a new FunctionEntry from program counter
func NewFunctionEntryFromPC(pc uintptr, data *DebugData) (*FunctionEntry, error) {
	reader := data.dwarfData.Reader()

	for entry, err := reader.Next(); entry != nil; entry, err = reader.Next() {
		if err != nil {
			return nil, common.Error(err)
		}

		if entry.Tag != dwarf.TagSubprogram {
			continue
		}

		ranges, err := data.dwarfData.Ranges(entry)
		if err != nil {
			return nil, common.Error(err)
		}

		for _, lowhigh := range ranges {
			lowpc := uintptr(lowhigh[0])
			highpc := uintptr(lowhigh[1])
			de := DebugEntry{data, entry}

			if lowpc <= pc && highpc > pc {
				return &FunctionEntry{
					entry:      de,
					Name:       de.Name(),
					HighPC:     highpc,
					LowPC:      lowpc,
					StaticBase: data.staticBase,
				}, nil
			}
		}
	}

	return nil, common.Errorf("the entry is not a function at pc: %#x", pc)
}

// NewLibFunctionEntry returns a dummy FunctionEntry for a library function
func NewLibFunctionEntry(name string, low, high, staticBase uintptr) (*FunctionEntry, error) {
	return &FunctionEntry{
		Name:       name,
		LowPC:      low,
		HighPC:     high,
		StaticBase: staticBase,
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
	var cfaOffset uintptr
	var varCount int

	for _, entry := range children {
		if len(vars) > 0 && entry.entry.Tag != dwarf.TagFormalParameter {
			break
		}

		v, err := NewVariableEntry(entry, fn.StaticBase)
		if err != nil {
			fmt.Println(common.Error(err))
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
	return vars, nil
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
