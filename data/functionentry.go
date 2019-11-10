package data

import (
	"debug/dwarf"

	"github.com/go-delve/delve/pkg/dwarf/op"
	"github.com/razzie/raztracer/common"
)

// FunctionEntry contains debug information about a function
type FunctionEntry struct {
	entry      DebugEntry
	Name       string
	HighPC     uintptr
	LowPC      uintptr
	StaticBase uintptr
}

// NewFunctionEntry returns a new FunctionEntry
func NewFunctionEntry(pc uintptr, data *DebugData) (*FunctionEntry, error) {
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

	return nil, common.Errorf("the entry is not a function at pc: %d", pc)
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
