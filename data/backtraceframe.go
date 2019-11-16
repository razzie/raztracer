package data

import (
	"fmt"
	"path"
	"strings"

	"github.com/razzie/raztracer/common"
	"github.com/razzie/raztracer/custom/dwarf/op"
)

// BacktraceFrame contains the name and variables of a function in the backtrace
type BacktraceFrame struct {
	Name      string           `json:"function"`
	Address   string           `json:"address"`
	Position  string           `json:"position"`
	CFA       string           `json:"cfa"`
	FrameBase string           `json:"framebase"`
	Variables []*VariableEntry `json:"variables"`
}

// NewBacktraceFrame returns a new BacktraceFrame
func NewBacktraceFrame(pid int, fn *FunctionEntry, pc uintptr, regs *op.DwarfRegisters) (*BacktraceFrame, error) {
	vars, err := fn.GetVariables()
	if err != nil {
		return nil, common.Error(err)
	}

	for _, v := range vars {
		v.ReadValue(pid, pc, regs)
	}

	debugData := fn.entry.data
	addr := fmt.Sprintf("%#x", fn.LowPC)
	position := fmt.Sprintf("%#x", pc)

	if debugData != nil {
		lineEntry, _ := NewLineEntry(pc, debugData)
		if lineEntry != nil {
			filename := path.Base(lineEntry.Filename)
			position += fmt.Sprintf(" %s:%d", filename, lineEntry.Line)
		}
	}

	if fn.StaticBase > 0 {
		addr += fmt.Sprintf(" (%#x)", fn.LowPC+fn.StaticBase)
	}

	return &BacktraceFrame{
		Name:      fn.Name,
		Address:   addr,
		Position:  position,
		CFA:       fmt.Sprintf("%#x", regs.CFA),
		FrameBase: fmt.Sprintf("%#x", regs.FrameBase),
		Variables: vars}, nil
}

// String returns the backtrace frame as a string
func (bt *BacktraceFrame) String() string {
	if len(bt.Variables) == 0 {
		return bt.Name + "()"
	}

	vars := make([]string, len(bt.Variables))
	for i, v := range bt.Variables {
		vars[i] = v.String()
	}
	return fmt.Sprintf("%s(%s)", bt.Name, strings.Join(vars, ","))
}
