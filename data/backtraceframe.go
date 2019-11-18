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
	fn        *FunctionEntry
	Function  string    `json:"function"`
	Source    string    `json:"source"`
	PC        string    `json:"pc"`
	CFA       string    `json:"cfa"`
	FrameBase string    `json:"framebase"`
	Variables []Reading `json:"variables"`
}

// NewBacktraceFrame returns a new BacktraceFrame
func NewBacktraceFrame(pid int, fn *FunctionEntry, pc uintptr, regs *op.DwarfRegisters) (*BacktraceFrame, error) {
	vars, err := fn.GetVariables()
	if err != nil {
		return nil, common.Error(err)
	}

	values, err := GetReadings(pid, pc, regs, vars...)

	source := fmt.Sprintf("%#x (no debug info)", pc)
	if fn.entry.data != nil {
		lineEntry, _ := NewLineEntry(pc, fn.entry.data)
		if lineEntry != nil {
			filename := path.Base(lineEntry.Filename)
			source = fmt.Sprintf("%s:%d", filename, lineEntry.Line)
		}
	}

	return &BacktraceFrame{
		fn:        fn,
		Function:  fmt.Sprintf("%s (%#x+%#x)", fn.Name, fn.LowPC, fn.StaticBase),
		Source:    source,
		PC:        fmt.Sprintf("%#x", pc),
		CFA:       fmt.Sprintf("%#x", regs.CFA),
		FrameBase: fmt.Sprintf("%#x", regs.FrameBase),
		Variables: values,
	}, nil
}

// String returns the backtrace frame as a string
func (bt *BacktraceFrame) String() string {
	if len(bt.Variables) == 0 {
		return bt.fn.Name + "()"
	}

	vars := make([]string, len(bt.Variables))
	for i, v := range bt.Variables {
		vars[i] = v.String()
	}
	return fmt.Sprintf("%s(%s)", bt.fn.Name, strings.Join(vars, ","))
}
