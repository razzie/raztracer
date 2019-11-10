package common

import (
	"bytes"

	"github.com/razzie/raztracer/arch"
)

var trapInstructionSize = uintptr(len(arch.TrapInstruction))
var emptyInstr = make([]byte, len(arch.TrapInstruction))

// Breakpoint represents a software breakpoint
type Breakpoint struct {
	pid       Process
	addr      uintptr
	enabled   bool
	savedData []byte
}

// NewBreakpoint returns an initialized but disabled breakpoint
func NewBreakpoint(pid Process, addr uintptr) *Breakpoint {
	return &Breakpoint{
		pid:       pid,
		addr:      addr,
		enabled:   false,
		savedData: make([]byte, trapInstructionSize)}
}

// Enable sets a software breakpoint
func (bp *Breakpoint) Enable() error {
	if bp.enabled {
		return Errorf("breakpoint already enabled")
	}

	err := bp.pid.PeekData(bp.addr, bp.savedData)
	if err != nil {
		return Error(err)
	}

	if bytes.Equal(bp.savedData, emptyInstr) {
		return Errorf("could not save original instruction at %x", bp.addr)
	}

	err = bp.pid.PokeData(bp.addr, arch.TrapInstruction)
	if err != nil {
		return Error(err)
	}

	bp.enabled = true
	return nil
}

// Disable restores the state before the breakpoint was set
func (bp *Breakpoint) Disable() error {
	if !bp.enabled {
		return Errorf("breakpoint already disabled")
	}

	err := bp.pid.PokeData(bp.addr, bp.savedData)
	if err != nil {
		return Error(err)
	}

	bp.enabled = false
	return nil
}

// IsEnabled returns whether the software breakpoint is set
func (bp *Breakpoint) IsEnabled() bool {
	return bp.enabled
}

// GetAddress returns the address of the breakpoint
func (bp *Breakpoint) GetAddress() uintptr {
	return bp.addr
}
