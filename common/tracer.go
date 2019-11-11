package common

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/razzie/raztracer/arch"
	"github.com/razzie/raztracer/data"
)

// TraceEvent is received when a breakpoint is hit or the process receives a signal
type TraceEvent struct {
	Status       syscall.WaitStatus
	Signal       syscall.Signal
	PID, TID     Process
	IsBreakpoint bool
	PC           uintptr
	Registers    map[string]string
	Globals      []*data.VariableEntry
	Backtrace    []*data.BacktraceFrame
}

// Tracer is used to trace a running process
type Tracer struct {
	progName      string
	pid, tid      Process
	debugData     *data.DebugData
	breakpoints   map[uintptr]*Breakpoint
	deliverSignal syscall.Signal
}

// NewTracer returns a Tracer instance attached to 'pid' process
func NewTracer(pid int) (*Tracer, error) {
	prog, err := os.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return nil, Errorf("process not found: %d", pid)
	}

	progNameBytes, _ := ioutil.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	progName := strings.TrimSuffix(string(progNameBytes), "\n")

	debugData, err := data.NewDebugData(prog, 0)
	if err != nil {
		return nil, Error(err)
	}

	proc := Process(pid)
	libs, _ := proc.SharedLibs()
	for _, lib := range libs {
		debugData.AddSharedLib(lib)
	}

	breakpoints := make(map[uintptr]*Breakpoint)

	t := &Tracer{
		progName:      progName,
		pid:           proc,
		tid:           0,
		debugData:     debugData,
		breakpoints:   breakpoints,
		deliverSignal: syscall.SIGCONT,
	}

	return t, t.Attach()
}

// GetProgName returns the basename of the process being traced
func (t *Tracer) GetProgName() string {
	return t.progName
}

// GetDebugData returns the debug data of the traced process
func (t *Tracer) GetDebugData() *data.DebugData {
	return t.debugData
}

// Attach attaches the Tracer to the running process
func (t *Tracer) Attach() error {
	threads, err := t.pid.Threads()
	if err != nil {
		return Error(err)
	}

	for _, tid := range threads {
		tid.Attach()
	}

	return nil
}

// Detach detaches the Tracer from the running process
func (t *Tracer) Detach() error {
	if t.deliverSignal == syscall.SIGSEGV {
		return nil
	}

	threads, err := t.pid.Threads()
	if err != nil {
		return Error(err)
	}

	for _, tid := range threads {
		err := Error(tid.Interrupt())
		if err != nil {
			fmt.Println(err)
		}

		t.tid = tid
		err = Error(t.stepOverBreakpoint())
		if err != nil {
			fmt.Println(err)
		}
	}

	for _, bp := range t.breakpoints {
		err := Error(bp.Disable())
		if err != nil {
			fmt.Println(err)
		}
	}

	t.tid = 0
	t.breakpoints = make(map[uintptr]*Breakpoint)

	for _, tid := range threads {
		err := Error(tid.Detach())
		if err != nil {
			fmt.Println(err)
		}
	}

	return nil
}

// GetPC gets the program counter
func (t *Tracer) GetPC() (uintptr, error) {
	regs, err := t.tid.GetRegs()
	if err != nil {
		return 0, Error(err)
	}

	return uintptr(regs[arch.PCRegNum]), nil
}

// SetPC sets the program counter
func (t *Tracer) SetPC(pc uintptr) error {
	regs, err := t.tid.GetRegs()
	if err != nil {
		return Error(err)
	}

	regs[arch.PCRegNum] = uint(pc)
	return Error(t.tid.SetRegs(regs))
}

// GetRegisters returns the register values of a running process in a map
func (t *Tracer) GetRegisters() (map[string]string, error) {
	regs, err := GetDwarfRegs(t.tid)
	if err != nil {
		return nil, Error(err)
	}

	regMap := make(map[string]string)

	for reg, regVal := range regs.Regs {
		if regVal == nil {
			continue
		}

		var regName string

		if reg < 32 {
			regName = fmt.Sprintf("DW_OP_reg%d", reg)
		} else {
			regName = fmt.Sprintf("DW_OP_regx %#x", reg)
		}

		switch uint64(reg) {
		case regs.PCRegNum:
			regName += " (PC)"
		case regs.SPRegNum:
			regName += " (SP)"
		case regs.BPRegNum:
			regName += " (FP/BP)"
		}

		regMap[regName] = fmt.Sprintf("%#x", regVal.Uint64Val)
	}

	return regMap, nil
}

// ReadMemory reads the process' memory to the given buffer
func (t *Tracer) ReadMemory(addr uintptr, out []byte) error {
	return t.tid.PeekData(addr, out)
}

// GetBacktrace gets the list of backtrace frames of the process
func (t *Tracer) GetBacktrace(maxFrames int) ([]*data.BacktraceFrame, error) {
	frames := make([]*data.BacktraceFrame, 0)
	stack, err := data.NewStackIterator(int(t.tid), t.debugData)
	if err != nil {
		return frames, Error(err)
	}

	for i := 0; stack.Next() && i < maxFrames; i++ {
		frame, err := stack.Frame()
		if err != nil {
			fmt.Println(Error(err))
			return frames, Error(err)
		}

		frames = append(frames, frame)
	}

	return frames, Error(stack.Err())
}

// GetGlobals returns the list of global variables in the compilation unit of PC
func (t *Tracer) GetGlobals(pc uintptr) ([]*data.VariableEntry, error) {
	vars, err := t.debugData.GetGlobals(pc)
	if err != nil {
		return nil, Error(err)
	}

	regs, err := GetDwarfRegs(t.tid)
	if err != nil {
		return nil, Error(err)
	}

	for _, v := range vars {
		v.ReadValue(int(t.tid), pc, regs)
	}

	return vars, nil
}

func (t *Tracer) continueExecution() error {
	if t.tid == 0 {
		return nil
	}

	err := t.stepOverBreakpoint()
	if err != nil {
		return Error(err)
	}

	err = t.tid.ContWithSig(t.deliverSignal)
	if err != nil {
		return Error(err)
	}

	t.tid = 0

	return nil
}

// RemoveBreakpoint removes the breakpoint at the given address
func (t *Tracer) RemoveBreakpoint(addr uintptr) error {
	var err error
	bp, found := t.breakpoints[addr]

	if found {
		if bp.IsEnabled() {
			//bp.pid = t.tid
			err = Error(bp.Disable())
		}
		delete(t.breakpoints, addr)
	}

	return err
}

// SetBreakpointAtFunction sets a breakpoint at the given function
func (t *Tracer) SetBreakpointAtFunction(name string, exact bool) ([]uintptr, error) {
	addresses := t.debugData.GetFunctionAddresses(name, exact)

	if len(addresses) == 0 {
		return nil, Errorf("function not found: %s", name)
	}

	for i, addr := range addresses {
		err := t.SetBreakpointAtAddress(addr)
		if err != nil {
			return addresses[:i], Error(err)
		}
	}

	return addresses, nil
}

// SetBreakpointAtAddress sets a breakpoint at the given address
func (t *Tracer) SetBreakpointAtAddress(addr uintptr) error {
	_, exists := t.breakpoints[addr]
	if exists {
		return Errorf("breakpoint already exists %#x", addr)
	}

	bp := NewBreakpoint(t.pid, addr)
	err := bp.Enable()
	if err != nil {
		return Error(err)
	}

	t.breakpoints[addr] = bp
	return nil
}

func (t *Tracer) singleStepInstruction() error {
	return Error(t.tid.SingleStep())
}

func (t *Tracer) stepOverBreakpoint() error {
	addr, err := t.GetPC()
	if err != nil {
		return Error(err)
	}

	bp, found := t.breakpoints[addr]
	if found && bp.IsEnabled() {
		bp.pid = t.tid

		err := bp.Disable()
		if err != nil {
			return Error(err)
		}

		for {
			err = t.singleStepInstruction()
			if err != nil {
				return Error(err)
			}

			pc, err := t.GetPC()
			if err != nil {
				return Error(err)
			}

			if pc >= addr+trapInstructionSize || pc < addr {
				break
			}
		}

		err = bp.Enable()
		if err != nil {
			return Error(err)
		}
	}

	return nil
}

// Run continues the process after all the breakpoints are set
func (t *Tracer) Run() error {
	threads, err := t.pid.Threads()
	if err != nil {
		return Error(err)
	}

	for _, tid := range threads {
		err := tid.Cont()
		if err != nil {
			return Error(err)
		}
	}

	return nil
}

// Interrupt interrupts the process to be able to set breakpoints
func (t *Tracer) Interrupt() error {
	threads, err := t.pid.Threads()
	if err != nil {
		return Error(err)
	}

	for _, tid := range threads {
		err := tid.Interrupt()
		if err != nil {
			return Error(err)
		}
	}

	return nil
}

// WaitForEvent blocks until a trace event happens, then returns it
func (t *Tracer) WaitForEvent(timeout time.Duration) (*TraceEvent, error) {
	err := t.continueExecution()
	if err != nil {
		return nil, Error(err)
	}

	evt := &TraceEvent{}
	wpid, err := t.pid.Wait(&evt.Status, timeout)
	if err != nil {
		return nil, Error(err)
	} else if wpid == 0 {
		return nil, nil
	}

	t.deliverSignal = syscall.SIGCONT
	t.tid = wpid // important to set t.tid before reading PC

	evt.PID = t.pid
	evt.TID = wpid
	evt.PC, err = t.GetPC()
	if err != nil {
		return nil, Error(err)
	}

	if evt.Status.Stopped() {
		evt.Signal = evt.Status.StopSignal()
	} else {
		evt.Signal = evt.Status.Signal()
	}

	if evt.Signal == syscall.SIGTRAP {
		_, evt.IsBreakpoint = t.breakpoints[evt.PC-trapInstructionSize]

		if evt.IsBreakpoint {
			evt.PC -= trapInstructionSize
			err := t.SetPC(evt.PC)
			if err != nil {
				return nil, Error(err)
			}
		}
	} else {
		t.deliverSignal = evt.Signal
	}

	evt.Registers, err = t.GetRegisters()
	if err != nil {
		return evt, Error(err)
	}

	evt.Backtrace, err = t.GetBacktrace(8)
	if err != nil {
		return evt, Error(err)
	}

	evt.Globals, err = t.GetGlobals(evt.PC)
	if err != nil {
		return evt, Error(err)
	}

	return evt, nil
}
