package raztracer

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"syscall"
	"time"
)

// TraceEvent is received when a breakpoint is hit or the process receives a signal
type TraceEvent struct {
	Status       syscall.WaitStatus `json:"-"`
	Signal       syscall.Signal     `json:"signal"`
	PID          Process            `json:"pid"`
	TID          Process            `json:"tid"`
	IsBreakpoint bool               `json:"breakpoint"`
	PC           uintptr            `json:"pc"`
	Registers    map[string]string  `json:"regs"`
	Globals      []Reading          `json:"globals"`
	Backtrace    []*BacktraceFrame  `json:"backtrace"`
}

// Tracer is used to trace a running process
type Tracer struct {
	progName      string
	pid, tid      Process
	debugData     *DebugData
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

	debugData, err := NewDebugData(prog, 0)
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
func (t *Tracer) GetDebugData() *DebugData {
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

	var errors []error

	for _, tid := range threads {
		err := Error(tid.Interrupt())
		if err != nil {
			errors = append(errors, Error(err))
		}

		t.tid = tid
		err = Error(t.stepOverBreakpoint())
		if err != nil {
			errors = append(errors, Error(err))
		}
	}

	for _, bp := range t.breakpoints {
		err := Error(bp.Disable())
		if err != nil {
			errors = append(errors, Error(err))
		}
	}

	t.tid = 0
	t.breakpoints = make(map[uintptr]*Breakpoint)

	for _, tid := range threads {
		err := Error(tid.Detach())
		if err != nil {
			errors = append(errors, Error(err))
		}
	}

	return MergeErrors(errors)
}

// GetPC gets the program counter
func (t *Tracer) GetPC() (uintptr, error) {
	regs, err := t.tid.GetRegs()
	if err != nil {
		return 0, Error(err)
	}

	return uintptr(regs[PCRegNum]), nil
}

// SetPC sets the program counter
func (t *Tracer) SetPC(pc uintptr) error {
	regs, err := t.tid.GetRegs()
	if err != nil {
		return Error(err)
	}

	regs[PCRegNum] = uint(pc)
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

// GetBacktrace gets the list of backtrace frames of the process
func (t *Tracer) GetBacktrace(maxFrames int) ([]*BacktraceFrame, error) {
	frames := make([]*BacktraceFrame, 0)
	stack, err := NewStackIterator(t.tid, t.debugData)
	if err != nil {
		return frames, Error(err)
	}

	for i := 0; stack.Next() && i < maxFrames; i++ {
		frame, err := stack.Frame()
		if err != nil {
			return frames, Error(err)
		}

		frames = append(frames, frame)
	}

	return frames, Error(stack.Err())
}

// GetGlobals returns the list of global variables
func (t *Tracer) GetGlobals() ([]Reading, error) {
	vars := t.debugData.GetGlobals()

	regs, err := GetDwarfRegs(t.tid)
	if err != nil {
		return nil, Error(err)
	}

	values, err := GetReadings(int(t.pid), 0, regs, vars...)
	return values, Error(err)
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

// SetBreakpoint sets a breakpoint at the given address
func (t *Tracer) SetBreakpoint(addr uintptr) error {
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

// RemoveBreakpoint removes the breakpoint at the given address
func (t *Tracer) RemoveBreakpoint(addr uintptr) error {
	bp, found := t.breakpoints[addr]

	if found {
		if bp.IsEnabled() {
			//bp.pid = t.tid
			err := bp.Disable()
			if err != nil {
				return Error(err)
			}
		}
		delete(t.breakpoints, addr)
	}

	return nil
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
			err = t.tid.SingleStep()
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

	var errors []error
	for _, tid := range threads {
		err := tid.Cont()
		if err != nil {
			errors = append(errors, err)
		}
	}

	return MergeErrors(errors)
}

// Interrupt interrupts the process to be able to set breakpoints
func (t *Tracer) Interrupt() error {
	threads, err := t.pid.Threads()
	if err != nil {
		return Error(err)
	}

	var errors []error
	for _, tid := range threads {
		err := tid.Interrupt()
		if err != nil {
			errors = append(errors, err)
		}
	}

	return MergeErrors(errors)
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

	evt.Globals, err = t.GetGlobals()
	if err != nil {
		return evt, Error(err)
	}

	return evt, nil
}
