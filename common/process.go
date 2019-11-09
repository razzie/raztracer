package common

import (
	"fmt"
	"io/ioutil"
	"reflect"
	"runtime"
	"strconv"
	"syscall"
	"time"
)

// Process is a wrapper around Linux's ptrace API
type Process int

// Threads return the threads of the process
func (pid Process) Threads() ([]Process, error) {
	tasks, err := ioutil.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		return nil, fmt.Errorf("Process not found: %d", pid)
	}

	threads := make([]Process, len(tasks))

	for i, task := range tasks {
		tid, _ := strconv.Atoi(task.Name())
		threads[i] = Process(tid)
	}

	return threads, nil
}

// Attach starts tracing the process and all of its threads
func (pid Process) Attach() error {
	err := syscall.PtraceAttach(int(int(pid)))
	if err == syscall.EPERM {
		_, err := syscall.PtraceGetEventMsg(int(pid))
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}

	pid.simpleWait(time.Second)
	// we want to try to set these options even if wait failed

	return pid.setOptions(syscall.PTRACE_O_TRACECLONE | syscall.PTRACE_O_TRACEFORK)
}

// Detach stops the tracing the process
func (pid Process) Detach() error {
	return syscall.PtraceDetach(int(pid))
}

// Wait waits for a trace event (signal or breakpoint stop)
func (pid Process) Wait(status *syscall.WaitStatus, timeout time.Duration) (int, error) {
	pgid, _ := syscall.Getpgid(int(pid))
	timer := time.NewTimer(timeout)

	for {
		select {
		case <-timer.C:
			return 0, nil

		default:
		}

		wpid, err := syscall.Wait4(-int(pgid), status, syscall.WALL|syscall.WUNTRACED|syscall.WNOHANG, nil)
		if err != nil {
			return 0, err
		}

		if wpid <= 0 {
			runtime.Gosched()
			continue
		}

		if status.Exited() || status.Continued() {
			continue
		}

		if status.Stopped() {
			sig := status.StopSignal()
			trapCause := status.TrapCause()

			if sig == syscall.SIGTRAP {
				switch trapCause {
				case 0:
					return wpid, nil

				case syscall.PTRACE_EVENT_CLONE, syscall.PTRACE_EVENT_FORK:
					newpid, err := syscall.PtraceGetEventMsg(wpid)
					if err != nil {
						return 0, err
					}
					Process(newpid).Attach()
					Process(newpid).Cont()
				}

				syscall.PtraceCont(wpid, 0)
				continue
			}

			return wpid, nil
		}

		if status.Signaled() {
			return wpid, nil
		}
	}
}

func (pid Process) simpleWait(timeout time.Duration) error {
	pgid, _ := syscall.Getpgid(int(pid))
	timer := time.NewTimer(timeout)

	for {
		select {
		case <-timer.C:
			return fmt.Errorf("timeout")

		default:
		}

		wpid, err := syscall.Wait4(-int(pgid), nil, syscall.WALL|syscall.WUNTRACED|syscall.WNOHANG, nil)
		if err != nil {
			return err
		}

		if wpid <= 0 {
			runtime.Gosched()
			continue
		}

		break
	}

	return nil
}

// Cont continues the traced process
func (pid Process) Cont() error {
	return pid.ContWithSig(syscall.SIGCONT)
}

// ContWithSig continues the traced process and delivers a signal
func (pid Process) ContWithSig(sig syscall.Signal) error {
	return syscall.PtraceCont(int(pid), int(sig))
}

// Interrupt interrupts the traced process
func (pid Process) Interrupt() error {
	err := syscall.Kill(int(pid), syscall.SIGSTOP)
	if err != nil {
		return err
	}

	return pid.simpleWait(time.Second)
}

func (pid Process) getEventMsg() (uint, error) {
	rv, err := syscall.PtraceGetEventMsg(int(pid))
	return rv, err
}

// GetRegs returns the register values of the process as a slice
func (pid Process) GetRegs() ([]uint, error) {
	var pregs syscall.PtraceRegs
	err := syscall.PtraceGetRegs(int(pid), &pregs)
	if err != nil {
		return nil, err
	}

	val := reflect.ValueOf(pregs)
	regs := make([]uint, val.NumField())
	for i := 0; i < len(regs); i++ {
		regs[i] = uint(val.Field(i).Uint())
	}

	return nil, nil
}

// SetRegs sets the registers of the process from the given slice of values
func (pid Process) SetRegs(regs []uint) error {
	var pregs syscall.PtraceRegs

	val := reflect.ValueOf(pregs)
	regs = regs[:val.NumField()]
	for i := 0; i < len(regs); i++ {
		val.Field(i).SetUint(uint64(regs[i]))
	}

	return syscall.PtraceSetRegs(int(pid), &pregs)
}

// PeekData reads arbitrary length data from the process' memory
func (pid Process) PeekData(addr uintptr, out []byte) error {
	_, err := syscall.PtracePeekData(int(pid), addr, out)
	return err
}

// PokeData writes arbitrary length data to the process' memory
func (pid Process) PokeData(addr uintptr, data []byte) error {
	_, err := syscall.PtracePokeData(int(pid), addr, data)
	return err
}

// ReadAddressAt reads an address from the pointed location
func (pid Process) ReadAddressAt(addr uintptr) (uintptr, error) {
	data := make([]byte, SizeofPtr)
	err := pid.PeekData(addr, data)
	if err != nil {
		return 0, err
	}

	return ReadAddress(data), nil
}

func (pid Process) setOptions(options int) error {
	return syscall.PtraceSetOptions(int(pid), options)
}

// SingleStep makes the process execute a single instruction and stop again
func (pid Process) SingleStep() error {
	err := syscall.PtraceSingleStep(int(pid))
	if err != nil {
		return err
	}

	return pid.simpleWait(time.Second)
}
