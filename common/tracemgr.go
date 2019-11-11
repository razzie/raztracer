package common

import (
	"fmt"
	"runtime"
	"syscall"
	"time"
)

// TraceManager is an automated tracer of a process that collects events
type TraceManager struct {
	tracer    *Tracer
	eventFunc func(*Tracer, *TraceEvent, error)
	requests  chan traceRequest
	pid       int
}

// NewTraceManager creates a new TraceManager
func NewTraceManager(pid int, eventFunc func(*Tracer, *TraceEvent, error)) (*TraceManager, error) {
	TraceManager := &TraceManager{
		tracer:    nil, // will be set later
		eventFunc: eventFunc,
		requests:  make(chan traceRequest, 1),
		pid:       pid,
	}

	errOut := make(chan error, 1)
	go TraceManager.run(errOut)

	if err := <-errOut; err != nil {
		return nil, Error(err)
	}

	return TraceManager, nil
}

// Close detaches the tracer from the process and stops the tracer's thread
func (proc *TraceManager) Close() error {
	req := func(*Tracer) error {
		err := proc.tracer.Detach()
		proc.tracer = nil
		return err
	}

	err := proc.HandleRequest(req)
	close(proc.requests)
	proc.requests = nil
	return Error(err)
}

func (proc *TraceManager) run(errOut chan<- error) {
	runtime.LockOSThread()

	tracer, err := NewTracer(proc.pid)
	if err != nil {
		errOut <- Error(err)
		return
	}

	proc.tracer = tracer

	tracer.Run()
	errOut <- nil // notify NewTraceManager everything is awesome

	for {
		select {
		case req := <-proc.requests:
			req.err <- Error(req.fn(tracer))

		default:
		}

		if proc.requests == nil {
			return
		}

		event, err := tracer.WaitForEvent(100 * time.Millisecond)
		if event == nil && err == nil {
			continue
		}

		proc.eventFunc(tracer, event, Error(err))

		if err != nil || (event != nil && event.Signal == syscall.SIGSEGV) {
			proc.tracer = nil
			err := tracer.Detach()
			if err != nil {
				fmt.Println(Error(err))
			}
			return
		}
	}
}

// HandleRequest is a blocking call to the provided function in the tracer's thread
func (proc *TraceManager) HandleRequest(fn func(*Tracer) error) error {
	if proc.tracer == nil {
		return fmt.Errorf("the inner debugger is already detached")
	}

	req := traceRequest{
		fn:  fn,
		err: make(chan error),
	}

	proc.requests <- req
	return Error(<-req.err)
}

type traceRequest struct {
	fn  func(*Tracer) error
	err chan error
}
