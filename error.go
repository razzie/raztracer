package raztracer

import (
	"fmt"
	"runtime"
	"strings"
)

// TracedError contains an error and the list of origin frames
type TracedError struct {
	Err    error
	Frames []runtime.Frame
}

// Error implements error interface
func (err *TracedError) Error() string {
	str := fmt.Sprint(err.Err)
	for _, frame := range err.Frames {
		str += fmt.Sprintf("\n[%s:%d]", frame.Function, frame.Line)
	}
	return str
}

// Error creates a new TracedError from 'e' or appends a new frame if 'e' is TracedError
func Error(e interface{}) *TracedError {
	if e == nil {
		return nil
	}

	frame := getLastFrame()

	switch err := e.(type) {
	case *TracedError:
		err.Frames = append(err.Frames, frame)
		return err

	case error:
		return &TracedError{
			Err:    err,
			Frames: []runtime.Frame{frame},
		}

	default:
		return &TracedError{
			Err:    fmt.Errorf("%v", e),
			Frames: []runtime.Frame{frame},
		}
	}
}

// Errorf creates a new TracedError using the provided format and args
func Errorf(format string, args ...interface{}) *TracedError {
	return &TracedError{
		Err:    fmt.Errorf(format, args...),
		Frames: []runtime.Frame{getLastFrame()},
	}
}

// MergeErrors merges multiple errors into a single TracedError
func MergeErrors(errors []error) *TracedError {
	if len(errors) == 0 {
		return nil
	}

	str := make([]string, 0, len(errors))
	for _, err := range errors {
		str = append(str, fmt.Sprint(err))
	}

	return &TracedError{
		Err:    fmt.Errorf("%s", strings.Join(str, "; ")),
		Frames: []runtime.Frame{getLastFrame()},
	}
}

func getLastFrame() runtime.Frame {
	pc := make([]uintptr, 1)
	n := runtime.Callers(3, pc)
	frames := runtime.CallersFrames(pc[:n])
	frame, _ := frames.Next()

	return frame
}
