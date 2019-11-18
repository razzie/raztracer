package data

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/razzie/raztracer/common"
	"github.com/razzie/raztracer/custom/dwarf/op"
)

// Reading contains the PC dependent location and value of a variable
type Reading struct {
	Variable *VariableEntry `json:"variable"`
	Location string         `json:"location"`
	Value    string         `json:"value"`
	Error    string         `json:"error"`
}

// NewReading returns a new Reading
func NewReading(v *VariableEntry, pid int, pc uintptr, regs *op.DwarfRegisters) (*Reading, error) {
	r := &Reading{}

	loc, data, err := v.GetValue(pid, pc, regs)
	if loc != nil {
		r.Location = loc.String()
	}
	if err != nil {
		r.Error = fmt.Sprint(err.Err)
		return r, common.Error(err)
	}

	if v.IsPointer {
		addr := common.ReadAddress(data)
		r.Value = fmt.Sprintf("%#x : ", addr)

		if isStringType(v.Type) {
			v.Size = 0
			data, err := readString(pid, uintptr(addr))
			if err != nil {
				return r, common.Error(err)
			}

			r.Value += string(data)
			return r, nil
		}

		data = make([]byte, v.Size)
		err := common.Process(pid).PeekData(addr, data)
		if err != nil {
			r.Error = fmt.Sprintf("couldn't read data at location:%#x", addr)
			return r, common.Error(err)
		}
	}

	if len(data) > int(v.Size) {
		data = data[:v.Size]
	}

	r.Value += "0x" + hex.EncodeToString(data)
	return r, nil

}

// GetReadings returns returns variable readings
func GetReadings(pid int, pc uintptr, regs *op.DwarfRegisters, vars ...*VariableEntry) ([]Reading, error) {
	var errors []error
	readings := make([]Reading, 0, len(vars))
	for _, v := range vars {
		r, err := NewReading(v, pid, pc, regs)
		if err != nil {
			errors = append(errors, err)
		} else {
			readings = append(readings, *r)
		}
	}
	return readings, common.MergeErrors(errors)
}

// String returns the variable reading as a string
func (r *Reading) String() string {
	if r.Value == "" {
		return r.Variable.Name
	}

	return r.Variable.Name + "=" + strings.Split(r.Value, "\n")[0]
}

func isStringType(typeName string) bool {
	switch typeName {
	case "char*":
		return true

	default:
		return false
	}
}

func readString(pid int, addr uintptr) ([]byte, error) {
	str := make([]byte, 0)
	proc := common.Process(pid)

	for {
		var buf [common.SizeofPtr]byte

		err := proc.PeekData(addr, buf[:])
		if err != nil {
			if len(str) == 0 {
				return nil, common.Error(err)
			}
			break
		}
		addr += uintptr(len(buf))

		for i, c := range buf {
			if c == 0 {
				str = append(str, buf[:i]...)
				return str, nil
			}
		}

		str = append(str, buf[:]...)

		if len(str) > 256 {
			break
		}
	}

	return str, nil
}
