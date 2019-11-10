package data

import (
	"github.com/razzie/raztracer/custom/dwarf/frame"
	"github.com/razzie/raztracer/custom/dwarf/op"
	"github.com/razzie/raztracer/arch"
	"github.com/razzie/raztracer/common"
)

// StackIterator iterates over stack frames
type StackIterator struct {
	proc    common.Process
	pc      uintptr
	retaddr uintptr
	regs    *op.DwarfRegisters
	fn      *FunctionEntry
	data    *DebugData
	err     error
}

// NewStackIterator returns a new StackIterator
func NewStackIterator(pid int, data *DebugData) (*StackIterator, error) {
	regs, err := common.GetDwarfRegs(pid)
	if err != nil {
		return nil, common.Error(err)
	}

	regs.StaticBase = uint64(data.staticBase)
	pc := uintptr(regs.PC())

	stack := &StackIterator{
		proc:    common.Process(pid),
		retaddr: pc,
		regs:    regs,
		data:    data}

	if pc == 0 { // PC could be 0 in case of a segfault
		if !stack.advanceRegs() {
			return nil, common.Error(stack.err)
		}
	}

	return stack, nil
}

// Next steps the iterator to the next frame. Returns false if there are no more frames.
func (it *StackIterator) Next() bool {
	it.pc = it.retaddr

	if it.pc == 0 {
		return false
	}

	it.fn, _ = it.data.GetFunctionFromPC(it.pc)
	if it.fn == nil {
		return false
	}

	fb, _ := it.fn.GetFrameBase(it.pc, it.regs)
	it.regs.FrameBase = int64(fb)
	it.regs.StaticBase = uint64(it.fn.StaticBase)

	return it.advanceRegs()
}

// Frame returns the current stack frame
func (it *StackIterator) Frame() (*BacktraceFrame, error) {
	if it.err != nil {
		return nil, common.Error(it.err)
	}

	frame, err := NewBacktraceFrame(int(it.proc), it.fn, it.pc, it.regs)
	return frame, common.Error(err)
}

// Err returns the error message from the last iteration
func (it *StackIterator) Err() error {
	return it.err
}

func (it *StackIterator) advanceRegs() bool {
	framectx, _ := it.data.GetFrameContextFromPC(it.pc)
	framectx = arch.FixFrameContext(framectx, it.pc, it.regs)

	cfareg, _ := it.executeFrameRegRule(framectx.CFA, 0)
	if cfareg == nil {
		it.err = common.Errorf("CFA becomes undefined at PC %#x", it.pc)
		return false
	}

	it.regs.CFA = int64(cfareg.Uint64Val)

	var retaddr uintptr

	for i, regRule := range framectx.Regs {
		reg, err := it.executeFrameRegRule(regRule, it.regs.CFA)
		it.regs.AddReg(i, reg)
		if i == framectx.RetAddrReg {
			if reg == nil {
				if err == nil {
					it.err = common.Errorf("undefined return address at %#x", it.pc)
					return false
				}

				it.err = common.Error(err)
				return false
			}

			retaddr = uintptr(reg.Uint64Val)
		}
	}

	it.retaddr = retaddr

	return true
}

func (it *StackIterator) executeFrameRegRule(rule frame.DWRule, cfa int64) (*op.DwarfRegister, error) {
	switch rule.Rule {
	default:
		fallthrough

	case frame.RuleUndefined:
		return nil, nil

	case frame.RuleSameVal:
		reg := *it.regs.Reg(rule.Reg)
		return &reg, nil

	case frame.RuleOffset:
		val, err := it.proc.ReadAddressAt(uintptr(cfa + rule.Offset))
		return op.DwarfRegisterFromUint64(uint64(val)), common.Error(err)

	case frame.RuleValOffset:
		return op.DwarfRegisterFromUint64(uint64(cfa + rule.Offset)), nil

	case frame.RuleRegister:
		return it.regs.Reg(rule.Reg), nil

	case frame.RuleExpression:
		v, _, err := op.ExecuteStackProgram(*it.regs, rule.Expression)
		if err != nil {
			return nil, err
		}
		val, err := it.proc.ReadAddressAt(uintptr(v))
		return op.DwarfRegisterFromUint64(uint64(val)), common.Error(err)

	case frame.RuleValExpression:
		v, _, err := op.ExecuteStackProgram(*it.regs, rule.Expression)
		if err != nil {
			return nil, err
		}
		return op.DwarfRegisterFromUint64(uint64(v)), nil

	case frame.RuleArchitectural:
		return nil, common.Errorf("architectural frame rules are unsupported")

	case frame.RuleCFA:
		cfareg := it.regs.Reg(rule.Reg)
		if cfareg == nil {
			return nil, nil
		}
		return op.DwarfRegisterFromUint64(uint64(int64(cfareg.Uint64Val) + rule.Offset)), nil

	case frame.RuleFramePointer:
		curReg := it.regs.Reg(rule.Reg)
		if curReg == nil {
			return nil, nil
		}
		if curReg.Uint64Val <= uint64(cfa) {
			val, err := it.proc.ReadAddressAt(uintptr(curReg.Uint64Val))
			return op.DwarfRegisterFromUint64(uint64(val)), common.Error(err)
		}
		newReg := *curReg
		return &newReg, nil
	}
}
