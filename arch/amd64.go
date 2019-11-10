// +build amd64

package arch

import (
	"github.com/razzie/raztracer/custom/frame"
	"github.com/razzie/raztracer/custom/op"
	"github.com/razzie/raztracer/common"
)

// TrapInstruction contains the int3 trap instruction for x86-64 platform
var TrapInstruction = []byte{0xcc} // int3

// https://github.com/torvalds/linux/blob/master/arch/x86/include/uapi/asm/ptrace.h#L44
// Indexes to special purpose registers
const (
	PCRegNum = 16 // rip
	SPRegNum = 19 // rsp
	FPRegNum = 4  // rbp
)

// AsmToDwarfReg converts a ptrace reg number to dwarf reg number
func AsmToDwarfReg(reg int) (uint64, bool) {
	asm2dwarf := map[int]uint64{
		0:  15,
		1:  14,
		2:  13,
		3:  12,
		4:  6, // rbp
		5:  3,
		6:  11,
		7:  10,
		8:  9,
		9:  8,
		10: 0,
		11: 2,
		12: 1,
		13: 4,
		14: 5,
		16: 49, // rip
		19: 7}  // rsp

	dreg, ok := asm2dwarf[reg]
	return dreg, ok
}

// FixFrameContext inserts missing rules to the frame context
func FixFrameContext(framectx *frame.FrameContext, pc uintptr, regs *op.DwarfRegisters) *frame.FrameContext {
	if framectx == nil {
		framectx = &frame.FrameContext{
			RetAddrReg: 16,
			Regs: map[uint64]frame.DWRule{
				16: frame.DWRule{
					Rule:   frame.RuleFramePointer,
					Reg:    16,
					Offset: -int64(common.SizeofPtr),
				},
				6: frame.DWRule{
					Rule:   frame.RuleOffset,
					Reg:    6,
					Offset: -2 * int64(common.SizeofPtr),
				},
				7: frame.DWRule{
					Rule:   frame.RuleValOffset,
					Reg:    7,
					Offset: 0,
				},
			},
			CFA: frame.DWRule{
				Rule:   frame.RuleCFA,
				Reg:    6,
				Offset: 2 * int64(common.SizeofPtr),
			},
		}
	}

	if framectx.Regs[6].Rule == frame.RuleUndefined {
		framectx.Regs[6] = frame.DWRule{
			Rule:   frame.RuleFramePointer,
			Reg:    6,
			Offset: 0,
		}
	}

	return framectx
}
