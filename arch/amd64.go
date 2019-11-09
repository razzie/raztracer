// +build amd64

package arch

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
