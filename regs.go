package raztracer

import (
	"github.com/razzie/raztracer/internal/dwarf/op"
)

// GetDwarfRegs returns the current register values mapped to dwarf register numbers
func GetDwarfRegs(pid Process) (*op.DwarfRegisters, error) {
	regs, err := pid.GetRegs()
	if err != nil {
		return nil, Error(err)
	}

	dregs := &op.DwarfRegisters{
		Regs:      make([]*op.DwarfRegister, len(regs)),
		ByteOrder: ByteOrder}

	dregs.PCRegNum, _ = AsmToDwarfReg(PCRegNum)
	dregs.SPRegNum, _ = AsmToDwarfReg(SPRegNum)
	dregs.BPRegNum, _ = AsmToDwarfReg(FPRegNum)

	for i, reg := range regs {
		dreg := &op.DwarfRegister{Uint64Val: uint64(reg)}
		if dregnum, ok := AsmToDwarfReg(i); ok {
			dregs.AddReg(dregnum, dreg)
		}
	}

	return dregs, nil
}
