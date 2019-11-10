package common

import (
	"github.com/razzie/raztracer/custom/op"
	"github.com/razzie/raztracer/arch"
)

// GetDwarfRegs returns the current register values mapped to dwarf register numbers
func GetDwarfRegs(pid int) (*op.DwarfRegisters, error) {
	regs, err := Process(pid).GetRegs()
	if err != nil {
		return nil, Error(err)
	}

	dregs := &op.DwarfRegisters{
		Regs:      make([]*op.DwarfRegister, len(regs)),
		ByteOrder: ByteOrder}

	dregs.PCRegNum, _ = arch.AsmToDwarfReg(arch.PCRegNum)
	dregs.SPRegNum, _ = arch.AsmToDwarfReg(arch.SPRegNum)
	dregs.BPRegNum, _ = arch.AsmToDwarfReg(arch.FPRegNum)

	for i, reg := range regs {
		dreg := &op.DwarfRegister{Uint64Val: uint64(reg)}
		if dregnum, ok := arch.AsmToDwarfReg(i); ok {
			dregs.AddReg(dregnum, dreg)
		}
	}

	return dregs, nil
}
