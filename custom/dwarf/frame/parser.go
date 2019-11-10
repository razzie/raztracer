// Package frame contains data structures and
// related functions for parsing and searching
// through Dwarf .debug_frame data.
package frame

import (
	"bytes"
	"encoding/binary"
	"strings"

	"github.com/razzie/raztracer/custom/dwarf/util"
)

type parsefunc func(*parseContext) parsefunc

type parseContext struct {
	offset     uint64
	staticBase uint64

	buf     *bytes.Buffer
	order   binary.ByteOrder
	entries FrameDescriptionEntries
	common  *CommonInformationEntry
	frame   *FrameDescriptionEntry
	length  uint32
}

// Parse takes in data (a byte slice) and returns a slice of
// commonInformationEntry structures. Each commonInformationEntry
// has a slice of frameDescriptionEntry structures.
func Parse(data []byte, order binary.ByteOrder, offset, staticBase uint64) FrameDescriptionEntries {
	var (
		buf  = bytes.NewBuffer(data)
		pctx = &parseContext{
			buf:        buf,
			order:      order,
			entries:    NewFrameIndex(),
			offset:     offset,
			staticBase: staticBase}
	)

	for fn := parselength; buf.Len() != 0; {
		fn = fn(pctx)
	}

	for i := range pctx.entries {
		pctx.entries[i].order = order
	}

	return pctx.entries
}

func cieEntry(data []byte) bool {
	return bytes.Equal(data, []byte{0x0, 0x0, 0x0, 0x0})
}

func parselength(ctx *parseContext) parsefunc {
	binary.Read(ctx.buf, binary.LittleEndian, &ctx.length)

	if ctx.length == 0 {
		// ZERO terminator
		return parselength
	}

	var data = ctx.buf.Next(4)

	ctx.length -= 4 // take off the length of the CIE id / CIE pointer.

	if cieEntry(data) {
		ctx.common = &CommonInformationEntry{Length: ctx.length, staticBase: ctx.staticBase}
		return parseCIE
	}

	ctx.frame = &FrameDescriptionEntry{Length: ctx.length, CIE: ctx.common}
	return parseFDE
}

func parseFDE(ctx *parseContext) parsefunc {
	pc := uint64(ctx.buf.Cap()-ctx.buf.Len()) + ctx.offset
	r := ctx.buf.Next(int(ctx.length))
	buf := bytes.NewBuffer(r)
	encoding := ctx.common.AugmentationData[0]

	ctx.frame.begin = util.DecodePointer(encoding, ctx.order, pc, buf) + ctx.staticBase
	ctx.frame.size = util.DecodePointer(encoding&0xF, ctx.order, 0, buf)

	if strings.Contains(ctx.common.Augmentation, "z") {
		// read augmentation length
		augLength, _ := util.DecodeULEB128(buf)

		// read augmentation data
		ctx.frame.AugmentationData = buf.Next(int(augLength))
	}

	// Insert into the tree after setting address range begin
	// otherwise compares won't work.
	ctx.entries = append(ctx.entries, ctx.frame)

	// The rest of this entry consists of the instructions
	// so we can just grab all of the data from the buffer
	// cursor to length.
	ctx.frame.Instructions = buf.Bytes()
	ctx.length = 0

	return parselength
}

func parseCIE(ctx *parseContext) parsefunc {
	data := ctx.buf.Next(int(ctx.length))
	buf := bytes.NewBuffer(data)
	// parse version
	ctx.common.Version, _ = buf.ReadByte()

	// parse augmentation
	ctx.common.Augmentation, _ = util.ParseString(buf)

	// parse code alignment factor
	ctx.common.CodeAlignmentFactor, _ = util.DecodeULEB128(buf)

	// parse data alignment factor
	ctx.common.DataAlignmentFactor, _ = util.DecodeSLEB128(buf)

	// parse return address register
	ctx.common.ReturnAddressRegister, _ = util.DecodeULEB128(buf)

	if strings.Contains(ctx.common.Augmentation, "z") {
		// read augmentation length
		augLength, _ := util.DecodeULEB128(buf)

		// read augmentation data
		ctx.common.AugmentationData = buf.Next(int(augLength))
	}

	// parse initial instructions
	// The rest of this entry consists of the instructions
	// so we can just grab all of the data from the buffer
	// cursor to length.
	ctx.common.InitialInstructions = buf.Bytes() //ctx.buf.Next(int(ctx.length))
	ctx.length = 0

	return parselength
}

// DwarfEndian determines the endianness of the DWARF by using the version number field in the debug_info section
// Trick borrowed from "debug/dwarf".New()
func DwarfEndian(infoSec []byte) binary.ByteOrder {
	if len(infoSec) < 6 {
		return binary.BigEndian
	}
	x, y := infoSec[4], infoSec[5]
	switch {
	case x == 0 && y == 0:
		return binary.BigEndian
	case x == 0:
		return binary.BigEndian
	case y == 0:
		return binary.LittleEndian
	default:
		return binary.BigEndian
	}
}
