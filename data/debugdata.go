package data

import (
	"bytes"
	"compress/zlib"
	"debug/dwarf"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/razzie/raztracer/common"
	"github.com/razzie/raztracer/custom/dwarf/frame"
)

// DebugData contains debug information of an application or library
type DebugData struct {
	elfData       *elf.File
	dwarfData     *dwarf.Data
	dwarfEndian   binary.ByteOrder
	entryPoint    uintptr
	staticBase    uintptr
	loclist       LocList
	frameEntries  []frame.FrameDescriptionEntries
	compUnits     []*CUEntry
	functions     []*FunctionEntry
	functionCache map[uintptr]*FunctionEntry
	globals       []*VariableEntry
}

// NewDebugData returns a new DebugData instance
func NewDebugData(file *os.File, staticBase uintptr) (*DebugData, error) {
	elfData, err := elf.NewFile(file)
	if err != nil {
		return nil, common.Error(err)
	}

	dwarfData, err := elfData.DWARF()
	if err != nil {
		return nil, common.Error(err)
	}

	entryPoint := uintptr(elfData.Entry)

	d := &DebugData{
		elfData:       elfData,
		dwarfData:     dwarfData,
		dwarfEndian:   common.ByteOrder,
		entryPoint:    entryPoint,
		staticBase:    staticBase,
		functionCache: make(map[uintptr]*FunctionEntry),
	}

	// determining dwarf endianness
	debugInfoData, _, _ := d.GetElfSection("debug_info")
	if debugInfoData != nil {
		d.dwarfEndian = frame.DwarfEndian(debugInfoData)
	}

	// reading location list data
	loclistData, _, _ := d.GetElfSection("debug_loc")
	if loclistData != nil {
		d.loclist = NewLocList(loclistData, d.dwarfEndian)
	}

	// reading frame data
	frameData, frameDataOffset, _ := d.GetElfSection("eh_frame")
	if frameData != nil {
		frameEntries := frame.Parse(frameData, d.dwarfEndian, uint64(frameDataOffset), uint64(staticBase))
		d.frameEntries = []frame.FrameDescriptionEntries{frameEntries}
	}

	// getting the list of compilation unit entries
	reader := dwarfData.Reader()
	for cu, _ := reader.Next(); cu != nil; cu, _ = reader.Next() {
		reader.SkipChildren()

		if cu.Tag != dwarf.TagCompileUnit {
			continue
		}

		cuEntry, err := NewCUEntry(DebugEntry{d, cu})
		if err != nil {
			fmt.Println(common.Error(err))
			continue
		}

		d.compUnits = append(d.compUnits, cuEntry)
	}

	// getting the list of function entries
	for _, cu := range d.compUnits {
		funcs, err := cu.GetFunctions()
		if err != nil {
			fmt.Println(common.Error(err))
			continue
		}

		d.functions = append(d.functions, funcs...)
	}

	// getting the list of global variable entries
	for _, cu := range d.compUnits {
		globals, err := cu.GetGlobals()
		if err != nil {
			fmt.Println(common.Error(err))
			continue
		}

		d.globals = append(d.globals, globals...)
	}

	return d, nil
}

// GetEntryPoint returns the entry point PC or 0 if not found
func (d *DebugData) GetEntryPoint() uintptr {
	return d.entryPoint
}

// GetStaticBase returns the static base (typically important for libraries)
func (d *DebugData) GetStaticBase() uintptr {
	return d.staticBase
}

// GetElfSection returns the given elf section content as a byte slice
func (d *DebugData) GetElfSection(name string) ([]byte, uintptr, error) {
	sec := d.elfData.Section("." + name)
	if sec != nil {
		data, err := sec.Data()
		return data, uintptr(sec.Addr), common.Error(err)
	}

	sec = d.elfData.Section(".z" + name)
	if sec == nil {
		return nil, 0, common.Errorf("could not find .%s or .z%s section", name, name)
	}

	b, err := sec.Data()
	if err != nil {
		return nil, 0, common.Error(err)
	}

	data, err := decompressMaybe(b)
	return data, uintptr(sec.Addr), err
}

func decompressMaybe(b []byte) ([]byte, error) {
	if len(b) < 12 || string(b[:4]) != "ZLIB" {
		// not compressed
		return b, nil
	}

	dlen := binary.BigEndian.Uint64(b[4:12])
	dbuf := make([]byte, dlen)
	r, err := zlib.NewReader(bytes.NewBuffer(b[12:]))
	if err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(r, dbuf); err != nil {
		return nil, err
	}
	if err := r.Close(); err != nil {
		return nil, err
	}
	return dbuf, nil
}

// AddSharedLib loads additional debug data from a shared library
func (d *DebugData) AddSharedLib(lib common.SharedLibrary) error {
	file, err := os.Open(lib.Name)
	if err != nil {
		return common.Error(err)
	}

	data, _ := NewDebugData(file, lib.StaticBase)
	if data != nil {
		d.functions = append(d.functions, data.functions...)
		return nil
	}

	elfData, err := elf.NewFile(file)
	if err != nil {
		return common.Error(err)
	}

	symbols, _ := elfData.Symbols()
	for _, symbol := range symbols {
		if symbol.Size == 0 {
			continue
		}

		fn, _ := NewLibFunctionEntry(&lib, symbol)
		d.functions = append(d.functions, fn)
	}

	return nil
}

// GetCompilationUnit returns the CU that belongs to the given PC
func (d *DebugData) GetCompilationUnit(pc uintptr) (*CUEntry, error) {
	for _, cu := range d.compUnits {
		if cu.ContainsPC(pc) {
			return cu, nil
		}
	}

	return nil, common.Errorf("compilation unit not found for pc: %#x", pc)
}

// GetLoclistEntry returns the instructions of the matching LocEntry
func (d *DebugData) GetLoclistEntry(pc uintptr, off int64) ([]byte, error) {
	cu, err := d.GetCompilationUnit(pc)
	if err != nil {
		return nil, common.Error(err)
	}

	entry, err := d.loclist.FindEntry(off, pc-cu.LowPC-cu.StaticBase)
	if err != nil {
		return nil, common.Error(err)
	}

	return entry.instructions, nil
}

// GetFunctionsByName returns function entries by name
func (d *DebugData) GetFunctionsByName(name string, exact bool) (results []*FunctionEntry) {
	for _, fn := range d.functions {
		if exact {
			if fn.Name != name {
				continue
			}
		} else {
			if !strings.Contains(fn.Name, name) {
				continue
			}
		}

		results = append(results, fn)
	}
	return
}

// GetFunctionFromPC returns the function entry at the given program counter
func (d *DebugData) GetFunctionFromPC(pc uintptr) (*FunctionEntry, error) {
	cached, found := d.functionCache[pc]
	if found {
		return cached, nil
	}

	for _, fn := range d.functions {
		lowpc := fn.LowPC + fn.StaticBase
		highpc := fn.HighPC + fn.HighPC
		if pc >= lowpc && pc < highpc {
			d.functionCache[pc] = fn
			return fn, nil
		}
	}

	return nil, common.Errorf("function not found for pc:%#x", pc)
}

// GetGlobals returns the list of global variables
func (d *DebugData) GetGlobals() []*VariableEntry {
	return d.globals
}

func (d *DebugData) getFDEFromPC(pc uintptr) (fde *frame.FrameDescriptionEntry, err error) {
	// frame entries already contain the static base

	defer func() {
		if r := recover(); r != nil {
			err = common.Errorf("%v", r)
		}
	}()

	for _, frameEntries := range d.frameEntries {
		fde, _ := frameEntries.FDEForPC(uint64(pc))
		if fde != nil {
			return fde, nil
		}
	}

	return nil, common.Errorf("FDE not found for pc:%#x", pc)
}

// GetFrameContextFromPC returns the frame information for the given program counter
func (d *DebugData) GetFrameContextFromPC(pc uintptr) (framectx *frame.FrameContext, err error) {
	fde, _ := d.getFDEFromPC(pc)
	if fde != nil {
		return fde.EstablishFrame(uint64(pc)), nil
	}

	return nil, common.Errorf("frame context not found for pc:%#x", pc)
}
