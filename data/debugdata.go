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
	"path"
	"strings"

	"github.com/razzie/raztracer/common"
	"github.com/razzie/raztracer/custom/frame"
	"github.com/razzie/raztracer/custom/op"
)

// DebugData contains debug information of an application or library
type DebugData struct {
	elfData       *elf.File
	dwarfData     *dwarf.Data
	dwarfEndian   binary.ByteOrder
	entryPoint    uintptr
	staticBase    uintptr
	loclist       LocList
	frameEntries  frame.FrameDescriptionEntries
	libs          map[string]*DebugData
	libFunctions  []*FunctionEntry
	functionCache map[uintptr]*FunctionEntry
	globalsCache  map[uintptr][]*VariableEntry
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
		libs:          make(map[string]*DebugData),
		libFunctions:  make([]*FunctionEntry, 0),
		functionCache: make(map[uintptr]*FunctionEntry),
		globalsCache:  make(map[uintptr][]*VariableEntry),
	}

	debugInfoData, _, _ := d.GetElfSection("debug_info")
	if debugInfoData != nil {
		d.dwarfEndian = frame.DwarfEndian(debugInfoData)
	}

	loclistData, _, _ := d.GetElfSection("debug_loc")
	if loclistData != nil {
		d.loclist = NewLocList(loclistData, d.dwarfEndian)
	}

	frameData, frameDataOffset, _ := d.GetElfSection("eh_frame")
	if frameData != nil {
		d.frameEntries = frame.Parse(frameData, d.dwarfEndian, uint64(frameDataOffset), uint64(staticBase))
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

	elfData, err := elf.NewFile(file)
	if err != nil {
		return common.Error(err)
	}

	libname := path.Base(lib.Name)
	symbols, _ := elfData.Symbols()
	for _, symbol := range symbols {
		if symbol.Size == 0 {
			continue
		}

		lowpc := uintptr(symbol.Value)
		highpc := lowpc + uintptr(symbol.Size)
		fnname := fmt.Sprintf("%s:%s", libname, symbol.Name)

		fn, _ := NewLibFunctionEntry(fnname, lowpc, highpc, lib.StaticBase)
		d.libFunctions = append(d.libFunctions, fn)
	}

	data, err := NewDebugData(file, lib.StaticBase)
	if err != nil {
		// try loading from secondary source

		file, err := os.Open(lib.Name)
		if err != nil {
			return common.Error(err)
		}

		data, err = NewDebugData(file, lib.StaticBase)
		if err != nil {
			return common.Error(err)
		}
	}

	d.libs[lib.Name] = data
	return nil
}

// GetSharedLib returns the debug data that belongs to the shared lib at PC
func (d *DebugData) GetSharedLib(pc uintptr) (data *DebugData) {
	for _, lib := range d.libs {
		if pc > lib.GetStaticBase() {
			data = lib
		}
	}

	return
}

// GetCompilationUnit returns the CU that belongs to the given PC
func (d *DebugData) GetCompilationUnit(pc uintptr) (*DebugEntry, error) {
	if pc > d.staticBase {
		pc -= d.staticBase
	}

	reader := d.dwarfData.Reader()

	for cu, _ := reader.Next(); cu != nil; cu, _ = reader.Next() {
		reader.SkipChildren()

		if cu.Tag != dwarf.TagCompileUnit {
			continue
		}

		ranges, err := d.dwarfData.Ranges(cu)
		if err != nil {
			return nil, common.Error(err)
		}

		for _, lowhigh := range ranges {
			lowpc := uintptr(lowhigh[0])
			highpc := uintptr(lowhigh[1])

			if lowpc <= pc && highpc > pc {
				return &DebugEntry{d, cu}, nil
			}
		}
	}

	lib := d.GetSharedLib(pc + d.staticBase)
	if lib != nil {
		cu, _ := lib.GetCompilationUnit(pc + d.staticBase)
		if cu != nil {
			return cu, nil
		}
	}

	return nil, common.Errorf("compilation unit not found for pc: %#x", pc)
}

// GetLoclistEntry returns the instructions of the matching LocEntry
func (d *DebugData) GetLoclistEntry(pc uintptr, off int64) ([]byte, error) {
	if pc > d.staticBase {
		pc -= d.staticBase
	}

	cu, err := d.GetCompilationUnit(pc)
	if err != nil {
		return nil, common.Error(err)
	}

	entry, err := d.loclist.FindEntry(off, pc-cu.LowPC())
	if err != nil {
		return nil, common.Error(err)
	}

	return entry.instructions, nil
}

// GetFunctionAddresses returns the addresses of the functions matching 'name'
func (d *DebugData) GetFunctionAddresses(name string, exact bool) []uintptr {
	addresses := make([]uintptr, 0)
	symbols, _ := d.elfData.Symbols()

	for _, symbol := range symbols {
		if symbol.Size == 0 {
			continue
		}

		if exact {
			if symbol.Name != name {
				continue
			}
		} else {
			if !strings.Contains(symbol.Name, name) {
				continue
			}
		}

		pc := uintptr(symbol.Value)

		if fn, _ := NewFunctionEntry(pc, d); fn == nil {
			continue
		}

		addr, err := d.getFunctionBreakpointAddress(pc)
		if err != nil {
			fmt.Println(common.Error(err))
			//continue
		}

		addresses = append(addresses, addr)
	}

	for _, lib := range d.libs {
		addresses = append(addresses, lib.GetFunctionAddresses(name, exact)...)
	}

	return addresses
}

func (d *DebugData) getFunctionBreakpointAddress(pc uintptr) (uintptr, error) {
	if pc > d.staticBase {
		pc -= d.staticBase
	}

	line, err := d.GetLineEntryFromPC(pc)
	if err != nil {
		return pc + d.staticBase, common.Error(err)
	}

	for line, err = line.Next(); line != nil; line, err = line.Next() {
		if err != nil {
			return pc + d.staticBase, common.Error(err)
		}

		if line.IsStmt {
			return line.Address + d.staticBase, nil
		}
	}

	return pc + d.staticBase, common.Errorf("no suitable breakpoint location for %#x", pc+d.staticBase)
}

// GetLineEntryFromPC returns the line entry at the given program counter
func (d *DebugData) GetLineEntryFromPC(pc uintptr) (*LineEntry, error) {
	if pc > d.staticBase {
		pc -= d.staticBase
	}

	reader := d.dwarfData.Reader()
	cu, err := reader.SeekPC(uint64(pc))
	if err != nil {
		return nil, common.Error(err)
	}

	lineReader, err := d.dwarfData.LineReader(cu)
	if err != nil {
		return nil, common.Error(err)
	}

	entry, err := NewLineEntry(pc, lineReader)
	if err != nil {
		lib := d.GetSharedLib(pc + d.staticBase)
		if lib != nil {
			entry, err := lib.GetLineEntryFromPC(pc)
			return entry, common.Error(err)
		}

		return nil, common.Error(err)
	}

	entry.Address += d.staticBase
	return entry, nil
}

// GetFunctionFromPC returns the function entry at the given program counter
func (d *DebugData) GetFunctionFromPC(pc uintptr) (*FunctionEntry, error) {
	if pc > d.staticBase {
		pc -= d.staticBase
	}

	cached, found := d.functionCache[pc]
	if found {
		return cached, nil
	}

	fn, err := NewFunctionEntry(pc, d)
	if err != nil {
		fn, _ = d.getLibFunctionFromPC(pc)
		if fn == nil {
			return nil, common.Error(err)
		}
	}

	d.functionCache[pc] = fn
	return fn, nil
}

func (d *DebugData) getLibFunctionFromPC(pc uintptr) (*FunctionEntry, error) {
	lib := d.GetSharedLib(pc)
	if lib != nil {
		fn, err := lib.GetFunctionFromPC(pc)
		if err != nil {
			return nil, common.Error(err)
		}

		return fn, nil
	}

	for _, fn := range d.libFunctions {
		low := fn.LowPC + fn.StaticBase
		high := fn.HighPC + fn.StaticBase

		if pc >= low && pc < high {
			return fn, nil
		}
	}

	return nil, common.Errorf("library function not found for %#x", pc)
}

// GetGlobals returns the list of global variables in the compilation unit of PC
func (d *DebugData) GetGlobals(pc uintptr) ([]*VariableEntry, error) {
	if pc > d.staticBase {
		pc -= d.staticBase
	}

	cached, found := d.globalsCache[pc]
	if found {
		return cached, nil
	}

	reader := d.dwarfData.Reader()
	cu, err := reader.SeekPC(uint64(pc))
	if err != nil {
		lib := d.GetSharedLib(pc + d.staticBase)
		if lib != nil {
			globals, err := lib.GetGlobals(pc + d.staticBase)
			if err == nil {
				d.globalsCache[pc] = globals
				return globals, nil
			}
		}

		return nil, common.Error(err)
	}

	cuEntry := DebugEntry{d, cu}
	children, err := cuEntry.Children(-1)
	if err != nil {
		return nil, common.Error(err)
	}

	vars := make([]*VariableEntry, 0)

	for _, de := range children {
		if de.entry.Tag != dwarf.TagVariable {
			continue
		}

		_, hasName := de.Val(dwarf.AttrName).(string)
		if !hasName {
			continue
		}

		loc, _ := de.Location(dwarf.AttrLocation, pc)
		if loc != nil && len(loc.instructions) > 0 {
			firstOp := op.Opcode(loc.instructions[0])
			if firstOp != op.DW_OP_addr {
				continue
			}
		} else {
			continue
		}

		v, err := NewVariableEntry(de, d.staticBase)
		if err != nil {
			fmt.Println(common.Error(err))
			continue
		}

		if v == nil || v.Size == 0 {
			continue
		}

		vars = append(vars, v)
	}

	d.globalsCache[pc] = vars
	return vars, nil
}

func (d *DebugData) getFDEFromPC(pc uintptr) (fde *frame.FrameDescriptionEntry, err error) {
	// frame entries already contain the static base

	defer func() {
		if r := recover(); r != nil {
			err = common.Errorf("%v", r)
		}
	}()

	if d.frameEntries != nil {
		fde, err := d.frameEntries.FDEForPC(uint64(pc))
		return fde, common.Error(err)
	}

	return nil, common.Errorf("FDE not found for pc:%#x", pc)
}

// GetFrameContextFromPC returns the frame information for the given program counter
func (d *DebugData) GetFrameContextFromPC(pc uintptr) (framectx *frame.FrameContext, err error) {
	fde, _ := d.getFDEFromPC(pc)
	if fde != nil {
		return fde.EstablishFrame(uint64(pc)), nil
	}

	lib := d.GetSharedLib(pc)
	if lib != nil {
		framectx, _ := lib.GetFrameContextFromPC(pc)
		if framectx != nil {
			return framectx, nil
		}
	}

	return nil, common.Errorf("frame context not found for pc:%#x", pc)
}
