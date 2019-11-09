package data

import (
	"bytes"
	"compress/zlib"
	"debug/dwarf"
	"debug/elf"
	"encoding/binary"
	"io"
	"os"

	"github.com/go-delve/delve/pkg/dwarf/frame"
	"github.com/razzie/raztracer/common"
)

// DebugData contains debug information of an application or library
type DebugData struct {
	elfData     *elf.File
	dwarfData   *dwarf.Data
	dwarfEndian binary.ByteOrder
	entryPoint  uintptr
	staticBase  uintptr
	loclist     LocList
	libs        map[string]*DebugData
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
		elfData:     elfData,
		dwarfData:   dwarfData,
		dwarfEndian: common.ByteOrder,
		entryPoint:  entryPoint,
		staticBase:  staticBase,
		libs:        make(map[string]*DebugData),
	}

	debugInfoData, _, _ := d.GetElfSection("debug_info")
	if debugInfoData != nil {
		d.dwarfEndian = frame.DwarfEndian(debugInfoData)
	}

	loclistData, _, _ := d.GetElfSection("debug_loc")
	if loclistData != nil {
		d.loclist = NewLocList(loclistData, d.dwarfEndian)
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
