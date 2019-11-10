package data

import (
	"debug/dwarf"

	"github.com/razzie/raztracer/common"
)

// LineEntry contains debug information about a line in the source code
type LineEntry struct {
	reader   *dwarf.LineReader
	pos      dwarf.LineReaderPos
	Filename string
	Address  uintptr
	IsStmt   bool
	Line     uint
	Column   uint
}

// NewLineEntry returns a new LineEntry
func NewLineEntry(pc uintptr, reader *dwarf.LineReader) (*LineEntry, error) {
	var entry dwarf.LineEntry

	err := reader.SeekPC(uint64(pc), &entry)
	if err != nil {
		return nil, common.Errorf("line entry not found for pc: %#x", pc)
	}

	return &LineEntry{
		reader:   reader,
		pos:      reader.Tell(),
		Filename: entry.File.Name,
		Address:  uintptr(entry.Address),
		IsStmt:   entry.IsStmt,
		Line:     uint(entry.Line),
		Column:   uint(entry.Column),
	}, nil
}

// Next returns the line entry following the current one
func (line *LineEntry) Next() (*LineEntry, error) {
	var entry dwarf.LineEntry

	line.reader.Seek(line.pos)
	err := line.reader.Next(&entry)
	if err != nil {
		return nil, common.Error(err)
	}

	return &LineEntry{
		reader:   line.reader,
		pos:      line.reader.Tell(),
		Filename: entry.File.Name,
		Address:  uintptr(entry.Address),
		IsStmt:   entry.IsStmt,
		Line:     uint(entry.Line),
		Column:   uint(entry.Column),
	}, nil
}
