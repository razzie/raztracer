package raztracer

import (
	"debug/dwarf"
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
// pc must not include the static base
func NewLineEntry(pc uintptr, data *DebugData) (*LineEntry, error) {
	var entry dwarf.LineEntry

	reader := data.dwarfData.Reader()
	cu, err := reader.SeekPC(uint64(pc))
	if err != nil {
		return nil, Error(err)
	}

	lineReader, err := data.dwarfData.LineReader(cu)
	if err != nil {
		return nil, Error(err)
	}

	err = lineReader.SeekPC(uint64(pc), &entry)
	if err != nil {
		return nil, Errorf("line entry not found for pc: %#x", pc)
	}

	return &LineEntry{
		reader:   lineReader,
		pos:      lineReader.Tell(),
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
		return nil, Error(err)
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
