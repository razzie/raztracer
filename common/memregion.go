package common

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// MemRegion represents a mapped memory region to a process
type MemRegion struct {
	Address     [2]uintptr
	Permissions string
	Offset      uint64
	Device      string
	Inode       uint64
	Pathname    string
}

// MemRegions returns the mapped memory regions of the process
func (pid Process) MemRegions() ([]MemRegion, error) {
	file, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, err
	}
	defer file.Close()

	regions := make([]MemRegion, 0)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var region MemRegion

		// incomplete lines cause an EOF panic in stripped binary
		if len(strings.Fields(scanner.Text())) != 6 {
			continue
		}

		// address           perms offset  dev   inode   pathname
		// 08048000-08056000 r-xp 00000000 03:0c 64593   /usr/sbin/gpm
		fmt.Sscanf(scanner.Text(), "%x-%x %s %x %s %d %s",
			&region.Address[0], &region.Address[1],
			&region.Permissions,
			&region.Offset,
			&region.Device,
			&region.Inode,
			&region.Pathname)

		regions = append(regions, region)
	}

	return regions, nil
}
