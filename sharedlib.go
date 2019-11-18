package raztracer

import (
	"strings"
)

// SharedLibrary represents a shared library
type SharedLibrary struct {
	Name       string
	StaticBase uintptr
}

// SharedLibs returns the shared libraries loaded by the process and their static bases
func (pid Process) SharedLibs() ([]SharedLibrary, error) {
	regions, err := pid.MemRegions()
	if err != nil {
		return nil, Error(err)
	}

	var lastLib string
	var libs []SharedLibrary

	for _, region := range regions {
		if region.Pathname == lastLib {
			continue
		}

		if !strings.HasSuffix(region.Pathname, ".so") {
			continue
		}

		lastLib = region.Pathname
		lib := SharedLibrary{Name: region.Pathname, StaticBase: region.Address[0]}
		libs = append(libs, lib)
	}

	return libs, nil
}
