package main

import (
	"flag"
	"fmt"

	"github.com/razzie/raztracer/ui"
)

func main() {
	theme := flag.String("theme", "light", "Specify light or dark theme")
	flag.Parse()

	if t, ok := ui.Themes[*theme]; ok {
		t.Apply()
	} else {
		panic(fmt.Errorf("Theme not found: %s", *theme))
	}

	app := NewApp()

	if err := app.Run(); err != nil {
		panic(err)
	}
}
