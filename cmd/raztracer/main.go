package main

import (
	"flag"
	"fmt"

	"github.com/razzie/raztracer/ui"
	"github.com/rivo/tview"
)

func main() {
	fmt.Printf("\033]0;Raztracer\007")

	theme := flag.String("theme", "light", "Specify light or dark theme")
	flag.Parse()

	themes := map[string]*ui.Theme{
		"light": &ui.LightTheme,
		"dark":  &ui.DarkTheme,
	}

	if t, found := themes[*theme]; found {
		t.Apply()
	}

	root := ui.NewRootElement()
	app := tview.NewApplication().
		SetInputCapture(root.InputCapture()).
		SetRoot(root, true)

	go func() {
		<-root.Quit
		app.Stop()
	}()

	if err := app.SetFocus(root).Run(); err != nil {
		panic(err)
	}
}
