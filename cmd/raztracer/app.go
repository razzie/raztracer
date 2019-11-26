package main

import (
	"github.com/razzie/raztracer/ui"
	"github.com/rivo/tview"
)

// App handles the user interface
type App struct {
	*ui.PageHandler
	app *tview.Application
}

// NewApp returns a new App
func NewApp() *App {
	pages := ui.NewPageHandler()

	app := tview.NewApplication().
		SetInputCapture(pages.InputCapture()).
		SetRoot(pages, true)

	return &App{
		PageHandler: pages,
		app:         app,
	}
}

// Run runs the user interface
func (app *App) Run() error {
	go func() {
		<-app.Quit
		app.app.Stop()
	}()

	ui.SetConsoleTitle("RazTracer")

	return app.app.SetFocus(app).Run()
}
