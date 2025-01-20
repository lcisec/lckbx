package main

import (
	"log"
	"os"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
)

var (
	content *fyne.Container
	center  *fyne.Container
	w       fyne.Window
)

func setupLogging() {
	path := getLogPath()

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatalf("Could not initialize logs: %s", err)
	}

	log.SetOutput(file)
}

// Build our user interface and run the application.
func main() {
	// Initialize the program
	createLckbxDir()
	setupLogging()

	// Get a LockedBox
	lb = getLockedBox()

	// Create an application and the needed windows.
	a := app.New()
	a.Settings().SetTheme(&lckbxTheme{})
	// How can we use these to create a crude idle timer.
	// a.LifeCycle().SetOnExitedForeground(func() {})
	// a.LifeCycle().SetOnEnteredForeground(func() {})

	w = a.NewWindow("LckBx")
	w.Resize(fyne.NewSize(width, height))

	center = container.New(
		layout.NewStackLayout(),
		buildDefaultScreen(),
	)

	content = container.NewBorder(
		buildToolBar(),
		nil,
		nil,
		nil,
		center,
	)

	w.SetContent(content)

	// Run the application
	w.ShowAndRun()
}
