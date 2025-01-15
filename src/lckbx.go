package main

import (
	"lckbx"
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
	lb      *lckbx.LockedBox
	ub      *lckbx.UnlockedBox
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
	width := float32(800.0)
	height := float32(450.0)
	pad := float32(width / 4)

	// Initialize the program
	createLckbxDir()
	setupLogging()

	// Get a LockedBox
	lb = getLockedBox()

	// Create an application and the needed windows.
	a := app.New()
	w = a.NewWindow("LckBx")
	w.Resize(fyne.NewSize(width, height))

	center = container.New(
		layout.NewCustomPaddedLayout(0.0, 0.0, pad, pad),
		buildDefaultScreen(),
	)

	content = container.NewBorder(
		buildTopBar(),
		nil,
		nil,
		nil,
		center,
	)

	w.SetContent(content)

	// Run the application
	w.ShowAndRun()
}
