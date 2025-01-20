package main

import (
	"fmt"
	"lckbx"
	"log"
	"os"
)

// createLckbxDir creates the .lckbx directory in the user's HOME, if it
// doesn't exist.
func createLckbxDir() {
	// Get the user's HOME
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Println("Unable to create .lckbx directory in $HOME.")
		log.Fatalf("Could not createLckbxDir: %v", err)
	}

	// Create the .lckbx directory in HOME
	path := fmt.Sprintf("%s/.lckbx", home)
	err = os.MkdirAll(path, 0700)
	if err != nil {
		fmt.Printf("Unable to create %s.\n", path)
		log.Fatalf("Could not createLckbxDir: %v", err)
	}
}

// getLockedBox creates a new lckbx.LockedBox object using the lckbx.db file
// in the .lckbx directory of the user's HOME.
func getLockedBox() *lckbx.LockedBox {
	// Get the user's HOME
	home, err := os.UserHomeDir()
	if err != nil {
		// fmt.Println("Unable to find database in $HOME.")
		log.Fatalf("Could not getLockedBox: %v", err)
	}

	// Open the lckbx.db file
	path := fmt.Sprintf("%s/.lckbx/lckbx.db", home)
	store, err := lckbx.NewStore(path)
	if err != nil {
		// fmt.Println("Unable to load database.")
		log.Fatalf("Could not getLockedBox: %v", err)
	}

	// Get a LockedBox
	locked, err := lckbx.NewLockedBox(&store)
	if err != nil {
		// fmt.Println("Unable to load database.")
		log.Fatalf("Could not getLockedBox: %v", err)
	}

	return &locked
}

// getLogPath returns the path to the log file in $HOME.
func getLogPath() string {
	// Get the user's HOME
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Println("Unable to find log file in $HOME.")
		log.Fatalf("Could not getLogPath: %v", err)
	}

	return fmt.Sprintf("%s/.lckbx/lckbx.log", home)
}
