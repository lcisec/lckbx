package main

import (
	"fmt"
	//"time"
	"log"
"os"
	"lckbx"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	// "fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

var (
)

func buildUnlockedUI(uv *lckbx.UnlockedBox) *fyne.Container {
	user := widget.NewLabel(uv.GetUserName())
	content := container.NewVBox(user)

	return content
}

func buildLoginUI(lv *lckbx.LockedBox, w fyne.Window) fyne.CanvasObject {
	username := widget.NewEntry()
	username.SetPlaceHolder("Enter username...")

	password := widget.NewPasswordEntry()
	password.SetPlaceHolder("Enter password...")

	content := container.NewVBox(username, password, widget.NewButton("Unlock", func() {
		uv, err := lv.Login(username.Text, password.Text)
		if err != nil {
			log.Printf("Could not Login: %v", err)
			w.SetContent(buildLoginUI(lv, w))
		} else {
			w.SetContent(buildUnlockedUI(&uv))
		}
	}))

	return content
}

func buildRegisterUI(lv *lckbx.LockedBox, w fyne.Window) fyne.CanvasObject {
	username := widget.NewEntry()
	username.SetPlaceHolder("Enter username...")

	password := widget.NewPasswordEntry()
	password.SetPlaceHolder("Enter password...")

	content := container.NewVBox(username, password, widget.NewButton("Register", func() {
		err := lv.Register(username.Text, password.Text)
		if err != nil {
			log.Printf("Could not Register: %v", err)
			w.SetContent(buildRegisterUI(lv, w))
		} else {
			w.SetContent(buildLoginUI(lv, w))
		}
	}))

	return content
}

func buildChangePasswordUI(lv *lckbx.LockedBox, w fyne.Window) fyne.CanvasObject {
	username := widget.NewEntry()
	username.SetPlaceHolder("Enter username...")

	oldPwd := widget.NewPasswordEntry()
	oldPwd.SetPlaceHolder("Enter old password...")

	newPwd := widget.NewPasswordEntry()
	newPwd.SetPlaceHolder("Enter new password...")

	content := container.NewVBox(username, oldPwd, newPwd, widget.NewButton("Change Password", func() {
		err := lv.ChangePassword(username.Text, oldPwd.Text, newPwd.Text)
		if err != nil {
			log.Printf("Could not Change Password: %v", err)
			w.SetContent(buildChangePasswordUI(lv, w))
		} else {
			w.SetContent(buildLoginUI(lv, w))
		}
	}))

	return content
}


// Build our user interface and run the application.
func main() {
	// Get the path for our lckbx data store
	dirname, err := os.UserHomeDir()
    if err != nil {
        log.Fatal(err)
    }
    
    // Get a new storer
    path := fmt.Sprintf("%s/%s", dirname, "lckbx.db")
    store, err := lckbx.NewStore(path)
    if err != nil {
    	log.Fatal(err)
    }

    // Get a LockedBox
    lv, err := lckbx.NewLockedBox(&store)
    if err != nil {
    	log.Fatal(err)
    }

    // Create an application and the needed windows.
	a := app.New()
	w := a.NewWindow("LckBx")
	w.Resize(fyne.NewSize(800.0, 450.0))

	// Define our buttons
	loginButton := widget.NewButton("Login", func(){
		w.SetTitle("LckBx - Login")
		w.SetContent(buildLoginUI(&lv, w))
	})

	registerButton := widget.NewButton("Register", func() {
		w.SetTitle("LckBx - Register")
		w.SetContent(buildRegisterUI(&lv, w))
	})

	changePasswordButton := widget.NewButton("Change Password", func() {
		w.SetTitle("LckBx - Change Password")
		w.SetContent(buildChangePasswordUI(&lv, w))
	})


	// Build the content for this window.
	content := container.New(layout.NewVBoxLayout(),
		loginButton,
		registerButton,
		changePasswordButton,
	)

	w.SetContent(content)


	// Run the application
	w.ShowAndRun()
}
