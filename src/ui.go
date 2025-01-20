package main

import (
	"log"
//"time"

	"lckbx"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	//"fyne.io/fyne/v2/data/binding"
)

var (
	lb *lckbx.LockedBox
	il *ItemList
)

const (
	width  = float32(800.0)
	height = float32(450.0)
)

func getPadding() float32 {
	if center == nil {
		return width / 4
	} else {
		return center.Size().Width / 4
	}
}

//------------
// ACTIONS
//------------

// loginShowAction locks the current UnlockedBox and displays the login
// screen.
func loginShowAction() {
	if il != nil {
		il.Close()
	}

	w.SetTitle("LckBx - Login")
	center.Objects[0] = buildLoginScreen()
	center.Refresh()
}

// registerShowAction displays the registration screen.
func registerShowAction() {
	w.SetTitle("LckBx - Register")
	center.Objects[0] = buildRegisterScreen()
	center.Refresh()
}

// logoutShowAction locks the current UnlockedBox and displays the login
// screen.
func logoutShowAction() {
	if il != nil {
		il.Close()
	}

	w.SetTitle("LckBx - Login")
	center.Objects[0] = buildLoginScreen()
	center.Refresh()
}

// passwordShowAction locks the current UnlockedBox and displayes the change
// password screen.
func passwordShowAction() {
	if il != nil {
		il.Close()
	}

	w.SetTitle("LckBx - Change Password")
	center.Objects[0] = buildChangePasswordScreen()
	center.Refresh()
}

// homeShowAction displays the home screen
func homeShowAction() {
	w.SetTitle("LckBx")
	center.Objects[0] = buildDefaultScreen()
	center.Refresh()
}

// ------------
// SCREENS
// ------------
func buildUnlockedScreen() fyne.CanvasObject {
	name := widget.NewEntry()
	data := widget.NewMultiLineEntry()

	// time.Sleep(time.Millisecond * 100)

	list := widget.NewList(
		func() int {
			return il.Length()
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("")
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			o.(*widget.Label).SetText(il.items[i].Name)
		},
	)

	list.OnSelected = func(i widget.ListItemID) {
		il.loadItem(i)

		name.SetText(il.current.Name)
		data.SetText(string(il.current.Data))
	}

	itemUi := container.NewBorder(name, nil, nil, nil, data)
	itemListUi := container.NewVScroll(list)

	itemsToolbar := widget.NewToolbar(
		widget.NewToolbarAction(theme.ContentAddIcon(), func() {
			il.AddItem()
			list.Refresh()
		}),
		widget.NewToolbarAction(theme.DeleteIcon(), func() {
			if il.current == nil {
				name.SetText("")
				data.SetText("")
				itemUi.Refresh()
			}

			il.DeleteItem()
			list.Refresh()
		}),
		widget.NewToolbarAction(theme.DocumentSaveIcon(), func() {
			if il.current == nil {
				il.AddItem()
			}

			il.current.Name = name.Text
			il.current.Data = []byte(data.Text)

			il.SaveItem()
			list.Refresh()
		}),
	)

	left := container.NewBorder(itemsToolbar, nil, nil, nil, itemListUi)
	screen := container.NewBorder(nil, nil, left, nil, itemUi)

	return screen
}

func buildLoginScreen() fyne.CanvasObject {
	username := widget.NewEntry()
	username.SetPlaceHolder("Enter username...")

	password := widget.NewPasswordEntry()
	password.SetPlaceHolder("Enter password...")

	form := container.New(
		layout.NewFormLayout(),
		widget.NewLabel("Username"), username,
		widget.NewLabel("Password"), password,
	)

	screen := container.New(
		layout.NewCustomPaddedLayout(0.0, 0.0, getPadding(), getPadding()),
		container.NewVBox(
			layout.NewSpacer(),
			form,
			widget.NewButton("Unlock", func() {
				unlocked, err := lb.Login(username.Text, password.Text)
				if err != nil {
					log.Printf("Could not Login: %v", err)
					center.Objects[0] = buildLoginScreen()
					center.Refresh()
				} else {
					il = NewItemList(&unlocked)
					log.Printf("Successfully logged in as %s", username.Text)
					center.Objects[0] = buildUnlockedScreen()
					center.Refresh()
				}
			}),
			layout.NewSpacer(),
		),
	)

	return screen
}

func buildRegisterScreen() fyne.CanvasObject {
	username := widget.NewEntry()
	username.SetPlaceHolder("Enter username...")

	password := widget.NewPasswordEntry()
	password.SetPlaceHolder("Enter password...")

	form := container.New(
		layout.NewFormLayout(),
		widget.NewLabel("Username"), username,
		widget.NewLabel("Password"), password,
	)

	screen := container.New(
		layout.NewCustomPaddedLayout(0.0, 0.0, getPadding(), getPadding()),
		container.NewVBox(
			layout.NewSpacer(),
			form,
			widget.NewButton("Register", func() {
				err := lb.Register(username.Text, password.Text)
				if err != nil {
					log.Printf("Could not Register: %v", err)
					center.Objects[0] = buildRegisterScreen()
					center.Refresh()
				} else {
					log.Printf("Successfully registered user: %s", username.Text)
					center.Objects[0] = buildLoginScreen()
					center.Refresh()
				}
			}),
			layout.NewSpacer(),
		),
	)

	return screen
}

func buildChangePasswordScreen() fyne.CanvasObject {
	username := widget.NewEntry()
	username.SetPlaceHolder("Enter username...")

	oldPwd := widget.NewPasswordEntry()
	oldPwd.SetPlaceHolder("Enter old password...")

	newPwd := widget.NewPasswordEntry()
	newPwd.SetPlaceHolder("Enter new password...")

	form := container.New(
		layout.NewFormLayout(),
		widget.NewLabel("Username"), username,
		widget.NewLabel("Old Password"), oldPwd,
		widget.NewLabel("New Password"), newPwd,
	)

	screen := container.New(
		layout.NewCustomPaddedLayout(0.0, 0.0, getPadding(), getPadding()),
		container.NewVBox(
			layout.NewSpacer(),
			form,
			widget.NewButton("Change Password", func() {
				err := lb.ChangePassword(username.Text, oldPwd.Text, newPwd.Text)
				if err != nil {
					log.Printf("Could not Change Password: %v", err)
					center.Objects[0] = buildChangePasswordScreen()
					center.Refresh()
				} else {
					log.Printf("Password successfully changed for %s", username.Text)
					center.Objects[0] = buildLoginScreen()
					center.Refresh()
				}
			}),
			layout.NewSpacer(),
		),
	)

	return screen
}

func buildDefaultScreen() fyne.CanvasObject {
	title := canvas.NewText("Welcome to LckBx", black)
	title.TextSize = 36.0
	title.Alignment = fyne.TextAlignCenter

	screen := container.New(
		layout.NewCustomPaddedLayout(0.0, 0.0, getPadding(), getPadding()),
		container.NewVBox(
			layout.NewSpacer(),
			title,
			widget.NewButtonWithIcon("Unlock", theme.LoginIcon(), loginShowAction),
			widget.NewButtonWithIcon("Add User", theme.AccountIcon(), registerShowAction),
			widget.NewButtonWithIcon("Lock", theme.LogoutIcon(), logoutShowAction),
			widget.NewButtonWithIcon("Change Password", theme.ViewRefreshIcon(), passwordShowAction),
			layout.NewSpacer(),
		),
	)

	return screen
}

// ------------
// COMPONENTS
// ------------
func buildToolBar() fyne.CanvasObject {
	toolbar := widget.NewToolbar(
		widget.NewToolbarAction(theme.HomeIcon(), homeShowAction),
		widget.NewToolbarAction(theme.AccountIcon(), registerShowAction),
		widget.NewToolbarAction(theme.LoginIcon(), loginShowAction),
		widget.NewToolbarAction(theme.LogoutIcon(), logoutShowAction),
		widget.NewToolbarAction(theme.ViewRefreshIcon(), passwordShowAction),
		//		widget.NewToolbarAction(theme.ColorPalatteIcon(), themeAction)
	)

	return toolbar
}
