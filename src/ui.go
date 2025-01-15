package main

import (
	"image/color"
	"log"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func buildUnlockedScreen() fyne.CanvasObject {
	return container.NewHSplit(layout.NewSpacer(), widget.NewLabel(ub.GetUserName()))
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

	content := container.NewVBox(
		layout.NewSpacer(),
		form,
		widget.NewButton("Unlock", func() {
			unlocked, err := lb.Login(username.Text, password.Text)
			if err != nil {
				log.Printf("Could not Login: %v", err)
				center.Objects[0] = buildLoginScreen()
				center.Refresh()
			} else {
				ub = &unlocked
				// go ub.purgeUnusedKeys()
				// go ub.updateEncryption()

				center.Objects[0] = buildUnlockedScreen()
				center.Refresh()
			}
		}),
		layout.NewSpacer(),
	)

	return content
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

	content := container.NewVBox(
		layout.NewSpacer(),
		form,
		widget.NewButton("Register", func() {
			err := lb.Register(username.Text, password.Text)
			if err != nil {
				log.Printf("Could not Register: %v", err)
				center.Objects[0] = buildRegisterScreen()
				center.Refresh()
			} else {
				center.Objects[0] = buildLoginScreen()
				center.Refresh()
			}
		}),
		layout.NewSpacer(),
	)

	return content
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

	content := container.NewVBox(
		layout.NewSpacer(),
		form,
		widget.NewButton("Change Password", func() {
			err := lb.ChangePassword(username.Text, oldPwd.Text, newPwd.Text)
			if err != nil {
				log.Printf("Could not Change Password: %v", err)
				center.Objects[0] = buildChangePasswordScreen()
				center.Refresh()
			} else {
				center.Objects[0] = buildLoginScreen()
				center.Refresh()
			}
		}),
		layout.NewSpacer(),
	)

	return content
}

func buildDefaultScreen() fyne.CanvasObject {
	return canvas.NewText("Welcome to LckBx", color.Black)
}

func buildTopBar() fyne.CanvasObject {
	register := widget.NewButtonWithIcon(
		"Add User",
		theme.AccountIcon(),
		func() {
			w.SetTitle("LckBx - Register")
			center.Objects[0] = buildRegisterScreen()
			center.Refresh()
		},
	)

	login := widget.NewButtonWithIcon(
		"Unlock",
		theme.LoginIcon(),
		func() {
			if ub != nil {
				ub.Lock()
			}
			w.SetTitle("LckBx - Login")
			center.Objects[0] = buildLoginScreen()
			center.Refresh()
		},
	)

	logout := widget.NewButtonWithIcon(
		"Lock",
		theme.LogoutIcon(),
		func() {
			if ub != nil {
				ub.Lock()
			}
			center.Objects[0] = buildLoginScreen()
			center.Refresh()
		},
	)

	password := widget.NewButtonWithIcon(
		"Change Password",
		theme.ViewRefreshIcon(),
		func() {
			if ub != nil {
				ub.Lock()
			}
			center.Objects[0] = buildChangePasswordScreen()
			center.Refresh()
		},
	)

	return container.NewHBox(register, login, logout, password)
}
