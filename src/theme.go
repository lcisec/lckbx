package main

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

var (
	orange = color.RGBA{R: 247, G: 152, B: 36, A: 255}
	black  = color.RGBA{R: 8, G: 9, B: 10, A: 255}
	white  = color.RGBA{R: 244, G: 247, B: 245, A: 255}
	grey   = color.RGBA{R: 87, G: 90, B: 94, A: 255}
)

type lckbxTheme struct{}

func (l lckbxTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	// Dark Theme
	if variant == theme.VariantDark {
		if name == theme.ColorNameBackground {
			return grey
		}

		if name == theme.ColorNameButton {
			return orange
		}

		if name == theme.ColorNameForeground {
			return white
		}
	}

	// Light Theme
	if variant == theme.VariantLight {
		if name == theme.ColorNameBackground {
			return white
		}

		if name == theme.ColorNameButton {
			return orange
		}

		if name == theme.ColorNameForeground {
			return grey
		}
	}

	return theme.DefaultTheme().Color(name, variant)
}

func (l lckbxTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

func (l lckbxTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

func (l lckbxTheme) Size(name fyne.ThemeSizeName) float32 {
	return theme.DefaultTheme().Size(name)
}
