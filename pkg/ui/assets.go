package ui

import _ "embed"

//go:embed login.html
var loginHTML string

func LoginHTML() string {
	return loginHTML
}
