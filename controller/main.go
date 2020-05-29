package main

import (
	"hyperline-controller/app"
)

func main() {

	app := &app.App{
		Host: "localhost",
		Port: 5000,
	}

	app.Run()
}
