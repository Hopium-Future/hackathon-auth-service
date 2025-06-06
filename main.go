package main

import (
	"flag"
	"fmt"
	"os"

	"na3/na3-auth/config"
	"na3/na3-auth/server"
)

func main() {
	environment := flag.String("e", "development", "")
	flag.Usage = func() {
		fmt.Println("Usage: server -e {mode}")
		os.Exit(1)
	}
	flag.Parse()
	config.Init(*environment)
	server.Init()
}
