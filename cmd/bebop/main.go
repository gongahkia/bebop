package main

import (
	"os"

	"github.com/bebop-home/bebop/internal/cli"
)

func main() { os.Exit(cli.New().Run(os.Args[1:])) }
