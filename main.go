package main

import (
	"fmt"
	"os"
)

func printUsage() {
	fmt.Println("fcrypt4 <command> [options]")
	fmt.Println()
	fmt.Println("COMMANDS:")
	fmt.Println()
	fmt.Println("	encrypt <file>")
	fmt.Println("	decrypt <file with extension .fc4>")
}

func main() {
	if len(os.Args) < 3 {
		printUsage()
		return
	}

	switch os.Args[1] {
	case "encrypt":
		encrypt()
	default:
		printUsage()
		return
	}
}
