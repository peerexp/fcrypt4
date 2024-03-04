package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

func decrypt() {
	inputfile := filepath.Clean(os.Args[2])

	if !strings.HasSuffix(inputfile, ".fc4") {
		log.Fatalln("Input file must have .fc4 exts.")
	}

	f, err := os.Open(inputfile)
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()

	outputfile := strings.TrimSuffix(inputfile, ".fc4")
	df, err := os.Create(outputfile)
	if err != nil {
		log.Fatalln(err)
	}
	defer df.Close()

	log.Println(inputfile, outputfile)

	fmt.Println()

	fmt.Print("Password: ")
	pw0, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		log.Fatalln(err)
	}

	var iv [16]byte
	clearB(iv[:])

	_, err = f.Read(iv[:])
	if err != nil {
		log.Println("IV Read Failed")
		log.Fatalln(err)
	}

	key := argon2.IDKey(pw0, iv[:], 1, 64*1024, 4, 32)
	clearB(pw0)

	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		clearB(key)
		log.Fatalln(err)
	}

	stream := cipher.NewCTR(aesCipher, iv[:])
	buffer := make([]byte, 4096)

	for {
		n, err := f.Read(buffer[:cap(buffer)])
		if err != nil {
			if err == io.EOF {
				break
			}

			stream.XORKeyStream(buffer, buffer)
			stream.XORKeyStream(buffer, buffer)
			clearB(key)
			clearB(iv[:])
			clearB(buffer)

			log.Fatalln(err)
		}

		buffer = buffer[:n]
		stream.XORKeyStream(buffer, buffer)

		_, err = df.Write(buffer)
		if err != nil {
			stream.XORKeyStream(buffer, buffer)
			stream.XORKeyStream(buffer, buffer)
			clearB(key)
			clearB(iv[:])
			clearB(buffer)

			log.Fatalln(err)
		}
	}

	stream.XORKeyStream(buffer, buffer)
	stream.XORKeyStream(buffer, buffer)
	clearB(key)
	clearB(iv[:])
	clearB(buffer)
}
