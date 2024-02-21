package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

func clearB(b []byte) {
	for i := range b {
		b[i] = 0
	}
	io.ReadFull(rand.Reader, b)
}

func encrypt() {
	inputfile := filepath.Clean(os.Args[2])

	f, err := os.Open(inputfile)
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()

	outputfile := inputfile + ".fc4"
	ef, err := os.Create(outputfile)
	if err != nil {
		log.Fatalln(err)
	}
	defer ef.Close()

	fmt.Println()

	fmt.Print("Password: ")
	pw0, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Print("Confirm: ")
	pw1, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		log.Fatalln(err)
	}
	if subtle.ConstantTimeCompare(pw0, pw1) != 1 {
		clearB(pw0)
		clearB(pw1)
	}
	clearB(pw1)

	var iv [16]byte
	clearB(iv[:])

	key := argon2.IDKey(pw0, iv[:], 1, 64*1024, 4, 32)
	clearB(pw0)

	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		clearB(key)
		log.Fatalln(err)
	}

	stream := cipher.NewCTR(aesCipher, iv[:])
	buffer := make([]byte, 4096)

	_, err = ef.Write(iv[:])
	if err != nil {
		stream.XORKeyStream(buffer, buffer)
		stream.XORKeyStream(buffer, buffer)
		clearB(key)
		clearB(iv[:])
		clearB(buffer)

		log.Fatalln(err)
	}

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

		_, err = ef.Write(buffer)
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
