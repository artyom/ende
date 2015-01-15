// Command encrypt encrypts file using RSA public key in PEM format. To decrypt
// file, private key should be used.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
)

var pubKey, inFile, outFile string

func main() {
	if len(pubKey) == 0 || len(inFile) == 0 || len(outFile) == 0 {
		flag.Usage()
		os.Exit(1)
	}
	reader, err := os.Open(inFile)
	if err != nil {
		log.Fatal(err)
	}
	defer reader.Close()
	key, err := readPublicKey(pubKey)
	if err != nil {
		log.Fatal(err)
	}
	// steps:
	// 1. create a random key to use with symmetric encryption by reading 32
	// bytes from rand.Reader
	// 2. encrypt this key using rsa.EncryptOAEP and public key to block of
	// 256 bytes
	// 3. write these encrypted bytes to output
	// 4. create stream encryption writer with cipher.StreamWriter and
	// cipher.NewCTR
	secret := make([]byte, 32) // key length 32 selects AES-256
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		log.Fatal(err)
	}
	header, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, key, secret, nil)
	if err != nil {
		log.Fatal(err)
	}
	block, err := aes.NewCipher(secret)
	if err != nil {
		log.Fatal(err)
	}
	stream := cipher.NewCTR(block, header[:block.BlockSize()])

	out, err := os.OpenFile(outFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := out.Close(); err != nil {
			log.Fatal(err)
		}
	}()
	if _, err := out.Write(header); err != nil {
		log.Fatal(err)
	}
	writer := &cipher.StreamWriter{S: stream, W: out}
	if _, err := io.Copy(writer, reader); err != nil {
		log.Fatal(err)
	}
}

func init() {
	log.SetFlags(0)
	flag.Usage = func() {
		usageFmt := "Command %s encrypts file using public RSA key.\nUsage:\n"
		fmt.Fprintf(os.Stderr, usageFmt, os.Args[0])
		flag.PrintDefaults()
	}
	flag.StringVar(&pubKey, "key", "", "path to public key in PEM format")
	flag.StringVar(&inFile, "in", "", "path to plaintext file to encrypt")
	flag.StringVar(&outFile, "out", "", "path to encrypted file to create (should not exist)")
	flag.Parse()
}

// readPublicKey reads and unmarshals RSA public key from PEM format file
func readPublicKey(file string) (*rsa.PublicKey, error) {
	b, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("failed to decode PEM file")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	if rsaKey, ok := key.(*rsa.PublicKey); ok {
		return rsaKey, nil
	}
	return nil, errors.New("unsupported key type")
}
