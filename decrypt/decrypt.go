// Command decrypt decrypts file encrypted with RSA public key, using matching
// RSA private key.
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

var privKey, inFile, outFile string

func main() {
	if len(privKey) == 0 || len(inFile) == 0 || len(outFile) == 0 {
		flag.Usage()
		os.Exit(1)
	}
	key, err := readPrivateKey(privKey)
	if err != nil {
		log.Fatal(err)
	}
	reader, err := os.Open(inFile)
	if err != nil {
		log.Fatal(err)
	}
	defer reader.Close()
	header := make([]byte, 256)
	if _, err := io.ReadFull(reader, header); err != nil {
		log.Fatal(err)
	}
	secret, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, key, header, nil)
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
	if _, err := io.Copy(out, &cipher.StreamReader{S: stream, R: reader}); err != nil {
		log.Fatal(err)
	}
}

func init() {
	log.SetFlags(0)
	flag.Usage = func() {
		usageFmt := "Command %s decrypts file using private RSA key.\nUsage:\n"
		fmt.Fprintf(os.Stderr, usageFmt, os.Args[0])
		flag.PrintDefaults()
	}
	flag.StringVar(&privKey, "key", "", "path to private key in PEM format")
	flag.StringVar(&inFile, "in", "", "path to encrypted file to decrypt")
	flag.StringVar(&outFile, "out", "", "path to decrypted file to create (should not exist)")
	flag.Parse()
}

// readPrivateKey reads and unmarshals RSA private key from PEM format file
func readPrivateKey(file string) (*rsa.PrivateKey, error) {
	b, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("failed to decode PEM file")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
