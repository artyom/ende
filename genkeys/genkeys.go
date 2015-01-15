// Command genkeys creates a pair of private and public RSA-2048 keys in PEM
// format.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
)

const nBits = 2048

func main() {
	var pubKeyFile, privKeyFile string
	flag.StringVar(&privKeyFile, "private", "", "private key file (should not exist)")
	flag.StringVar(&pubKeyFile, "public", "", "public key file (should not exist)")
	flag.Parse()
	if len(pubKeyFile) == 0 || len(privKeyFile) == 0 {
		flag.Usage()
		os.Exit(1)
	}
	privKey, err := rsa.GenerateKey(rand.Reader, nBits)
	if err != nil {
		log.Fatal(err)
	}
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privKey)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		log.Fatal(err)
	}
	privKeyPemBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privKeyBytes,
		},
	)
	pubKeyPemBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubKeyBytes,
		},
	)
	if err := writeFile(privKeyFile, privKeyPemBytes, 0600); err != nil {
		log.Fatal(err)
	}
	if err := writeFile(pubKeyFile, pubKeyPemBytes, 0644); err != nil {
		log.Fatal(err)
	}
}

func init() {
	log.SetFlags(0)
	flag.Usage = func() {
		usageFmt := "Command %s creates a pair of RSA-%d keys.\nUsage:\n"
		fmt.Fprintf(os.Stderr, usageFmt, os.Args[0], nBits)
		flag.PrintDefaults()
	}
}

// writeFile writes data to a file named by filename. The file should not exist,
// writeFile creates it with permissions perm.
func writeFile(filename string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	n, err := f.Write(data)
	if err == nil && n < len(data) {
		err = io.ErrShortWrite
	}
	if err1 := f.Close(); err == nil {
		err = err1
	}
	return err
}
