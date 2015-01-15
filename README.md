# ende

This is a set of small utilities to encrypt/decrypt files using public/private
key pairs.  Use `genkeyz utility to generate RSA keypair in supported PEM
format. Public and private keys are only used to encrypt/decrypt one-time key
which is used to do encryption with symmetric cipher (AES-256). Note that
per-file keys are generated from [rand.Reader][1].

 
**Disclaimer**: these programs are not intended as a PGP/gpg replacement, but
mostly as a convenience tool, where brevity of usage is preferred. You probably
want to use gpg instead. Consider these tools as an exercise in using golang's
crypto library API.

Install:

	go get -u -v github.com/artyom/ende/...

`genkeys` usage:

	Command genkeys creates a pair of RSA-2048 keys.
	Usage:
	  -private="": private key file (should not exist)
	  -public="": public key file (should not exist)

`encrypt` usage:

	Command encrypt encrypts file using public RSA key.
	Usage:
	  -in="": path to plaintext file to encrypt
	  -key="": path to public key in PEM format
	  -out="": path to encrypted file to create (should not exist)

`decrypt` usage:

	Command decrypt decrypts file using private RSA key.
	Usage:
	  -in="": path to encrypted file to decrypt
	  -key="": path to private key in PEM format
	  -out="": path to decrypted file to create (should not exist)

[1]: http://golang.org/pkg/crypto/rand/#Reader
