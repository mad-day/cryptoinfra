/*
Copyright (c) 2019 Simon Schmidt

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/



package ciphersuite2

import (
	"github.com/mad-day/cryptoinfra/format2"
	"io"
	"fmt"
)

type UnknownCipherError string
func (e UnknownCipherError) Error() string { return "Unknown Cipher Algorithm: "+string(e) }

type UnknownPkaError string
func (e UnknownPkaError) Error() string { return "Unknown Public Key Algorithm: "+string(e) }

type InvalidKeyError string
func (e InvalidKeyError) Error() string { return "Invalid Private/Public Key Object: "+string(e) }

type MalformedKeyError string
func (e MalformedKeyError) Error() string { return "Malformed Private/Public Key: "+string(e) }

type MalformedEncryptedKeyError string
func (e MalformedEncryptedKeyError) Error() string { return "Malformed Encrypted Key: "+string(e) }

var pka_drivers = make(map[string]Pka_Driver)

type KeyRing interface {
	// GetKey SHOULD return the corresponding private key for a ciphertext.
	GetKey(opaque []byte,pk_algo string) (PrivateKey,error)
}
type defaultKeyRing struct{
	priv PrivateKey
}
func (p defaultKeyRing) GetKey(opaque []byte,pk_algo string) (PrivateKey,error) { return p.priv,nil }
func AsKeyRing(priv PrivateKey) KeyRing {
	return defaultKeyRing{priv}
}

// Key-Ring object for wrapped opaques.
type KeyRing2 interface {
	// GetKey2 SHOULD return the corresponding private key for a ciphertext.
	//
	// This works like GetKey except, that opaque might be substituted by n_opaque
	GetKey2(opaque []byte,pk_algo string) (n_opaque []byte, pk PrivateKey,err error)
}


type PublicKey interface {}
type PrivateKey interface {}
type Pka_Driver interface {
	GenerateKeyPair(rand io.Reader) (pub,priv []byte,err error)
	LoadPublic(pub []byte) (PublicKey,error)
	LoadPrivate(priv []byte) (PrivateKey,error)
	
	DecryptKey(opaque []byte,prik PrivateKey,cb *Cipher_Buffer) error
	EncryptKey(rand io.Reader,pubk PublicKey,cb *Cipher_Buffer) (opaque []byte,err error)
}

var cipher_drivers = make(map[string]Cipher_Driver)

type Cipher_Buffer struct {
	Key []byte
	IV  []byte
}

type Cipher_Driver interface {
	Keybuf() *Cipher_Buffer
	Encrypt(b *Cipher_Buffer) (*format2.CipherObject,error)
	Decrypt(b *Cipher_Buffer) (*format2.CipherObject,error)
}

func RegisterCipher(str string,ciph Cipher_Driver) { cipher_drivers[str] = ciph }
func RegisterPkAlgo(str string,pka Pka_Driver) { pka_drivers[str] = pka }

type DecryptionContext struct{
	KeyRing KeyRing
	KeyRing2 KeyRing2
}
func (d *DecryptionContext) getKey2(opaque []byte,pk_algo string) (n_opaque []byte, pk PrivateKey,err error) {
	if d.KeyRing!=nil {
		n_opaque = opaque
		pk,err = d.KeyRing.GetKey(opaque,pk_algo)
	} else {
		n_opaque,pk,err = d.KeyRing2.GetKey2(opaque,pk_algo)
	}
	return
}
func (d *DecryptionContext) StartDecryption(p *format2.Preamble) (*format2.CipherObject,error) {
	opaque,pubk,err := d.getKey2(p.Opaque,p.PK_Algo)
	if err!=nil { return nil,err }
	
	enc,ok := cipher_drivers[p.Encoding]
	if !ok { return nil,UnknownCipherError(p.Encoding) }
	pka,ok := pka_drivers[p.PK_Algo]
	if !ok { return nil,UnknownPkaError(p.PK_Algo) }
	cb := enc.Keybuf()
	err = pka.DecryptKey(opaque,pubk,cb)
	if err!=nil { return nil,err }
	return enc.Decrypt(cb)
}
// Non-Wrapped only.
func Decrypt(kr KeyRing) *DecryptionContext { return &DecryptionContext{kr,nil} }

// Wrapped only.
func Decrypt2(kr KeyRing2) *DecryptionContext { return &DecryptionContext{nil,kr} }

/* Encrypter for non-Wrapped Opaques. */
type EncryptionContext struct {
	PublicKey PublicKey
	PK_Algo   string
	Encoding  string
	Random    io.Reader
}
func (e *EncryptionContext) StartEncryption() (*format2.Preamble, *format2.CipherObject, error) {
	enc,ok := cipher_drivers[e.Encoding]
	if !ok { return nil,nil,UnknownCipherError(e.Encoding) }
	pka,ok := pka_drivers[e.PK_Algo]
	if !ok { return nil,nil,UnknownPkaError(e.PK_Algo) }
	
	cb := enc.Keybuf()
	opaque,err := pka.EncryptKey(e.Random,e.PublicKey,cb)
	if err!=nil { return nil,nil,err }
	
	ciph,err := enc.Encrypt(cb)
	if err!=nil { return nil,nil,err }
	
	return &format2.Preamble{
		Opaque:opaque,
		PK_Algo:e.PK_Algo,
		Encoding:e.Encoding,
	},ciph,nil
}
func GenerateKeyPair(rand io.Reader,pk_algo string) (pub, priv []byte, err error) {
	pka,ok := pka_drivers[pk_algo]
	if !ok { return nil,nil,UnknownPkaError(pk_algo) }
	
	return pka.GenerateKeyPair(rand)
}
func LoadPublicKey(pk_algo string,pub []byte) (PublicKey,error) {
	pka,ok := pka_drivers[pk_algo]
	if !ok { return nil,UnknownPkaError(pk_algo) }
	
	return pka.LoadPublic(pub)
}
func LoadPrivateKey(pk_algo string,priv []byte) (PrivateKey,error) {
	pka,ok := pka_drivers[pk_algo]
	if !ok { return nil,UnknownPkaError(pk_algo) }
	
	return pka.LoadPrivate(priv)
}


