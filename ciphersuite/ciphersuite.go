/*
Copyright (c) 2018 Simon Schmidt

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

/*
A (not so extensible) Ciphersuite for Format 2.
*/
package ciphersuite

import "crypto/cipher"
import "errors"
import "io"

var ENextKE = errors.New("Next KE Algo")
var ENextKeyRing = errors.New("Next Key Ring")
var ENoPublicKey = errors.New("No Public Key")
var EInvalidInput = errors.New("EInvalidInput")

type EncryptionKeyData interface{
	get32() *[32]byte
}

type EncryptionAlgorithm struct{
	Name   string
	Block  func(e EncryptionKeyData) cipher.BlockMode
	Stream func(e EncryptionKeyData) cipher.Stream
	AEAD   func(e EncryptionKeyData) cipher.AEAD
}
func Register_EncryptionAlgorithm(e *EncryptionAlgorithm) {
	allEncryptionAlgorithms[e.Name] = e
}

var allEncryptionAlgorithms = make(map[string]*EncryptionAlgorithm)

type KeyRing interface{
	Algo() string
	IsKeyRing()
}
type PublicKey interface{
	Algo() string
	IsPublicKey()
}

type KeyExchangeAlgoritm struct{
	Name   string
	Encode func(rand io.Reader,pub PublicKey) (EncryptionKeyData,[]byte,error)
	Decode func(rand io.Reader,opaque []byte,kring KeyRing) (EncryptionKeyData,error)
}
func Register_KeyExchangeAlgoritm(e *KeyExchangeAlgoritm) {
	allKeyExchangeAlgoritm[e.Name] = e
}

var allKeyExchangeAlgoritm = make(map[string]*KeyExchangeAlgoritm)

func NextKE() (EncryptionKeyData,[]byte,error) {
	return nil,nil,ENextKE
}
func NextKeyRing() (EncryptionKeyData,error) {
	return nil,ENextKeyRing
}
