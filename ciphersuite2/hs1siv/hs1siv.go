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


/*
Implements the HS1-SIV Authenticated Cipher.

	Encoding = (
		"hs1siv"
	)
*/
package hs1siv

import (
	"github.com/mad-day/cryptoinfra/ciphersuite2"
	"github.com/mad-day/cryptoinfra/format2"
	
	"github.com/Yawning/hs1siv"
)

type hs1sivDriver struct{}

var _ ciphersuite2.Cipher_Driver = hs1sivDriver{}

func (hs1sivDriver) Keybuf() *ciphersuite2.Cipher_Buffer {
	return &ciphersuite2.Cipher_Buffer{Key:make([]byte,hs1siv.KeySize)}
}
func (hs1sivDriver) Encrypt(b *ciphersuite2.Cipher_Buffer) (*format2.CipherObject, error) {
	aead := hs1siv.New(b.Key)
	return &format2.CipherObject{AEAD:aead},nil
}
func (hs1sivDriver) Decrypt(b *ciphersuite2.Cipher_Buffer) (*format2.CipherObject, error) {
	aead := hs1siv.New(b.Key)
	return &format2.CipherObject{AEAD:aead},nil
}
func init() {
	ciphersuite2.RegisterCipher("hs1siv",hs1sivDriver{})
}
