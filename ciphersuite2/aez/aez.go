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
Implements AEZ AEAD cipher.
See: http://web.cs.ucdavis.edu/~rogaway/aez/

	Encoding = (
		"aez"
	)
*/
package aez

import (
	"github.com/mad-day/cryptoinfra/ciphersuite2"
	"github.com/mad-day/cryptoinfra/format2"
	
	"github.com/mad-day/Yawning-crypto/aez"
)

type aezDriver struct{}

var _ ciphersuite2.Cipher_Driver = aezDriver{}

func (aezDriver) Keybuf() *ciphersuite2.Cipher_Buffer {
	return &ciphersuite2.Cipher_Buffer{Key:make([]byte,16*3)}
}
func (aezDriver) Encrypt(b *ciphersuite2.Cipher_Buffer) (*format2.CipherObject, error) {
	aead,err := aez.New(b.Key)
	if err!=nil { return nil,err }
	return &format2.CipherObject{AEAD:aead},nil
}
func (aezDriver) Decrypt(b *ciphersuite2.Cipher_Buffer) (*format2.CipherObject, error) {
	aead,err := aez.New(b.Key)
	if err!=nil { return nil,err }
	return &format2.CipherObject{AEAD:aead},nil
}
func init() {
	ciphersuite2.RegisterCipher("aez",aezDriver{})
}
