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
Implements AES (128,192,256) in various modes of operations.

	Encoding = (
		"chacha20-poly1305"
		"xchacha20-poly1305"
	) + (
		"/gcm"
		"/cbc"
		"/cfb"
		"/ctr"
		"/ofb"
	)
*/
package chacha20poly1305

import (
	"crypto/cipher"
	iciph "golang.org/x/crypto/chacha20poly1305"
	
	"github.com/mad-day/cryptoinfra/ciphersuite2"
	"github.com/mad-day/cryptoinfra/format2"
)

type c20p1305 int

func (c20p1305) Keybuf() *ciphersuite2.Cipher_Buffer {
	return &ciphersuite2.Cipher_Buffer{
		Key:make([]byte,32),
	}
}
func (c c20p1305) Encrypt(b *ciphersuite2.Cipher_Buffer) (*format2.CipherObject,error) {
	var aead cipher.AEAD
	var err  error
	switch c {
	case 0: aead,err = iciph.New(b.Key)
	case 1: aead,err = iciph.NewX(b.Key)
	default: panic("unknown variant")
	}
	if err!=nil { return nil,err }
	return &format2.CipherObject{AEAD:aead},nil
}
func (c c20p1305) Decrypt(b *ciphersuite2.Cipher_Buffer) (*format2.CipherObject,error) { return c.Encrypt(b) }


func init() {
	ciphersuite2.RegisterCipher("chacha20-poly1305",c20p1305(0))
	ciphersuite2.RegisterCipher("xchacha20-poly1305",c20p1305(1))
}

