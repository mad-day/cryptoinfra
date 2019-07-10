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
Implements Block Modes. This package is intended for SPIs.
The GCM mode is only available for ciphers with 128-bit block size.

	Encoding = (
		$ciphers....
	) + (
		"/gcm"
		"/cbc"
		"/cfb"
		"/ctr"
		"/ofb"
	)

*/
package block

import (
	"crypto/cipher"
	
	"github.com/mad-day/cryptoinfra/ciphersuite2"
	
	"github.com/mad-day/cryptoinfra/format2"
	"github.com/mad-day/go-various-ciphers/crypto/eax"
	
	"fmt"
)

type MakeBlock func(key []byte) (cipher.Block, error)

const (
	GCM = iota
	CBC
	CFB
	CTR
	OFB
	EAX
)


type BlockCipher struct{
	F MakeBlock
	Key int
	IV  int // BlockSize for .RegisterVariants("..."), IV-size otherwise.
	Mode int
}

var _ ciphersuite2.Cipher_Driver = (*BlockCipher)(nil)

func mkbytes(i int) []byte {
	if i==0 { return nil }
	return make([]byte,i)
}

func supportsEax(bz int) bool {
	switch (bz * 8) {
	case 64,128,160,192,224,256,320,384,448,512,768,1024,2048: return true
	}
	return false
}


func (c *BlockCipher) Keybuf() *ciphersuite2.Cipher_Buffer {
	return &ciphersuite2.Cipher_Buffer{
		Key:mkbytes(c.Key),
		IV:mkbytes(c.IV),
	}
}
func (c *BlockCipher) crypt(b *ciphersuite2.Cipher_Buffer,en bool) (*format2.CipherObject,error) {
	block,err := c.F(b.Key)
	if err!=nil { return nil,err }
	obj := new(format2.CipherObject)
	switch c.Mode {
	case CBC,CFB,CTR,OFB:
		if len(b.IV)!=block.BlockSize() { err = fmt.Errorf("BlockSize(%d)!=IV(%d)",block.BlockSize(),len(b.IV)); break }
	}
	switch c.Mode {
	case GCM: obj.AEAD,err = cipher.NewGCM(block)
	case CBC:
		if en {
			obj.Block = cipher.NewCBCEncrypter(block,b.IV)
		} else {
			obj.Block = cipher.NewCBCDecrypter(block,b.IV)
		}
	case CFB:
		if en {
			obj.Stream = cipher.NewCFBEncrypter(block,b.IV)
		} else {
			obj.Stream = cipher.NewCFBDecrypter(block,b.IV)
		}
	case CTR:
		obj.Stream = cipher.NewCTR(block,b.IV)
	case OFB:
		obj.Stream = cipher.NewOFB(block,b.IV)
	case EAX: obj.AEAD,err = eax.New(block,block.BlockSize())
	default: err = fmt.Errorf("illegal mode 0x%x",c.Mode)
	}
	if err!=nil { obj = nil }
	return obj,err
}
func (c *BlockCipher) Encrypt(b *ciphersuite2.Cipher_Buffer) (*format2.CipherObject,error) { return c.crypt(b,true) }
func (c *BlockCipher) Decrypt(b *ciphersuite2.Cipher_Buffer) (*format2.CipherObject,error) { return c.crypt(b,false) }

func (c *BlockCipher) derive(mode int,noiv bool) *BlockCipher {
	other := new(BlockCipher)
	*other = *c
	other.Mode = mode
	if noiv { other.IV = 0 }
	return other
}
func (c *BlockCipher) RegisterVariants(name string) {
	if c.IV==16 {
		ciphersuite2.RegisterCipher(name+"/gcm",c.derive(GCM,true))
	}
	if supportsEax(c.IV) {
		ciphersuite2.RegisterCipher(name+"/eax",c.derive(EAX,true))
	}
	ciphersuite2.RegisterCipher(name+"/cbc",c.derive(CBC,false))
	ciphersuite2.RegisterCipher(name+"/cfb",c.derive(CFB,false))
	ciphersuite2.RegisterCipher(name+"/ctr",c.derive(CTR,false))
	ciphersuite2.RegisterCipher(name+"/ofb",c.derive(OFB,false))
}
