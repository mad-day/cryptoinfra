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


package stretch


import (
	"github.com/mad-day/cryptoinfra/ciphersuite2"
	"golang.org/x/crypto/sha3"
)

func write(raw []byte,cb *ciphersuite2.Cipher_Buffer) {
	a1 := copy(cb.Key,raw)
	copy(cb.IV,raw[:a1])
}
func sha3kdf(raw []byte,i int,cb *ciphersuite2.Cipher_Buffer) {
	if i<=28 {
		dig := sha3.Sum224(raw)
		write(dig[:],cb)
	} else if i<=32 {
		dig := sha3.Sum256(raw)
		write(dig[:],cb)
	} else if i<=48 {
		dig := sha3.Sum384(raw)
		write(dig[:],cb)
	} else if i<=64 {
		dig := sha3.Sum512(raw)
		write(dig[:],cb)
	}
	sh := sha3.NewShake256()
	sh.Write(raw)
	sh.Read(cb.Key)
	sh.Read(cb.IV)
}

func DeriveKey(raw []byte,cb *ciphersuite2.Cipher_Buffer) {
	i := len(cb.Key)+len(cb.IV)
	if i==len(raw) {
		write(raw,cb)
		return
	}
	sha3kdf(raw,i,cb)
}

func DeriveKeyHash(raw []byte,cb *ciphersuite2.Cipher_Buffer) {
	i := len(cb.Key)+len(cb.IV)
	sha3kdf(raw,i,cb)
}
