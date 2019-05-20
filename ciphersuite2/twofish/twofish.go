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
Implements Twofish (128,192,256 keysize) in various modes of operations.

	Encoding = (
		"twofish-128"
		"twofish-192"
		"twofish-256"
	) + (
		"/gcm"
		"/cbc"
		"/cfb"
		"/ctr"
		"/ofb"
	)

Deprecated: Twofish is a legacy cipher and should not be used for new applications.
*/
package twofish

import (
	"crypto/cipher"
	"golang.org/x/crypto/twofish"
	
	"github.com/mad-day/cryptoinfra/ciphersuite2/block"
)
func eCipher(key []byte) (cipher.Block,error) { return twofish.NewCipher(key) }

func init() {
	bc := &block.BlockCipher{eCipher,16,16,0}
	bc.RegisterVariants("twofish-128")
	bc.Key = 24
	bc.RegisterVariants("twofish-192")
	bc.Key = 32
	bc.RegisterVariants("twofish-256")
}

