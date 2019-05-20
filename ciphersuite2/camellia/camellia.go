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
Implements CAMELLIA encryption algorithm (128,192,256 bit) in various modes of operations.

	Encoding = (
		"camellia-128"
		"camellia-192"
		"camellia-256"
	) + (
		"/gcm"
		"/cbc"
		"/cfb"
		"/ctr"
		"/ofb"
	)
*/
package camellia

import (
	"crypto/cipher"
	"github.com/mad-day/go-various-ciphers/camellia"
	
	"github.com/mad-day/cryptoinfra/ciphersuite2/block"
)

func mkCipher(key []byte) (cipher.Block,error) {
	n := new(camellia.Camellia)
	err := n.Init(key)
	if err!=nil { return nil,err }
	return n,nil
}


func init() {
	bc := &block.BlockCipher{mkCipher,16,16,0}
	bc.RegisterVariants("camellia-128")
	bc.Key = 24
	bc.RegisterVariants("camellia-192")
	bc.Key = 32
	bc.RegisterVariants("camellia-256")
}

