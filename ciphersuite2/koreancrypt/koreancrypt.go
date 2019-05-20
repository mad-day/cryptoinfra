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
Implements ciphers from Korea Internet Security Agency.
Namely ARIA (128,192,256) and SEED (128-bit)
in various modes of operations.

	Encoding = (
		"aria-128"
		"aria-192"
		"aria-256"
		"seed"
	) + (
		"/gcm"
		"/cbc"
		"/cfb"
		"/ctr"
		"/ofb"
	)
	
The cipher HIGH is bugged somehow and therfore not available.
BTW: HIGH has a block-size of 8 bytes (64 bit) which is not good.
*/
package koreancrypt

// HIGHT(128-bit) and 
/*
	// OR
	Encoding = (
		"high/cbc"
		"high/cfb"
		"high/ctr"
		"high/ofb"
	)
*/

import (
	krc "github.com/dgryski/go-krcrypt"
	
	"github.com/mad-day/cryptoinfra/ciphersuite2/block"
)

func init() {
	bc := &block.BlockCipher{krc.NewARIA,16,16,0}
	bc.RegisterVariants("aria-128")
	bc.Key = 24
	bc.RegisterVariants("aria-192")
	bc.Key = 32
	bc.RegisterVariants("aria-256")
	
	bc = &block.BlockCipher{krc.NewSEED,16,16,0}
	bc.RegisterVariants("seed")
	
	//bc = &block.BlockCipher{krc.NewHIGHT,16,8,0}
	//bc.RegisterVariants("high")
}

