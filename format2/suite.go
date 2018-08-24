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

package format2

import "crypto/cipher"

const (
	m_ = iota
	mBlock
	mStream
	mAEAD
)

/*
A generic cipher that can be a one of...
	cipher.BlockMode
	cipher.Stream
	cipher.AEAD
*/
type CipherObject struct{
	cont struct{}
	Block  cipher.BlockMode
	Stream cipher.Stream
	AEAD   cipher.AEAD
}
func (c *CipherObject) mode() int {
	if c.Block!=nil { return mBlock }
	if c.Stream!=nil { return mStream }
	if c.AEAD!=nil { return mAEAD }
	return 0
}

type Encrypter interface{
	StartEncryption() (*Preamble,*CipherObject,error)
}
type Decrypter interface{
	StartDecryption(p *Preamble) (*CipherObject,error)
}

