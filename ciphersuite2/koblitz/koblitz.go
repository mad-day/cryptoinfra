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
Bitelliptic implements several Koblitz

	PK_Algo = (
		"koblitz_s160"
		"koblitz_s192"
		"koblitz_s224"
		"koblitz_s256"
	)
*/
package koblitz

import (
	elliptic "github.com/sour-is/koblitz/kelliptic"
	
	"github.com/mad-day/cryptoinfra/ciphersuite2"
	"github.com/mad-day/cryptoinfra/ciphersuite2/ecc"
)

func init() {
	ciphersuite2.RegisterPkAlgo("koblitz_s160",ecc.Wrap(elliptic.S160()))
	ciphersuite2.RegisterPkAlgo("koblitz_s192",ecc.Wrap(elliptic.S192()))
	ciphersuite2.RegisterPkAlgo("koblitz_s224",ecc.Wrap(elliptic.S224()))
	ciphersuite2.RegisterPkAlgo("koblitz_s256",ecc.Wrap(elliptic.S256()))
}

