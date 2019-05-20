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
European Brainpool ECC curves.

	PK_Algo = (
		"brainpool_p160"
		"brainpool_p192"
		"brainpool_p224"
		"brainpool_p256"
		"brainpool_p320"
		"brainpool_p384"
		"brainpool_p256"
		"brainpool_p512"
	) + (
		"r1"
		"t1"
	)
*/
package brainpool

import (
	elliptic "github.com/ebfe/brainpool"
	
	"github.com/mad-day/cryptoinfra/ciphersuite2"
	"github.com/mad-day/cryptoinfra/ciphersuite2/ecc"
)

func init() {
	ciphersuite2.RegisterPkAlgo("brainpool_p160r1",ecc.Wrap(elliptic.P160r1()))
	ciphersuite2.RegisterPkAlgo("brainpool_p192r1",ecc.Wrap(elliptic.P192r1()))
	ciphersuite2.RegisterPkAlgo("brainpool_p224r1",ecc.Wrap(elliptic.P224r1()))
	ciphersuite2.RegisterPkAlgo("brainpool_p256r1",ecc.Wrap(elliptic.P256r1()))
	ciphersuite2.RegisterPkAlgo("brainpool_p320r1",ecc.Wrap(elliptic.P320r1()))
	ciphersuite2.RegisterPkAlgo("brainpool_p384r1",ecc.Wrap(elliptic.P384r1()))
	ciphersuite2.RegisterPkAlgo("brainpool_p512r1",ecc.Wrap(elliptic.P512r1()))
	
	ciphersuite2.RegisterPkAlgo("brainpool_p160t1",ecc.Wrap(elliptic.P160t1()))
	ciphersuite2.RegisterPkAlgo("brainpool_p192t1",ecc.Wrap(elliptic.P192t1()))
	ciphersuite2.RegisterPkAlgo("brainpool_p224t1",ecc.Wrap(elliptic.P224t1()))
	ciphersuite2.RegisterPkAlgo("brainpool_p256t1",ecc.Wrap(elliptic.P256t1()))
	ciphersuite2.RegisterPkAlgo("brainpool_p320t1",ecc.Wrap(elliptic.P320t1()))
	ciphersuite2.RegisterPkAlgo("brainpool_p384t1",ecc.Wrap(elliptic.P384t1()))
	ciphersuite2.RegisterPkAlgo("brainpool_p512t1",ecc.Wrap(elliptic.P512t1()))
}

