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
This package implements support for x448

	PK_Algo = (
		"x448"
	)
*/
package x448

import (
	"github.com/mad-day/cryptoinfra/ciphersuite2"
	"github.com/mad-day/cryptoinfra/ciphersuite2/stretch"
	
	xcurve "github.com/mad-day/x448"
	"io"
	"fmt"
)

type pka_driver struct {}

func (*pka_driver) GenerateKeyPair(rand io.Reader) (pub,priv []byte,err error) {
	secret := new([56]byte)
	public := new([56]byte)
restart:
	_,err = io.ReadFull(rand,secret[:])
	if err==nil {
		pub = public[:]
		priv = secret[:]
	}
	secret[0] &= 252
	secret[55] |= 128
	res := xcurve.ScalarBaseMult(public,secret)
	if res!=0 { goto restart }
	
	return
}
func (*pka_driver) LoadPublic(pub []byte) (ciphersuite2.PublicKey,error) {
	k := new([56]byte)
	copy(k[:],pub)
	return k,nil
}
func (*pka_driver) LoadPrivate(priv []byte) (ciphersuite2.PrivateKey,error) {
	k := new([56]byte)
	copy(k[:],priv)
	return k,nil
}
func (*pka_driver) DecryptKey(opaque []byte,prik ciphersuite2.PrivateKey,cb *ciphersuite2.Cipher_Buffer) error {
	rp,ok := prik.(*[56]byte)
	if !ok { return ciphersuite2.InvalidKeyError("Expected *[56]byte") }
	pub := new([56]byte)
	shared := new([56]byte)
	copy(pub[:],opaque)
	res := xcurve.ScalarMult(shared,rp,pub)
	if res!=0 { return fmt.Errorf("Decryption failed") }
	stretch.DeriveKey(shared[:],cb)
	return nil
}
func (*pka_driver) EncryptKey(rand io.Reader,pubk ciphersuite2.PublicKey,cb *ciphersuite2.Cipher_Buffer) (opaque []byte,err error) {
	rp,ok := pubk.(*[56]byte)
	if !ok { return nil,ciphersuite2.InvalidKeyError("Expected *[56]byte") }
	secret := new([56]byte)
	public := new([56]byte)
	shared := new([56]byte)
restart:
	_,err = io.ReadFull(rand,secret[:])
	secret[0] &= 252
	secret[55] |= 128
	res1 := xcurve.ScalarBaseMult(public,secret)
	res2 := xcurve.ScalarMult(shared,secret,rp)
	if res1!=0 || res2!=0 { goto restart }
	if err==nil {
		stretch.DeriveKey(shared[:],cb)
		opaque = public[:]
	}
	return
}


var _ ciphersuite2.Pka_Driver = (*pka_driver)(nil)

func init(){
	ciphersuite2.RegisterPkAlgo("x448",new(pka_driver))
}

