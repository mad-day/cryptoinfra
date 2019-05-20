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
This package implements support for curve25519

	PK_Algo = (
		"curve25519"
	)
*/
package pk25519

import (
	"github.com/mad-day/cryptoinfra/ciphersuite2"
	"github.com/mad-day/cryptoinfra/ciphersuite2/stretch"
	
	"golang.org/x/crypto/curve25519"
	"io"
)

type pka_driver struct {}

func (*pka_driver) GenerateKeyPair(rand io.Reader) (pub,priv []byte,err error) {
	secret := new([32]byte)
	public := new([32]byte)
	_,err = io.ReadFull(rand,secret[:])
	secret[0] &= 248;
	secret[31] &= 127;
	secret[31] |= 64;
	curve25519.ScalarBaseMult(public,secret)
	if err==nil {
		pub = public[:]
		priv = secret[:]
	}
	return
}
func (*pka_driver) LoadPublic(pub []byte) (ciphersuite2.PublicKey,error) {
	k := new([32]byte)
	copy(k[:],pub)
	return k,nil
}
func (*pka_driver) LoadPrivate(priv []byte) (ciphersuite2.PrivateKey,error) {
	k := new([32]byte)
	copy(k[:],priv)
	return k,nil
}
func (*pka_driver) DecryptKey(opaque []byte,prik ciphersuite2.PrivateKey,cb *ciphersuite2.Cipher_Buffer) error {
	rp,ok := prik.(*[32]byte)
	if !ok { return ciphersuite2.InvalidKeyError("Expected *[32]byte") }
	pub := new([32]byte)
	shared := new([32]byte)
	copy(pub[:],opaque)
	curve25519.ScalarMult(shared,rp,pub)
	stretch.DeriveKey(shared[:],cb)
	return nil
}
func (*pka_driver) EncryptKey(rand io.Reader,pubk ciphersuite2.PublicKey,cb *ciphersuite2.Cipher_Buffer) (opaque []byte,err error) {
	rp,ok := pubk.(*[32]byte)
	if !ok { return nil,ciphersuite2.InvalidKeyError("Expected *[32]byte") }
	secret := new([32]byte)
	public := new([32]byte)
	shared := new([32]byte)
	_,err = io.ReadFull(rand,secret[:])
	secret[0] &= 248;
	secret[31] &= 127;
	secret[31] |= 64;
	curve25519.ScalarBaseMult(public,secret)
	curve25519.ScalarMult(shared,secret,rp)
	if err==nil {
		stretch.DeriveKey(shared[:],cb)
		opaque = public[:]
	}
	return
}


var _ ciphersuite2.Pka_Driver = (*pka_driver)(nil)

func init(){
	ciphersuite2.RegisterPkAlgo("curve25519",new(pka_driver))
}

