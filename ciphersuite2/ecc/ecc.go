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



package ecc

import (
	"crypto/elliptic"
	
	"github.com/mad-day/cryptoinfra/ciphersuite2"
	"github.com/mad-day/cryptoinfra/ciphersuite2/stretch"
	"io"
	"math/big"
)

type publicKey struct {
	x,y *big.Int
}

type pka_driver struct {
	curve elliptic.Curve
}
var _ ciphersuite2.Pka_Driver = (*pka_driver)(nil)

func (p *pka_driver) GenerateKeyPair(rand io.Reader) (pub,priv []byte,err error) {
	var x,y *big.Int
	priv,x,y,err = elliptic.GenerateKey(p.curve,rand)
	if err!=nil { return }
	pub = elliptic.Marshal(p.curve,x,y)
	return
}
func (p *pka_driver) LoadPublic(pub []byte) (ciphersuite2.PublicKey,error) {
	x,y := elliptic.Unmarshal(p.curve,pub)
	if x==nil { return nil,ciphersuite2.MalformedKeyError("ECC") }
	return publicKey{x,y},nil
}
func (*pka_driver) LoadPrivate(priv []byte) (ciphersuite2.PrivateKey,error) { return priv,nil }
func (p *pka_driver) DecryptKey(opaque []byte,prik ciphersuite2.PrivateKey,cb *ciphersuite2.Cipher_Buffer) error {
	rp,ok := prik.([]byte)
	if !ok { return ciphersuite2.InvalidKeyError("Expected []byte") }
	x,y := elliptic.Unmarshal(p.curve,opaque)
	if x==nil { return ciphersuite2.MalformedEncryptedKeyError("ECC") }
	x,y = p.curve.ScalarMult(x,y,rp)
	stretch.DeriveKeyHash(elliptic.Marshal(p.curve,x,y),cb)
	return nil
}
func (p *pka_driver) EncryptKey(rand io.Reader,pubk ciphersuite2.PublicKey,cb *ciphersuite2.Cipher_Buffer) (opaque []byte,err error) {
	var temp []byte
	var tx,ty,x,y *big.Int
	rp,ok := pubk.(*publicKey)
	if !ok { err = ciphersuite2.InvalidKeyError("Expected ECC key"); return }
	temp,tx,ty,err = elliptic.GenerateKey(p.curve,rand)
	if err!=nil { return }
	x,y = p.curve.ScalarMult(rp.x,rp.y,temp)
	stretch.DeriveKeyHash(elliptic.Marshal(p.curve,x,y),cb)
	opaque = elliptic.Marshal(p.curve,tx,ty)
	return
}

func Wrap(curve elliptic.Curve) ciphersuite2.Pka_Driver { return &pka_driver{curve} }


