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
This package implements support for newhope

	PK_Algo = (
		"newhope"
	)
*/
package newhope

import (
	"github.com/mad-day/cryptoinfra/ciphersuite2"
	"github.com/mad-day/cryptoinfra/ciphersuite2/stretch"
	
	"github.com/mad-day/newhope"
	"io"
)

type pka_driver struct {}

func (*pka_driver) GenerateKeyPair(rand io.Reader) (pub,priv []byte,err error) {
	
	epriv,epub,err2 := newhope.GenerateKeyPair(rand)
	if err2!=nil { err=err2; return }
	priv = epriv.GetBytes(nil)
	pub = epub.Send[:]
	
	return
}
func (*pka_driver) LoadPublic(pub []byte) (ciphersuite2.PublicKey,error) {
	if len(pub)!=newhope.SendASize { return nil,ciphersuite2.MalformedKeyError("NewHope-PublicKey") }
	k := new(newhope.PublicKeyAlice)
	copy(k.Send[:],pub)
	return k,nil
}
func (*pka_driver) LoadPrivate(priv []byte) (ciphersuite2.PrivateKey,error) {
	k := new(newhope.PrivateKeyAlice)
	if !k.SetBytes(priv) {
		return nil,ciphersuite2.MalformedKeyError("NewHope-PrivateKey")
	}
	return k,nil
}
func (*pka_driver) DecryptKey(opaque []byte,prik ciphersuite2.PrivateKey,cb *ciphersuite2.Cipher_Buffer) error {
	rp,ok := prik.(*newhope.PrivateKeyAlice)
	if !ok { return ciphersuite2.InvalidKeyError("Expected *newhope.PrivateKeyAlice") }
	bob := new(newhope.PublicKeyBob)
	copy(bob.Send[:],opaque)
	shared,err := newhope.KeyExchangeAlice(bob,rp)
	if err!=nil { return err }
	stretch.DeriveKey(shared,cb)
	return nil
}
func (*pka_driver) EncryptKey(rand io.Reader,pubk ciphersuite2.PublicKey,cb *ciphersuite2.Cipher_Buffer) (opaque []byte,err error) {
	rp,ok := pubk.(*newhope.PublicKeyAlice)
	if !ok { err = ciphersuite2.InvalidKeyError("Expected *newhope.PublicKeyAlice"); return }
	
	resp,shared,err2 := newhope.KeyExchangeBob(rand,rp)
	if err2!=nil { err = err2; return }
	opaque = resp.Send[:]
	stretch.DeriveKey(shared,cb)
	
	return
}

var _ ciphersuite2.Pka_Driver = (*pka_driver)(nil)

func init(){
	ciphersuite2.RegisterPkAlgo("newhope",new(pka_driver))
}

