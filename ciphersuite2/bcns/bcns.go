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
This package implements support for bcns, a key exchange based on the Ring Learning With Errors Problem.

	PK_Algo = (
		"bcns"
	)
*/
package bcns

import (
	"github.com/mad-day/cryptoinfra/ciphersuite2"
	"github.com/mad-day/cryptoinfra/ciphersuite2/stretch"
	
	"github.com/mad-day/Yawning-crypto/bcns"
	"io"
)

type pka_driver struct {}

func (*pka_driver) GenerateKeyPair(rand io.Reader) (pub,priv []byte,err error) {
	
	epriv,epub,err2 := bcns.GenerateKeyPair(rand)
	if err2!=nil { err=err2; return }
	priv = epriv.Bytes()
	pub = epub.Bytes()
	
	return
}
func (*pka_driver) LoadPublic(pub []byte) (ciphersuite2.PublicKey,error) {
	k := new(bcns.PublicKey)
	err := k.FromBytes(pub)
	if err!=nil { return nil,err }
	return k,nil
}
func (*pka_driver) LoadPrivate(priv []byte) (ciphersuite2.PrivateKey,error) {
	k := new(bcns.PrivateKey)
	err := k.FromBytes(priv)
	if err!=nil { return nil,err }
	return k,nil
}
func (*pka_driver) DecryptKey(opaque []byte,prik ciphersuite2.PrivateKey,cb *ciphersuite2.Cipher_Buffer) error {
	rp,ok := prik.(*bcns.PrivateKey)
	if !ok { return ciphersuite2.InvalidKeyError("Expected *bcns.PrivateKey") }
	
	Tp := new(bcns.PublicKey)
	rec := new(bcns.RecData)
	
	var oprec []byte
	
	if len(opaque)>bcns.PublicKeySize {
		opaque,oprec = opaque[:bcns.PublicKeySize],opaque[bcns.PublicKeySize:]
	}
	
	err := Tp.FromBytes(opaque)
	if err!=nil { return err }
	err = rec.FromBytes(oprec)
	if err!=nil { return err }
	
	shared := bcns.KeyExchangeAlice(Tp,rp,rec)
	
	stretch.DeriveKey(shared,cb)
	return nil
}
func (*pka_driver) EncryptKey(rand io.Reader,pubk ciphersuite2.PublicKey,cb *ciphersuite2.Cipher_Buffer) (opaque []byte,err error) {
	rp,ok := pubk.(*bcns.PublicKey)
	if !ok { err = ciphersuite2.InvalidKeyError("Expected *bcns.PublicKey"); return }
	
	Ts,Tp,err2 := bcns.GenerateKeyPair(rand)
	if err2!=nil { err = err2; return }
	
	rec,shared,err2 := bcns.KeyExchangeBob(rand,rp,Ts)
	if err2!=nil { err = err2; return }
	
	opaque = make([]byte,bcns.PublicKeySize+bcns.RecDataSize)
	copy(opaque[:bcns.PublicKeySize],Tp.Bytes())
	copy(opaque[bcns.PublicKeySize:],rec.Bytes())
	
	stretch.DeriveKey(shared,cb)
	
	return
}

var _ ciphersuite2.Pka_Driver = (*pka_driver)(nil)

func init(){
	ciphersuite2.RegisterPkAlgo("bcns",new(pka_driver))
}

