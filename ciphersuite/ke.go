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

package ciphersuite

import "io"
import "golang.org/x/crypto/curve25519"

type ekd32 struct{
	key [32]byte
}
func (e *ekd32) get32() *[32]byte {
	return &e.key
}
var _ EncryptionKeyData = (*ekd32)(nil)

type Curve25519_PublicKey [32]byte
func (c *Curve25519_PublicKey) Algo() string { return "curve25519" }
func (c *Curve25519_PublicKey) IsPublicKey() { }
var _ PublicKey = (*Curve25519_PublicKey)(nil)

type Curve25519_KeyRing map[[32]byte][32]byte
func (c Curve25519_KeyRing) Algo() string { return "curve25519" }
func (c Curve25519_KeyRing) IsKeyRing() { }
var _ KeyRing = (Curve25519_KeyRing)(nil)

func c25519_pub(rand io.Reader,pub PublicKey) (EncryptionKeyData,[]byte,error) {
	c,ok := pub.(*Curve25519_PublicKey)
	if !ok { return NextKE() }
	t := new([32]byte)
	T := new([32]byte)
	e := new(ekd32)
	_,err := rand.Read(t[:])
	if err!=nil { return nil,nil,err }
	curve25519.ScalarBaseMult(T,t)
	curve25519.ScalarMult(&e.key,(*[32]byte)(c),t)
	d := make([]byte,64)
	copy(d,c[:])
	copy(d[32:],T[:])
	return e,d,nil
}
func c25519_priv(rand io.Reader,opaque []byte,kring KeyRing) (EncryptionKeyData,error) {
	c,ok := kring.(Curve25519_KeyRing)
	if !ok { return NextKeyRing() }
	if len(opaque)!=64 { return nil,EInvalidInput }
	t := new([32]byte) // t = Public Key in header.
	T := new([32]byte)
	copy(t[:],opaque)
	copy(T[:],opaque[32:])
	*t,ok = c[*t] // t = Private Key from key-ring
	if !ok { return nil,ENoPublicKey }
	e := new(ekd32)
	curve25519.ScalarMult(&e.key,T,t)
	return e,nil
}

func init(){
	Register_KeyExchangeAlgoritm(&KeyExchangeAlgoritm{"curve25519",c25519_pub,c25519_priv})
}

