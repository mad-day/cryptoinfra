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
Key Derivation functions for Public-Key-Algorithms.
*/
package stretch


import (
	"github.com/mad-day/cryptoinfra/ciphersuite2"
	"golang.org/x/crypto/sha3"
	"golang.org/x/crypto/salsa20/salsa"
)

var sigma16 [16]byte
var sigma32 [32]byte
func init() {
	s := "Expand 16-bytes key!"
	for i := range sigma16 { sigma16[i] = s[i%len(s)] }
	s  = "Expand 32-bytes key!"
	for i := range sigma32 { sigma32[i] = s[i%len(s)] }
}


func write(raw []byte,cb *ciphersuite2.Cipher_Buffer) {
	a1 := copy(cb.Key,raw)
	copy(cb.IV,raw[:a1])
}

func incr(s *[16]byte) {
	for i := range s {
		s[i]++
		if s[i]!=0 { break }
	}
}

// len(in)<len(out)
func expand(in, out []byte) {
	count := sigma16
	sb1 := new([16]byte)
	sb2 := new([32]byte)
	begin := len(in)
	end := len(out)
	
	copy(out,in)
	
	for {
		l := end-begin
		if l<16 { break }
		
		// Lemma: l>=16
		if begin<16 {
			if end <= len(in) { return }
			
			/*
			Restart with the Whole Input-Key, and process further.
			*/
			begin = len(in)
			incr(&count)
			continue
		}
		copy(sb1[:],in[begin-16:begin])
		salsa.HSalsa20(sb2,sb1,&sigma32,&count)
		copy(out[end-32:end],sb2[:])
		end -= 32
		begin -= 16
		if begin < 0 { begin = 0 }
	}
	
	l := end-begin
	
	// Lemma: l<16
	if l>0 {
		if begin<16 {
			if end <= len(in) { return }
			sha3.ShakeSum256(out[begin:end],out[:begin])
		} else {
			sha3.ShakeSum256(out[begin:end],out[begin-16:begin])
		}
	}
}

// len(in)>len(out)
func shrink(in, out []byte) {
	l := (len(out)+63)/64
	p := len(in)/l
	for i := 1; i<l ; i++ {
		dig := sha3.Sum512(in[:p])
		copy(out,dig[:])
		out = out[64:]
		in  = in[p:]
	}
	shrink_last(in,out)
}

// len(in)>len(out) AND len(out)<=64
func shrink_last(in, out []byte) {
	i := len(out)
	if i<=28 {
		dig := sha3.Sum224(in)
		copy(out,dig[:])
	} else if i<=32 {
		dig := sha3.Sum256(in)
		copy(out,dig[:])
	} else if i<=48 {
		dig := sha3.Sum384(in)
		copy(out,dig[:])
	} else if i<=64 {
		dig := sha3.Sum512(in)
		copy(out,dig[:])
	} else {
		panic("Output chunk too big")
	}
}

func convert(buf []byte) {
	b1 := new([64]byte)
	for len(buf)>=64 {
		copy(b1[:],buf[:64])
		salsa.Core208(b1,b1)
		copy(buf[:64],b1[:])
		buf = buf[64:]
	}
	if len(buf)>=32 {
		dig := sha3.Sum256(buf)
		copy(buf,dig[:])
		buf = buf[32:]
	}
	if len(buf)>=28 {
		dig := sha3.Sum224(buf)
		copy(buf,dig[:])
		buf = buf[28:]
	}
	if len(buf)>0 {
		sha3.ShakeSum256(buf,buf)
	}
}

func DeriveKey(raw []byte,cb *ciphersuite2.Cipher_Buffer) {
	i := len(cb.Key)+len(cb.IV)
	if i>len(raw) {
		nr := make([]byte,i)
		expand(raw,nr)
		raw = nr
	} else if i<len(raw) {
		nr := make([]byte,i)
		shrink(raw,nr)
		raw = nr
	}
	// assert(i==len(raw))
	write(raw,cb)
}

func DeriveKeyHash(raw []byte,cb *ciphersuite2.Cipher_Buffer) {
	i := len(cb.Key)+len(cb.IV)
	nr := make([]byte,i)
	if i>len(raw) {
		expand(raw,nr)
	} else if i<len(raw) {
		shrink(raw,nr)
	} else {
		copy(nr,raw)
	}
	convert(nr)
	
	// assert(i==len(raw))
	write(nr,cb)
}
