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

/*
Wire format 2, Encrypted Preamble File.
*/
package format2

import "github.com/vmihailenco/msgpack"
import "fmt"
import "bytes"
import "io"
import "bufio"
import "math/rand"

var (
	EUnknownCipherType = fmt.Errorf("Unknown Cipher Type")
	EBlockAlignmentError = fmt.Errorf("Block Alignment Error")
	ENonceError = fmt.Errorf("Nonce Error")
)

func stretch(b []byte,i int) []byte {
	if cap(b)>=i { return b[:i] }
	return make([]byte,i)
}
func unpadd(lb []byte) int {
	/*
	[length] -> padding
	[1] -> 0
	[2] -> 0,1
	[3] -> 0,1,1
	[3] -> 0,?,2
	...
	[256]-> 0,...,255
	*/
	for {
		b := int(lb[len(lb)-1])
		if b==0 { return len(lb)-1 }
		if len(lb)<=b { return 0 }
		lb = lb[:len(lb)-b]
	}
}
func padd(lc []byte) {
	if len(lc)==0 { panic("must have at least one byte over") }
	lc[0] = 0
	lc = lc[1:]
	for len(lc)>255 {
		for i := range lc[:255] {
			lc[i] = 255
		}
		lc = lc[255:]
	}
	if len(lc)>0 {
		bl := byte(len(lc))
		for i := range lc {
			lc[i] = bl
		}
	}
}

type Preamble struct {
	_msgpack struct{} `msgpack:",asArray"`
	Opaque []byte
	PK_Algo  string
	Encoding string
}
type Data struct {
	_msgpack struct{} `msgpack:",asArray"`
	Last  bool
	Nonce []byte
	Data  []byte
}

type Writer struct {
	enc    *msgpack.Encoder
	writer *bufio.Writer
	cipher *CipherObject
	cached Data
	buffer bytes.Buffer
	coder  func(*Writer,bool) error
	errcd  error
	random rand.Source
}
func (w *Writer) randomize() {
	m := 0
	var e uint64
	for i := range w.cached.Nonce {
		if m==0 {
			e = uint64(w.random.Int63())*3
			m+= 8
		}
		w.cached.Nonce[i] ^= byte(e)
		e>>=8
		m--
	}
}
func wBlock(w *Writer,last bool) error {
	bz := w.cipher.Block.BlockSize()
	l := w.buffer.Len()
	if l>=bz {
		L := l - (l%bz)
		data := w.buffer.Next(L)
		w.cached.Data = stretch(w.cached.Data,len(data))
		w.cached.Last = false
		w.cached.Nonce = nil
		w.cipher.Block.CryptBlocks(w.cached.Data,data)
		err := w.enc.Encode(&w.cached)
		if err!=nil { return err }
	}
	if last {
		l = w.buffer.Len()
		lb := make([]byte,bz)
		copy(lb,w.buffer.Next(l))
		padd(lb[l:])
		w.cached.Data = stretch(w.cached.Data,len(lb))
		w.cached.Last = true
		w.cached.Nonce = nil
		w.cipher.Block.CryptBlocks(w.cached.Data,lb)
		return w.enc.Encode(&w.cached)
	}
	return nil
}
func wStream(w *Writer,last bool) error {
	data := w.buffer.Next(w.buffer.Len())
	w.cached.Data = stretch(w.cached.Data,len(data))
	w.cached.Last = false
	w.cached.Nonce = nil
	w.cipher.Stream.XORKeyStream(w.cached.Data,data)
	return w.enc.Encode(&w.cached)
}
func wAEAD(w *Writer,last bool) error {
	nz := w.cipher.AEAD.NonceSize()
	oh := w.cipher.AEAD.Overhead()
	if len(w.cached.Nonce)<=nz {
		w.cached.Nonce = make([]byte,nz)
	}
	w.randomize()
	data := w.buffer.Next(w.buffer.Len())
	w.cached.Data = stretch(w.cached.Data,len(data)+oh)
	w.cached.Last = false
	w.cached.Data = w.cipher.AEAD.Seal(w.cached.Data[:0],w.cached.Nonce[:nz],data,w.cached.Nonce[nz:])
	return w.enc.Encode(&w.cached)
}

/*
NOTE: Returns a *Writer object.
*/
func NewWriter(w io.Writer, enc Encrypter) (io.WriteCloser,error){
	bw := bufio.NewWriter(w)
	pre,ciph,err := enc.StartEncryption()
	if err!=nil { return nil,err }
	g := &Writer{
		enc: msgpack.NewEncoder(bw),
		writer:bw,
		cipher:ciph,
	}
	err = g.enc.Encode(pre)
	if err!=nil { return nil,err }
	switch ciph.mode() {
	case mBlock: g.coder = wBlock
	case mStream: g.coder = wStream
	case mAEAD:
		g.coder = wAEAD
		g.random = rand.NewSource(rand.Int63())
	default: return nil,EUnknownCipherType
	}
	return g,nil
}

func (w *Writer) Write(p []byte) (n int, err error) {
	if w.errcd!=nil { return 0,w.errcd }
	w.buffer.Write(p)
	e := w.coder(w,false)
	if e!=nil { w.errcd = e }
	return len(p),nil
}
func (w *Writer) Close() error {
	err := w.coder(w,true)
	if err!=nil { return err }
	return w.writer.Flush()
}

type Reader struct {
	dec    *msgpack.Decoder
	cipher *CipherObject
	cached Data
	buffer bytes.Buffer
	temp   []byte
	coder  func(*Reader) error
	errcd  error
}
func rBlock(r *Reader) error {
	if (len(r.cached.Data)%r.cipher.Block.BlockSize())!=0 {
		return EBlockAlignmentError
	}
	r.temp = stretch(r.temp,len(r.cached.Data))
	r.cipher.Block.CryptBlocks(r.temp,r.cached.Data)
	if r.cached.Last && len(r.temp)!=0 {
		sz := len(r.temp)-r.cipher.Block.BlockSize()
		r.temp = r.temp[:sz+unpadd(r.temp[sz:])]
	}
	r.buffer.Write(r.temp)
	for i := range r.temp { r.temp[i] = 0 }
	return nil
}
func rStream(r *Reader) error {
	r.temp = stretch(r.temp,len(r.cached.Data))
	r.cipher.Stream.XORKeyStream(r.temp,r.cached.Data)
	r.buffer.Write(r.temp)
	for i := range r.temp { r.temp[i] = 0 }
	return nil
}
func rAEAD(r *Reader) error {
	nz := r.cipher.AEAD.NonceSize()
	//oh := r.cipher.AEAD.Overhead()
	if len(r.cached.Nonce)<nz { return ENonceError }
	r.temp = stretch(r.temp,len(r.cached.Data))
	var err error
	r.temp,err = r.cipher.AEAD.Open(r.temp[:0],r.cached.Nonce[:nz],r.cached.Data,r.cached.Nonce[nz:])
	if err==nil {
		r.buffer.Write(r.temp)
	}
	for i := range r.temp { r.temp[i] = 0 }
	return err
}
/*
NOTE: Returns a *Reader object.
*/
func NewReader(r io.Reader,decr Decrypter) (io.Reader,error) {
	g := &Reader{
		dec:msgpack.NewDecoder(bufio.NewReader(r)),
	}
	p := new(Preamble)
	err := g.dec.Decode(p)
	if err!=nil { return nil,err }
	g.cipher,err = decr.StartDecryption(p)
	if err!=nil { return nil,err }
	switch g.cipher.mode() {
	case mBlock: g.coder = rBlock
	case mStream: g.coder = rStream
	case mAEAD: g.coder = rAEAD
	default: return nil,EUnknownCipherType
	}
	return g,nil
}
func (r *Reader) Read(p []byte) (n int, err error) {
	m,_ := r.buffer.Read(p)
	if m>0 {
		n+=m
		p = p[:m]
	}
	for len(p)>0 {
		if r.errcd!=nil { err = r.errcd ; return }
		err := r.dec.Decode(&r.cached)
		if err!=nil { r.errcd = err ; continue }
		err = r.coder(r)
		if err!=nil { r.errcd = err ; continue }
		m,_ := r.buffer.Read(p)
		if m>0 {
			n+=m
			p = p[:m]
		}
	}
	return
}

