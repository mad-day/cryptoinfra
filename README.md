# cryptoinfra
Cryptography Infrastructure

**Non-Goals:**
- Inventing or implementing new Ciphers.
- Inventing or implementing new [modes of operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)

**Goals:**
- A file/wire format to deploy ciphers orthogonally yet transparently.
	- CBC mode and similar Block-Modes
	- AEAD modes
	- Stream ciphers


## Parts

### Format 2

*Why Format 2? Where is Format 1? Why is there no Format 1?*

*Because the develope of Format 1 utterly failed, before it was even started.*

[![GoDoc](https://godoc.org/github.com/mad-day/cryptoinfra/format2?status.svg)](https://godoc.org/github.com/mad-day/cryptoinfra/format2)

```go
package main

import "github.com/mad-day/cryptoinfra/format2"
import "fmt"
import "bytes"
import "crypto/aes"
import "crypto/cipher"

type dummy struct{}
func (dummy) StartEncryption() (*format2.Preamble,*format2.CipherObject,error) {
	b,_ := aes.NewCipher([]byte("1234567890abcdef"))
	enc := cipher.NewCBCEncrypter(b,[]byte("1234567890abcdef"))
	return &format2.Preamble{Opaque:[]byte("1234567890abcdef"),PK_Algo:"/",Encoding:"aes"},&format2.CipherObject{Block:enc},nil
}
func (dummy) StartDecryption(p *format2.Preamble) (*format2.CipherObject,error) {
	b,_ := aes.NewCipher([]byte("1234567890abcdef"))
	enc := cipher.NewCBCDecrypter(b,[]byte("1234567890abcdef"))
	return &format2.CipherObject{Block:enc},nil
}

func main() {
	buf := new(bytes.Buffer)
	{
		wr,err := format2.NewWriter(buf,dummy{})
		if err!=nil { fmt.Println(err); return }
		fmt.Println(fmt.Fprintln(wr,"Hello World!"))
		wr.Close()
	}
	fmt.Printf("%q\n",buf.Bytes())
	buf2 := new(bytes.Buffer)
	{
		rd,err := format2.NewReader(buf,dummy{})
		if err!=nil { fmt.Println(err); return }
		buf2.ReadFrom(rd)
	}
	fmt.Printf("%q\n",buf2.Bytes())
}
```