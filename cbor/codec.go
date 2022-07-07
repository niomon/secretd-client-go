package cbor

import (
	"bytes"
	"fmt"
	"io"
	"net/rpc"

	"github.com/pkg/errors"
	"github.com/ugorji/go/codec"
)

var cborHandle codec.CborHandle

func init() {
	cborHandle.WriterBufferSize = 65535
}

// Encode writes an object into bytes
func Encode(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := codec.NewEncoder(&buf, &cborHandle)
	err := enc.Encode(v)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Decode decodes an object from byte slice and stores the result in the value pointed to by v
// In particular, when the value interface is an struct and the decoding stream is an array, it will map by the order of fields in the struct.
// See https://pkg.go.dev/github.com/ugorji/go/codec#Decoder.Decode for the behavior for decoding into different interface.
func Decode(b []byte, v interface{}) error {
	buf := bytes.NewBuffer(b)
	enc := codec.NewDecoder(buf, &cborHandle)
	return enc.Decode(v)
}

// RPCClientCodec defines a rpc client codec for CBOR RPC.
type RPCClientCodec struct {
	conn io.ReadWriteCloser
	dec  *codec.Decoder
	enc  *codec.Encoder
}

// NewRPCClientCodec returns a new rpc codec for CBOR RPC.
func NewRPCClientCodec(conn io.ReadWriteCloser) *RPCClientCodec {
	dec := codec.NewDecoder(conn, &cborHandle)
	enc := codec.NewEncoder(conn, &cborHandle)
	return &RPCClientCodec{
		conn: conn,
		dec:  dec,
		enc:  enc,
	}
}

// WriteRequest writes a request to the connection.
func (c *RPCClientCodec) WriteRequest(r *rpc.Request, body interface{}) (err error) {
	msg := []interface{}{0, uint64(r.Seq), r.ServiceMethod, body}
	err = c.enc.Encode(msg)
	return
}

// ReadResponseHeader reads a response header from the connection.
func (c *RPCClientCodec) ReadResponseHeader(r *rpc.Response) (err error) {
	return c.parseCustomHeader(1, &r.Seq, &r.Error)
}

func (c *RPCClientCodec) parseCustomHeader(expectTypeByte byte, msgid *uint64, methodOrError *string) (err error) {
	// We read the response header by hand
	// so that the body can be decoded on its own from the stream at a later time.

	const fia byte = 0x84 //four item array descriptor value

	var ba [1]byte
	var n int
	for {
		n, err = c.conn.Read(ba[:])
		if err != nil {
			return
		}
		if n == 1 {
			break
		}
	}

	var b = ba[0]
	if b != fia {
		err = errors.Errorf("message is not an array - %x", b)
	} else {
		err = c.dec.Decode(&b)
		if err == nil {
			if b != expectTypeByte {
				err = fmt.Errorf("invalid message - expecting %v but got %v",
					expectTypeByte, b)
			} else {
				err = c.dec.Decode(msgid)
				if err == nil {
					var any interface{}
					err = c.dec.Decode(&any)
					if err == nil && any != nil {
						*methodOrError = fmt.Sprintf("%v", any)
					}
				}
			}
		}
	}
	return
}

// ReadResponseBody reads a response body from the connection.
func (c *RPCClientCodec) ReadResponseBody(body interface{}) error {
	// if nil is passed in, we should read and discard
	if body == nil {
		var discard interface{}
		c.dec.Decode(&discard)
	}
	return c.dec.Decode(body)
}

// Close is called when finished with the connection.
func (c *RPCClientCodec) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}
