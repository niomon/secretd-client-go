package cbor

import (
	"bytes"
	"encoding/hex"
	"net/rpc"
	"testing"

	"github.com/stretchr/testify/assert"
)

type buffer struct {
	*bytes.Buffer
}

func newBuffer(buf []byte) *buffer {
	return &buffer{
		bytes.NewBuffer(buf),
	}
}

func (*buffer) Close() error {
	return nil
}

func TestWriteRequest(t *testing.T) {
	buf := newBuffer(make([]byte, 0, 50))
	codec := NewRPCClientCodec(buf)

	r := rpc.Request{
		ServiceMethod: "hello",
		Seq:           0,
	}
	err := codec.WriteRequest(&r, []uint64{1})
	assert.NoError(t, err)
	assert.Equal(t, "8400006568656c6c6f8101", hex.EncodeToString(buf.Bytes()))
}

func TestReadResponse(t *testing.T) {
	response, _ := hex.DecodeString("840100f68102")
	buf := newBuffer(response)
	codec := NewRPCClientCodec(buf)

	r := rpc.Response{}
	err := codec.ReadResponseHeader(&r)
	if assert.NoError(t, err) {
		assert.Empty(t, r.Error)
		assert.Equal(t, uint64(0), r.Seq)
		var body []uint
		err = codec.ReadResponseBody(&body)
		assert.NoError(t, err)
		assert.Equal(t, []uint{2}, body)
	}
}

func TestReadErrorResponse(t *testing.T) {
	response, _ := hex.DecodeString("840100656572726F72F6")
	buf := newBuffer(response)
	codec := NewRPCClientCodec(buf)

	r := rpc.Response{}
	err := codec.ReadResponseHeader(&r)
	if assert.NoError(t, err) {
		assert.Equal(t, "error", r.Error)
		assert.Equal(t, uint64(0), r.Seq)
		var body interface{}
		err = codec.ReadResponseBody(&body)
		assert.NoError(t, err)
		assert.Equal(t, nil, body)
	}
}