package secretd

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/flynn/noise"
	"github.com/stretchr/testify/assert"
)

type authProvider struct {
	s noise.DHKey
}

func (a *authProvider) Name() string {
	return "null"
}
func (a *authProvider) AuthParams() interface{} {
	return nil
}
func (a *authProvider) LocalStaticKeypair() noise.DHKey {
	return a.s
}

type mockConn struct {
	r *bytes.Buffer
	w *bytes.Buffer
}

func newMockConn(resp []byte) *mockConn {
	return &mockConn{
		r: bytes.NewBuffer(resp),
		w: &bytes.Buffer{},
	}
}

func (m *mockConn) Read(p []byte) (int, error) {
	return m.r.Read(p)
}
func (m *mockConn) Write(p []byte) (int, error) {
	return m.w.Write(p)
}

func (*mockConn) Close() error {
	return nil
}

func TestClientHandshake(t *testing.T) {
	serverPrivateKey, _ := hex.DecodeString("a4841649e94d627f7055affcb39c4ec000b1c2cc2aaa7e583c476f30eadb3d36")
	serverPublicKey, _ := hex.DecodeString("1c0636267d4e931cf4c8254faf61d5e54341a6f91366488d299f92792213b504")
	clientPrivateKey, _ := hex.DecodeString("0bf8b4563510b9c3e1c7a62b41fbc9e568c34e6d7e880bf7e9d0980f8aa31256")
	clientPublicKey, _ := hex.DecodeString("441e5e44179cea4b1c33fb5d6899659b79bd4d3997888f9f9899eb6d2dc5de26")
	ap := authProvider{s: noise.DHKey{
		Public:  clientPublicKey,
		Private: clientPrivateKey,
	}}

	// Test client handshake message
	conn := newMockConn([]byte{})
	_, err := clientHandshake(conn, serverPublicKey, &ap)
	assert.NoError(t, err)

	negotiationData := []byte(handshakeMagic)
	prologue := makePrologue(negotiationData)
	psk := make([]byte, 32)
	hsState, _ := noise.NewHandshakeState(noise.Config{
		CipherSuite:           cipherSuite,
		Pattern:               noise.HandshakeIK,
		Initiator:             false,
		Prologue:              prologue,
		PresharedKey:          psk,
		PresharedKeyPlacement: 2,
		StaticKeypair: noise.DHKey{
			Private: serverPrivateKey,
			Public:  serverPublicKey,
		},
	})
	b := conn.w.Bytes()
	assert.Equal(t, "0015536563726574445f48616e647368616b655f315f30", hex.EncodeToString(b[:23]))

	assert.Equal(t, "0070", hex.EncodeToString(b[23:25]))
	out, _, _, err := hsState.ReadMessage([]byte{}, b[25:])
	assert.NoError(t, err)
	// ignore the timestamp
	assert.Equal(t, "83", hex.EncodeToString(out[:1]))
	assert.Equal(t, "646e756c6cf6", hex.EncodeToString(out[10:]))

}
