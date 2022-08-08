package secretd

import (
	"encoding/binary"
	"io"
	"time"

	"github.com/flynn/noise"
	"github.com/pkg/errors"

	"github.com/niomon/secretd-client-go/cbor"
)

const handshakeMagic = "SecretD_Handshake_1_0"

var cipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)

// connector is used to connect to a server with network streams.
type connector struct {
	authProvider    AuthProvider
	remotePublicKey []byte
}

// newConnector returns a new connector.
func newConnector(remotePublicKey []byte, authProvider AuthProvider) connector {
	return connector{
		remotePublicKey: remotePublicKey,
		authProvider:    authProvider,
	}
}

// connect initiates a handshake to a server. It returns a Session when it completes.
func (c *connector) connect(conn io.ReadWriteCloser) (*session, error) {
	hs, err := clientHandshake(conn, c.remotePublicKey, c.authProvider)
	if err != nil {
		return nil, err
	}
	negotiationData, err := readLengthDelimited(conn)
	if err != nil {
		return nil, errors.New("connection closed")
	}
	if len(negotiationData) > 0 {
		return nil, errors.New("handshake error")
	}
	hsMessage, err := readLengthDelimited(conn)
	if err != nil {
		return nil, errors.New("connection closed")
	}
	var _serverHello []byte
	_, sendState, recvState, err := hs.ReadMessage(_serverHello, hsMessage)
	if err != nil {
		return nil, errors.New("handshake error")
	}

	return &session{
		conn:      conn,
		sendState: sendState,
		recvState: recvState,
	}, nil
}

// session represents an encrypted channel
type session struct {
	conn       io.ReadWriteCloser
	sendState  *noise.CipherState
	recvState  *noise.CipherState
	recvBuffer []byte
}

// Write writes len(p) bytes from p to the underlying data stream.
func (s *session) Write(p []byte) (int, error) {
	n := len(p)
	out, err := s.sendState.Encrypt([]byte{}, []byte{}, p)
	if err != nil {
		return 0, err
	}
	err = writeLengthDelimited(s.conn, out)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// Read reads up to len(p) bytes into p.
func (s *session) Read(p []byte) (n int, err error) {
	if len(s.recvBuffer) == 0 {
		var buffer []byte
		buffer, err = readLengthDelimited(s.conn)
		if err != nil {
			return
		}
		s.recvBuffer, err = s.recvState.Decrypt([]byte{}, []byte{}, buffer)
		if err != nil {
			return
		}
	}
	n = copy(p, s.recvBuffer)
	s.recvBuffer = s.recvBuffer[n:]
	return
}

// Close closes the underlying stream.
func (s *session) Close() error {
	return s.conn.Close()
}

type clientHelloMessage struct {
	_struct    bool `codec:",toarray"`
	Timestamp  uint64
	AuthMethod string
	AuthParams interface{}
}

func clientHandshake(conn io.Writer, remotePublicKey []byte, authProvider AuthProvider) (*noise.HandshakeState, error) {
	negotiationData := []byte(handshakeMagic)
	prologue := makePrologue(negotiationData)
	psk := make([]byte, 32)
	config := noise.Config{
		CipherSuite:           cipherSuite,
		Pattern:               noise.HandshakeIK,
		Initiator:             true,
		Prologue:              prologue,
		PresharedKey:          psk,
		PresharedKeyPlacement: 2,
		PeerStatic:            remotePublicKey,
		StaticKeypair:         authProvider.LocalStaticKeypair(),
	}
	hsState, err := noise.NewHandshakeState(config)
	if err != nil {
		return nil, err
	}

	clientHello := clientHelloMessage{
		Timestamp:  unixNano(),
		AuthMethod: authProvider.Name(),
		AuthParams: authProvider.AuthParams(),
	}
	clientHelloBytes, err := cbor.Encode(clientHello)
	if err != nil {
		return nil, err
	}

	out, _, _, err := hsState.WriteMessage([]byte{}, clientHelloBytes)
	if err != nil {
		return nil, err
	}

	err = writeLengthDelimited(conn, negotiationData)
	if err != nil {
		return nil, err
	}

	err = writeLengthDelimited(conn, out)
	if err != nil {
		return nil, err
	}

	return hsState, nil
}

func writeLengthDelimited(w io.Writer, buf []byte) (err error) {
	length := uint16(len(buf))
	err = binary.Write(w, binary.BigEndian, length)
	if err != nil {
		return
	}
	_, err = w.Write(buf)
	return
}

func readLengthDelimited(r io.Reader) (out []byte, err error) {
	var n uint16
	err = binary.Read(r, binary.BigEndian, &n)
	if err != nil {
		return
	}
	out = make([]byte, n)
	_, err = io.ReadFull(r, out)
	return
}

func makePrologue(negotiationData []byte) []byte {
	prologue := make([]byte, len(negotiationData)+2)
	binary.BigEndian.PutUint16(prologue[0:], uint16(len(negotiationData)))
	copy(prologue[2:], negotiationData)
	return prologue
}

func unixNano() uint64 {
	return uint64(time.Now().UnixNano())
}
