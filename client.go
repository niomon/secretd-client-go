package secretd

import (
	"encoding/base64"
	"io"
	"net"
	"net/rpc"

	"github.com/flynn/noise"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"gitlab.com/blocksq/secretd-client-go/cbor"
)

// AuthProvider is used to implement a client authentication method.
type AuthProvider interface {
	Name() string
	AuthParams() interface{}
	LocalStaticKeypair() noise.DHKey
}

// Client represents an RPC Client. There may be multiple outstanding Calls associated with a
// single Client, and a Client may be used by multiple goroutines simultaneously.
type Client struct {
	*rpc.Client
}

// NewClient returns a new Client to handle requests to the secretd at the end of the connection.
func NewClient(conn io.ReadWriteCloser, serverPublicKeyBase64 string, ap AuthProvider) (cl *Client, err error) {
	serverPublicKey, err := base64.StdEncoding.DecodeString(serverPublicKeyBase64)
	if err != nil {
		logrus.Error("cannot decode server public key")
		return nil, err
	}
	if len(serverPublicKey) != 32 {
		return nil, errors.New("invalid public key length")
	}
	connector := newConnector(serverPublicKey, ap)
	session, err := connector.connect(conn)
	if err != nil {
		return
	}
	codec := cbor.NewRPCClientCodec(session)
	rpcClient := rpc.NewClientWithCodec(codec)
	cl = &Client{rpcClient}
	return
}

// Dial connects to a secretd server at the specified network address.
func Dial(address string, serverPublicKeyBase64 string, ap AuthProvider) (cl *Client, err error) {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return
	}
	return NewClient(conn, serverPublicKeyBase64, ap)
}

func (c *Client) SystemSubrequest(subrequestBytes []byte) ([]byte, error) {
	var response []byte
	err := c.Call("system_subrequest", [][]byte{subrequestBytes}, &response)
	if err != nil {
		logrus.Errorf("error occurred when calling secretd %v", err)
		return nil, err
	}
	return response, nil
}

func (c *Client) HDWalletGenerateWithPolicy(oid string, mnemonicLength int, attributes map[string]string, policyID string) (string, error) {
	attrs := make([][]string, 0)
	for k, v := range attributes {
		attrs = append(attrs, []string{k, v})
	}
	var resp string
	err := c.Call("hdwallet_generate_with_policy", []interface{}{oid, mnemonicLength, attrs, policyID}, &resp)
	if err != nil {
		return "", err
	}
	return resp, nil
}

type HDWalletGetExtendedPublicKeyResponse struct {
	PublicKey         string
	ExtendedPublicKey string
}

func (c *Client) HDWalletGetExtendedPublicKey(oid string, derivePath string) (HDWalletGetExtendedPublicKeyResponse, error) {
	var resp HDWalletGetExtendedPublicKeyResponse
	err := c.Call("hdwallet_get_extended_public_key", []interface{}{oid, derivePath}, &resp)
	if err != nil {
		return HDWalletGetExtendedPublicKeyResponse{}, err
	}
	return resp, nil
}
