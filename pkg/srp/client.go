package srp

import (
	"crypto"
	rand "crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

// Client represents an SRP Client. Client possesses a password and initiates
// enrollment and authentication against an SRP Server.
type Client struct {
	SRP
	Username string
	Password string
}

// Salt returns a random salt for the client.
func (c *Client) Salt() string {
	if c.S != "" {
		return c.S
	}

	bytes := make([]byte, 8)
	rand.Read(bytes)
	s := &big.Int{}
	s.SetBytes(bytes)

	c.S = s.String()
	return c.S
}

// LongTermSecret returns the client's long term secret X.
// RFC 5054 2.5.3 Defines X as SHA1(salt|SHA1(username|":"|password))
func (c *Client) LongTermSecret() (*big.Int, error) {
	if c.S == "" || c.Username == "" || c.Password == "" {
		return nil, errors.New("salt, username, and password must be initialized")
	}

	if c.Secret != nil {
		return c.Secret, nil
	}

	if c.H == crypto.Hash(0) {
		return nil, errors.New("hash not initialized")
	}

	iHasher := c.H.New()
	oHasher := c.H.New()

	iHasher.Write([]byte(c.Username))
	iHasher.Write([]byte(":"))
	iHasher.Write([]byte(c.Password))
	innerHash := iHasher.Sum(nil)

	oHasher.Write([]byte(c.S))
	oHasher.Write(innerHash)
	hash := oHasher.Sum(nil)

	X := &big.Int{}
	X.SetBytes(hash)

	c.Secret = X
	return X, nil
}

// Verifier returns the client's verifier value. A verifier is never persisted
// by the client. It is stored by the SRP server in place as a password to serve
// as the Server's long term secret, V.
// RFC 5054 2.5.3 Defines V as g^x % N
func (c *Client) Verifier() (*big.Int, error) {
	if c.G == nil || c.N == nil {
		return nil, errors.New("srp.Group not initialized")
	}

	X, err := c.LongTermSecret()
	if err != nil {
		return nil, errors.New(
			fmt.Sprintf("failed to generate verifier - %s", err),
		)
	}

	V := &big.Int{}
	V.Exp(c.G, X, c.N)
	return V, nil
}

// EphemeralPublic calculate's the client's ephemeral public key A.
// RFC 5054 2.6 Defines A as g^a % N
func (c *Client) EphemeralPublic() (*big.Int, error) {
	if c.G == nil || c.N == nil {
		return nil, errors.New("srp.Group not initialized")
	}

	A := &big.Int{}
	A.Exp(c.G, c.EphemeralPrivateKey, c.N)
	c.EphemeralPublicKey = A
	return A, nil
}

// CalculateSessionKey creates a shared session key. RFC 5054 refers to this
// value as K1 and K2 for client/server.
func (c *Client) CalculateSessionKey() error {
	// TODO
	return nil
}

// CalculateProofOfKey creates hash to prove prior calculation of the shared
// session key.
func (c *Client) CalculateProofOfKey() error {
	// TODO
	return nil
}

// ValidateProof validates a SRP Server's proof of session key.
func (c *Client) ValidateProof() bool {
	// TODO
	return true
}

// RequestEnrollment prepares an enrollment payload for an SRP server.
// We expect enrollment payload to be persisted on the server for future
// authentication.
func (c *Client) RequestEnrollment() {
	// TODO
}

// RequestAuthentication prepares an authentication payload for an SRP server.
// We expect a Client to have already completed a RequestEnrollment prior to
// submitting an authentication request.
func (c *Client) RequestAuthentication() {
	// TODO
}
