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
	password string
}

// Enroll prepares an enrollment payload for an SRP server.
// We expect enrollment payload to be persisted on the server for future
// authentication.
func (c *Client) Enroll() (string, string, *big.Int, error) {
	c.salt()
	c.longTermSecret()
	v, err := c.verifier()
	if err != nil {
		return "", "", &big.Int{}, err
	}

	// Username, Salt, Verifier
	return c.I, c.S, v, nil
}

// Auth prepares an authentication payload for an SRP server.
// We expect a Client to have already completed a RequestEnrollment prior to
// submitting an authentication request.
func (c *Client) Auth() (string, *big.Int) {
	// Username, Ephemeral Public Key A
	return c.I, c.ephemeralPublicKey
}

// ProveIdentity accepts a SRP Server's authentication response and attempts
// to prove Client authentication with the Client's proof of key.
func (c *Client) ProveIdentity(A *big.Int, s string) (*big.Int, error) {
	pk := big.Int{}
	if pk.Mod(A, c.N); pk.Sign() == 0 {
		return &big.Int{}, ErrPublicKeyModuloZero
	}

	c.ephemeralSharedKey = A
	c.S = s

	_, err := c.premasterSecret()
	if err != nil {
		return &big.Int{}, err
	}

	p, _ := c.clientProof(c.ephemeralPublicKey, c.ephemeralSharedKey)
	return p, nil
}

// IsProofValid validates a SRP Server's proof of session key.
func (c *Client) IsProofValid(i *big.Int) bool {
	cP, _ := c.clientProof(c.ephemeralPublicKey, c.ephemeralSharedKey)
	proof, _ := c.serverProof(cP, c.ephemeralPublicKey)
	isValid := proof.Cmp(i) == 0
	return isValid
}

// salt returns a random salt for the client.
func (c *Client) salt() string {
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

// longTermSecret returns the client's long term secret X.
// RFC 5054 2.5.3 Defines X as SHA1(salt|SHA1(username|":"|password))
func (c *Client) longTermSecret() (*big.Int, error) {
	if c.S == "" || c.I == "" || c.password == "" {
		return nil, errors.New("salt, username, and password must be initialized")
	}

	if c.Secret != nil {
		return c.Secret, nil
	}

	if c.H == crypto.Hash(0) {
		return nil, ErrNoHash
	}

	iHasher := c.H.New()
	oHasher := c.H.New()

	iHasher.Write([]byte(c.I))
	iHasher.Write([]byte(":"))
	iHasher.Write([]byte(c.password))
	innerHash := iHasher.Sum(nil)

	oHasher.Write([]byte(c.S))
	oHasher.Write(innerHash)
	hash := oHasher.Sum(nil)

	X := &big.Int{}
	X.SetBytes(hash)

	c.Secret = X
	return X, nil
}

// verifier returns the client's verifier value. A verifier is never persisted
// by the client. It is stored by the SRP server in place of a password to serve
// as the Server's long term secret, v.
// RFC 5054 2.5.3 Defines V as g^x % N
func (c *Client) verifier() (*big.Int, error) {
	if c.G == nil || c.N == nil {
		return nil, ErrNoGroupParams
	}

	x, err := c.longTermSecret()
	if err != nil {
		return nil, fmt.Errorf("%s - %s", ErrCalcVerifier, err)
	}

	v := &big.Int{}
	v.Exp(c.G, x, c.N)
	return v, nil
}

// ephemeralPublic calculate's the client's ephemeral public key A.
// RFC 5054 2.6 Defines A as g^a % N
func (c *Client) ephemeralPublic() (*big.Int, error) {
	if c.G == nil || c.N == nil {
		return nil, ErrNoGroupParams
	}

	A := &big.Int{}
	A.Exp(c.G, c.ephemeralPrivateKey, c.N)
	c.ephemeralPublicKey = A
	return c.ephemeralPublicKey, nil
}

// premasterSecret creates the premaster secret key. If either client/server pair
// fails to calculate the premaster secret, final messages will fail to decrypt.
// RFC 5054 2.6 Defines the client secret as (B - (k * g^x))^(a + (u * x)) % N
func (c *Client) premasterSecret() (*big.Int, error) {
	if c.G == nil || c.N == nil {
		return nil, ErrNoGroupParams
	}

	if c.ephemeralPublicKey == nil || c.ephemeralSharedKey == nil {
		return nil, ErrNoEphemeralKeys
	}

	ownKey := big.Int{}
	if ownKey.Mod(c.ephemeralPublicKey, c.N); ownKey.Sign() == 0 {
		return nil, ErrPublicKeyModuloZero
	}

	otherKey := big.Int{}
	if otherKey.Mod(c.ephemeralSharedKey, c.N); otherKey.Sign() == 0 {
		return nil, ErrPublicKeyModuloZero
	}

	if c.k == nil {
		c.multiplierParam()
	}

	if c.Secret == nil {
		c.longTermSecret()
	}

	c.scramblingParam(c.ephemeralPublicKey, c.ephemeralSharedKey)

	t1 := &big.Int{}
	t2 := &big.Int{}

	// (a + (u * x))
	t2.Mul(c.u, c.Secret)
	t2.Add(t2, c.ephemeralPrivateKey)

	// (B - (k * g^x))
	t1.Exp(c.G, c.Secret, c.N)
	t1.Mul(t1, c.k)
	t1.Sub(c.ephemeralSharedKey, t1)
	t1.Mod(t1, c.N)

	k := &big.Int{}
	k.Exp(t1, t2, c.N)
	c.PremasterKey = k

	return c.PremasterKey, nil
}

// NewClient returns an SRP Clientwith user defined hash and group.
func NewClient(h crypto.Hash, g *Group, u, p string) (*Client, error) {
	srp, err := NewSRP(h, g)
	if err != nil {
		return &Client{}, err
	}
	srp.I = u
	client := &Client{
		SRP:      *srp,
		password: p,
	}
	client.ephemeralPublic()
	return client, nil
}

// NewDefaultClient returns an SRP Client preconfigured for parameters
// Group4096 and SHA256 hashing function.
func NewDefaultClient(u, p string) (*Client, error) {
	g, _ := NewGroup(Group4096)
	return NewClient(crypto.SHA256, g, u, p)
}
