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
// by the client. It is stored by the SRP server in place of a password to serve
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

// PremasterSecret creates the premaster secret key. If either client/server pair
// fails to calculate the premaster secret, final messages will fail to decrypt.
// RFC 5054 2.6 Defines the client secret as (B - (k * g^x))^(a + (u * x)) % N
func (c *Client) PremasterSecret() (*big.Int, error) {
	if c.G == nil || c.N == nil {
		return nil, errors.New("srp.Group not initialized")
	}

	if c.EphemeralPublicKey == nil || c.EphemeralSharedKey == nil {
		return nil, errors.New("shared keys A/B not calculated")
	}

	ownKey := big.Int{}
	if ownKey.Mod(c.EphemeralPublicKey, c.N); ownKey.Sign() == 0 {
		return nil, errors.New("generated invalid public key, key % N cannot be 0")
	}

	otherKey := big.Int{}
	if otherKey.Mod(c.EphemeralSharedKey, c.N); otherKey.Sign() == 0 {
		return nil, errors.New("received invalid public key, key % N cannot be 0")
	}

	if c.K == nil {
		c.MultiplierParam()
	}

	if c.Secret == nil {
		c.LongTermSecret()
	}

	c.scramblingParam()

	t1 := &big.Int{}
	t2 := &big.Int{}

	// (a + (u * x))
	t2.Mul(c.U, c.Secret)
	t2.Add(t2, c.EphemeralPrivateKey)

	// (B - (k * g^x))
	t1.Exp(c.G, c.Secret, c.N)
	t1.Mul(t1, c.K)
	t1.Sub(c.EphemeralSharedKey, t1)
	t1.Mod(t1, c.N)

	k := &big.Int{}
	k.Exp(t1, t2, c.N)
	c.PremasterKey = k

	return c.PremasterKey, nil
}

// scramblingParam returns a scrambling paramter U.
// RFC 5054 2.5.3 Defines U as SHA1(A | B)
func (c *Client) scramblingParam() *big.Int {
	h := c.H.New()
	// EphemeralSharedKey is written first to match
	// server order.
	h.Write(c.EphemeralSharedKey.Bytes())
	h.Write(c.EphemeralPublicKey.Bytes())

	U := &big.Int{}
	c.U = U.SetBytes(h.Sum(nil))
	return c.U
}

// ProofOfKey creates hash to prove prior calculation of the premaster secret.
// Client must send proof of key prior to the Server as client proof is used
// in the Server's own proof of key.
// RFC 2945 Defines the proof as H(H(N) XOR H(g), H(I), s, A, B, H(premaster-secret))
func (c *Client) ProofOfKey() (*big.Int, error) {
	if c.PremasterKey == nil {
		return nil, errors.New("premaster key required to calculate proof")
	}

	// Client proof of key
	proof := c.H.New()
	// Inner hashes for proof of key
	nHash := c.H.New()
	gHash := c.H.New()
	uHash := c.H.New()
	kHash := c.H.New()

	nHash.Write(c.N.Bytes())
	gHash.Write(c.G.Bytes())

	xor := &big.Int{}
	nHashI := &big.Int{}
	gHashI := &big.Int{}
	nHashI.SetBytes(nHash.Sum(nil))
	gHashI.SetBytes(gHash.Sum(nil))
	xor.Xor(nHashI, gHashI)

	uHash.Write([]byte(c.Username))
	kHash.Write(c.PremasterKey.Bytes())

	proof.Write(xor.Bytes())
	proof.Write(uHash.Sum(nil))
	proof.Write([]byte(c.S))
	proof.Write(c.EphemeralPublicKey.Bytes())
	proof.Write(c.EphemeralSharedKey.Bytes())
	proof.Write(kHash.Sum(nil))

	proofInt := &big.Int{}
	proofInt.SetBytes(proof.Sum(nil))
	return proofInt, nil
}

// ValidateProof validates a SRP Server's proof of session key.
func (c *Client) IsProofValid(i *big.Int) bool {
	// TODO
	return false
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

// NewDefaultClient returns an SRP server preconfigured for parameters
// Group4096 and SHA256 hashing function.
func NewDefaultClient(u, p string) (*Client, error) {
	srp, err := NewDefaultSRP()
	if err != nil {
		return &Client{}, err
	}
	client := &Client{
		SRP:      *srp,
		Username: u,
		Password: p,
	}
	client.EphemeralPublic()
	return client, nil
}
