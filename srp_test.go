package srp

import (
	"crypto"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreatesEphemeralPrivateKey(t *testing.T) {
	minBitSize := 256
	srp := &SRP{}
	ephemeralPrivateKey := srp.ephemeralPrivate()
	assert.Equal(t, srp.ephemeralPrivateKey, ephemeralPrivateKey)
	assert.True(t, srp.ephemeralPrivateKey.BitLen() >= minBitSize)
}

func TestCreatesMultiplierParameter(t *testing.T) {
	group, _ := NewGroup(Group4096)
	n, _ := group.CalcN()
	srp := &SRP{
		H: crypto.SHA256,
		N: n,
		G: group.G,
	}
	K, err := srp.multiplierParam()
	hex := "0x3516f0d285667a2bc686470c48edf380fd82558f16ac9fe7978b06b11efaf406"
	mp, _ := new(big.Int).SetString(hex, 0)
	assert.NoError(t, err)
	assert.Equal(t, srp.k, K)
	assert.Equal(t, srp.k, mp)
}

func TestMultiplierParamRequiresInitializedSRP(t *testing.T) {
	group, _ := NewGroup(Group4096)
	n, _ := group.CalcN()
	srp := &SRP{}
	_, err := srp.multiplierParam()
	assert.EqualError(t, err, "srp.Group not initialized")

	srp = &SRP{N: n}
	_, err = srp.multiplierParam()
	assert.EqualError(t, err, "srp.Group not initialized")

	srp = &SRP{
		N: n,
		G: group.G,
	}
	_, err = srp.multiplierParam()
	assert.EqualError(t, err, "hash not initialized")
}

func TestServerClientCreatesMatchingScramblingParameter(t *testing.T) {
	c, _ := NewDefaultClient("username", "password")
	s, _ := NewDefaultServer()

	c.salt()
	c.longTermSecret()
	v, _ := c.verifier()

	// Client must provide verifier, salt, username to server
	s.Secret = v
	s.I = c.I
	s.S = c.S
	s.ephemeralPublic()

	// Client and server must exchange ephemeral public keys
	c.ephemeralSharedKey = s.ephemeralPublicKey
	s.ephemeralSharedKey = c.ephemeralPublicKey

	u1 := s.scramblingParam(s.ephemeralSharedKey, s.ephemeralPublicKey)
	u2 := c.scramblingParam(c.ephemeralPublicKey, c.ephemeralSharedKey)

	assert.Equal(t, u1, u2)
}

func TestCannotCreatSRPWithBadGroup(t *testing.T) {
	_, err := NewSRP(crypto.SHA512, &Group{})
	errMsg := "srp.Group not initialized - invalid prime value provided"
	assert.EqualError(t, err, errMsg)
}

func TestCreatesDefaultSRPWithSHA256(t *testing.T) {
	srp, err := NewDefaultSRP()
	assert.NoError(t, err)
	assert.Equal(t, srp.H, crypto.SHA256)
}

func TestClientAndServerCalculatesMatchingKey(t *testing.T) {
	c, _ := NewDefaultClient("username", "password")
	s, _ := NewDefaultServer()

	c.salt()
	c.longTermSecret()
	v, _ := c.verifier()

	// Client must provide verifier, salt, username to server
	s.Secret = v
	s.I = c.I
	s.S = c.S
	s.ephemeralPublic()

	// Client and server must exchange ephemeral public keys
	c.ephemeralSharedKey = s.ephemeralPublicKey
	s.ephemeralSharedKey = c.ephemeralPublicKey

	k1, _ := s.premasterSecret()
	k2, _ := c.premasterSecret()
	assert.Equal(t, k1, k2)
}

func TestClientAndServerValidateProof(t *testing.T) {
	c, _ := NewDefaultClient("username", "password")
	s, _ := NewDefaultServer()

	c.salt()
	c.longTermSecret()
	v, _ := c.verifier()

	// Client must provide verifier, salt, username to server
	s.Secret = v
	s.I = c.I
	s.S = c.S
	s.ephemeralPublic()

	// Client and server must exchange ephemeral public keys
	c.ephemeralSharedKey = s.ephemeralPublicKey
	s.ephemeralSharedKey = c.ephemeralPublicKey

	s.premasterSecret()
	c.premasterSecret()

	// Client must generate proof first
	cProof, cErr := c.clientProof(c.ephemeralPublicKey, c.ephemeralSharedKey)
	sProof, sErr := s.serverProof(cProof, s.ephemeralSharedKey)

	assert.Equal(t, s.PremasterKey, c.PremasterKey)
	assert.NoError(t, cErr)
	assert.NoError(t, sErr)
	assert.True(t, c.IsProofValid(sProof))
	assert.True(t, s.IsProofValid(cProof))
}

func TestServerCannotCreateProofWithoutKey(t *testing.T) {
	s, _ := NewDefaultServer()
	_, err := s.serverProof(&big.Int{}, &big.Int{})
	assert.EqualError(t, err, "premaster key required for calculation")
}

func TestClientCannotCreateProofWithNilClientProof(t *testing.T) {
	c, _ := NewDefaultClient("username", "password")
	_, err := c.clientProof(&big.Int{}, &big.Int{})
	assert.EqualError(t, err, "premaster key required for calculation")
}

func TestClientCanEnrollWithServer(t *testing.T) {
	s, _ := NewDefaultServer()
	c, _ := NewDefaultClient("username", "password")
	uname, salt, v, _ := c.Enroll()

	assert.True(t, s.ProcessEnroll(uname, salt, v))
}

func TestClientFailsToEnrollWithServer(t *testing.T) {
	s, _ := NewDefaultServer()
	c, _ := NewDefaultClient("", "password")
	uname, salt, v, _ := c.Enroll()

	assert.False(t, s.ProcessEnroll(uname, salt, v))
}

func TestClientCanAuthenticateWithServer(t *testing.T) {
	s, _ := NewDefaultServer()
	// Separate clients are used as auth flow from a client that
	// did not perform enrollment should succeedseparate client
	c, _ := NewDefaultClient("username", "password")
	c2, _ := NewDefaultClient("username", "password")

	// Client must enroll with server before authentication
	_, salt, v, _ := c.Enroll()

	// Client must submit username and public key to server
	uname, A := c2.Auth()

	// Server must identify client and respond if valid.
	B, salt2, err := s.ProcessAuth(uname, salt, A, v)
	assert.NoError(t, err)

	// Client must calculate session and key and provide proof
	// of calculation
	cp, err := c2.ProveIdentity(B, salt2)
	assert.NoError(t, err)

	// Server must validate client proof
	sp, err := s.ProcessProof(cp)
	assert.NoError(t, err)

	// Client must validate server proof
	assert.True(t, c2.IsProofValid(sp))
}

func TestClientFailsToAuthenticateWithIncorrectPassword(t *testing.T) {
	s, _ := NewDefaultServer()
	c, _ := NewDefaultClient("username", "password")
	c2, _ := NewDefaultClient("username", "wrong-password")

	// Client must enroll with server before authentication
	_, salt, v, _ := c.Enroll()

	// Client must submit username and public key to server
	uname, A := c2.Auth()

	// Server must identify client and respond if valid.
	B, salt2, err := s.ProcessAuth(uname, salt, A, v)
	assert.NoError(t, err)

	// Client must calculate session and key and provide proof
	// of calculation
	cp, err := c2.ProveIdentity(B, salt2)
	assert.NoError(t, err)

	// Server must invalidate client proof
	sp, err := s.ProcessProof(cp)
	assert.EqualError(t, err, "invalid client proof received")
	assert.Equal(t, sp, &big.Int{})
}

func TestAuthWithSHA512(t *testing.T) {
	g, _ := NewGroup(Group8192)
	s, _ := NewServer(crypto.SHA512, g)
	// Separate clients are used as auth flow from a client that
	// did not perform enrollment should succeedseparate client
	c, _ := NewClient(crypto.SHA512, g, "janedoe", "1ee2f02acdb70f1797db")
	c2, _ := NewClient(crypto.SHA512, g, "janedoe", "1ee2f02acdb70f1797db")

	_, salt, v, _ := c.Enroll()
	uname, A := c2.Auth()
	B, salt2, err := s.ProcessAuth(uname, salt, A, v)
	assert.NoError(t, err)

	cp, err := c2.ProveIdentity(B, salt2)
	assert.NoError(t, err)

	sp, err := s.ProcessProof(cp)
	assert.NoError(t, err)
	assert.True(t, c2.IsProofValid(sp))
}
