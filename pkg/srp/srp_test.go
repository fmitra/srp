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
	ephemeralPrivateKey := srp.EphemeralPrivate()
	assert.Equal(t, srp.EphemeralPrivateKey, ephemeralPrivateKey)
	assert.True(t, srp.EphemeralPrivateKey.BitLen() >= minBitSize)
}

func TestCreatesMultiplierParameter(t *testing.T) {
	group, _ := NewGroup(Group4096)
	N, _ := group.CalcN()
	srp := &SRP{
		H: crypto.SHA256,
		N: N,
		G: group.G,
	}
	K, err := srp.MultiplierParam()
	hex := "0x3516f0d285667a2bc686470c48edf380fd82558f16ac9fe7978b06b11efaf406"
	mp, _ := new(big.Int).SetString(hex, 0)
	assert.NoError(t, err)
	assert.Equal(t, srp.K, K)
	assert.Equal(t, srp.K, mp)
}

func TestMultiplierParamRequiresInitializedSRP(t *testing.T) {
	group, _ := NewGroup(Group4096)
	N, _ := group.CalcN()
	srp := &SRP{}
	_, err := srp.MultiplierParam()
	assert.EqualError(t, err, "prime value not initialized")

	srp = &SRP{N: N}
	_, err = srp.MultiplierParam()
	assert.EqualError(t, err, "primative root not initialized")

	srp = &SRP{
		N: N,
		G: group.G,
	}
	_, err = srp.MultiplierParam()
	assert.EqualError(t, err, "hash not initialized")
}

func TestServerClientCreatesMatchingScramblingParameter(t *testing.T) {
	c, _ := NewDefaultClient("username", "password")
	s, _ := NewDefaultServer()

	c.Salt()
	c.LongTermSecret()
	v, _ := c.Verifier()

	// Client must provide verifier, salt, username to server
	s.Secret = v
	s.I = c.I
	s.S = c.S
	s.EphemeralPublic()

	// Client and server must exchange ephemeral public keys
	c.EphemeralSharedKey = s.EphemeralPublicKey
	s.EphemeralSharedKey = c.EphemeralPublicKey

	u1 := s.ScramblingParam(s.EphemeralSharedKey, s.EphemeralPublicKey)
	u2 := c.ScramblingParam(c.EphemeralPublicKey, c.EphemeralSharedKey)

	assert.Equal(t, u1, u2)
}

func TestCreatesDefaultSRPWithSHA256(t *testing.T) {
	srp, err := NewDefaultSRP()
	assert.NoError(t, err)
	assert.Equal(t, srp.H, crypto.SHA256)
}

func TestClientAndServerCalculatesMatchingKey(t *testing.T) {
	c, _ := NewDefaultClient("username", "password")
	s, _ := NewDefaultServer()

	c.Salt()
	c.LongTermSecret()
	v, _ := c.Verifier()

	// Client must provide verifier, salt, username to server
	s.Secret = v
	s.I = c.I
	s.S = c.S
	s.EphemeralPublic()

	// Client and server must exchange ephemeral public keys
	c.EphemeralSharedKey = s.EphemeralPublicKey
	s.EphemeralSharedKey = c.EphemeralPublicKey

	k1, _ := s.PremasterSecret()
	k2, _ := c.PremasterSecret()
	assert.Equal(t, k1, k2)
}

func TestClientAndServerValidateProof(t *testing.T) {
	c, _ := NewDefaultClient("username", "password")
	s, _ := NewDefaultServer()

	c.Salt()
	c.LongTermSecret()
	v, _ := c.Verifier()

	// Client must provide verifier, salt, username to server
	s.Secret = v
	s.I = c.I
	s.S = c.S
	s.EphemeralPublic()

	// Client and server must exchange ephemeral public keys
	c.EphemeralSharedKey = s.EphemeralPublicKey
	s.EphemeralSharedKey = c.EphemeralPublicKey

	s.PremasterSecret()
	c.PremasterSecret()

	// Client must generate proof first
	cProof, cErr := c.ClientProof(c.EphemeralPublicKey, c.EphemeralSharedKey)
	sProof, sErr := s.ServerProof(cProof, s.EphemeralSharedKey)

	assert.Equal(t, s.PremasterKey, c.PremasterKey)
	assert.NoError(t, cErr)
	assert.NoError(t, sErr)
	assert.True(t, c.IsProofValid(sProof))
	assert.True(t, s.IsProofValid(cProof))
}

func TestClientCanEnrollWithServer(t *testing.T) {
	s, _ := NewDefaultServer()
	c, _ := NewDefaultClient("username", "password")
	cr, _ := c.StartEnrollment()

	assert.True(t, s.ReceiveEnrollmentRequest(cr))
}

func TestClientFailsToEnrollWithServer(t *testing.T) {
	s, _ := NewDefaultServer()
	c, _ := NewDefaultClient("", "password")
	cr, _ := c.StartEnrollment()

	assert.False(t, s.ReceiveEnrollmentRequest(cr))
}

func TestClientCanAuthenticateWithServer(t *testing.T) {
	s, _ := NewDefaultServer()
	// Separate clients are used as auth flow from a client that
	// did not perform enrollment should succeedseparate client
	c, _ := NewDefaultClient("username", "password")
	c2, _ := NewDefaultClient("username", "password")

	// Client must enroll with server before authentication
	userCreds, _ := c.StartEnrollment()

	// Client must submit username and public key to server
	cr := c2.StartAuthentication()

	// Server must identify client and respond if valid.
	// We assume userCreds has been retrieved from some persisted
	// storage.
	cr, err := s.ReceiveAuthenticationRequest(cr, userCreds)
	assert.NoError(t, err)

	// Client must calculate session and key and provide proof
	// of calculation
	cr, err = c2.ProveIdentity(cr)
	assert.NoError(t, err)

	// Server must validate client proof
	cr, err = s.ReceiveIdentityProof(cr)
	assert.NoError(t, err)

	// Client must validate server proof
	assert.True(t, c2.IsProofValid(cr.Proof))
}

func TestClientFailsToAuthenticateWithIncorrectPassword(t *testing.T) {
	s, _ := NewDefaultServer()
	c, _ := NewDefaultClient("username", "password")
	c2, _ := NewDefaultClient("username", "wrong-password")

	// Client must enroll with server before authentication
	userCreds, _ := c.StartEnrollment()

	// Client must submit username and public key to server
	cr := c2.StartAuthentication()

	// Server must identify client and respond if valid.
	// We assume userCreds has been retrieved from some persisted
	// storage.
	cr, err := s.ReceiveAuthenticationRequest(cr, userCreds)
	assert.NoError(t, err)

	// Client must calculate session and key and provide proof
	// of calculation
	cr, err = c2.ProveIdentity(cr)
	assert.NoError(t, err)

	// Server must invalidate client proof
	cr, err = s.ReceiveIdentityProof(cr)
	assert.EqualError(t, err, "invalid client proof received")
	assert.Nil(t, cr.Proof)
}
