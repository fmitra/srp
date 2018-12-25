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
