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

func TestCreatesSramblingParameter(t *testing.T) {
	srp := &SRP{
		EphemeralSharedKey: big.NewInt(20),
		EphemeralPublicKey: big.NewInt(22),
		N:                  big.NewInt(3),
		H:                  crypto.SHA256,
	}
	hex := "0x54260607e15ce9508bf0a39536d4870a7cb1b9f9da5221ea87fff02597be4bee"
	sp, _ := new(big.Int).SetString(hex, 0)

	U, err := srp.ScramblingParam()
	assert.NoError(t, err)
	assert.Equal(t, srp.U, U)
	assert.Equal(t, srp.U, sp)
}

func TestScramblingParamRequiresInitializedSRP(t *testing.T) {
	srp := &SRP{}
	_, err := srp.ScramblingParam()
	assert.EqualError(t, err, "prime value not initialized")

	srp = &SRP{N: big.NewInt(2)}
	_, err = srp.ScramblingParam()
	assert.EqualError(t, err, "public keys A/B not initialized")

	srp = &SRP{
		EphemeralSharedKey: big.NewInt(20),
		EphemeralPublicKey: big.NewInt(21),
		N:                  big.NewInt(2),
	}
	_, err = srp.ScramblingParam()
	assert.EqualError(t, err, "received invalid public key, key % N cannot be 0")

	srp = &SRP{
		EphemeralSharedKey: big.NewInt(20),
		EphemeralPublicKey: big.NewInt(21),
		N:                  big.NewInt(3),
	}
	_, err = srp.ScramblingParam()
	assert.EqualError(t, err, "generated invalid public key, key % N cannot be 0")

	srp = &SRP{
		EphemeralSharedKey: big.NewInt(20),
		EphemeralPublicKey: big.NewInt(21),
		N:                  big.NewInt(6),
	}
	_, err = srp.ScramblingParam()
	assert.EqualError(t, err, "hash not initialized")
}

func TestCreatesDefaultSRPWithSHA256(t *testing.T) {
	srp, err := NewDefaultSRP()
	assert.NoError(t, err)
	assert.Equal(t, srp.H, crypto.SHA256)
}
