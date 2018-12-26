package srp

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreatesNewGroupFromRFC5054Spec(t *testing.T) {
	var tests = []struct {
		s string
		p *big.Int
	}{
		{Group1024, big.NewInt(2)},
		{Group2048, big.NewInt(2)},
		{Group4096, big.NewInt(5)},
		{Group8192, big.NewInt(19)},
	}

	// Spec is noted in RFC 5054 Appendix B
	minBitSize := 1024
	for _, test := range tests {
		g, err := NewGroup(test.s)
		assert.Equal(t, g.G, test.p)
		assert.NoError(t, err)
		assert.True(t, g.N.ProbablyPrime(10))
		assert.True(t, g.N.BitLen() >= minBitSize)
	}
}

func TestErrorForInvalidPrimeHexConversion(t *testing.T) {
	g := &Group{Hex: "invalid-hex-value"}
	_, err := g.CalcN()
	assert.EqualError(t, err, "invalid prime value provided")
}

func TestErrorForInvalidRootPrimative(t *testing.T) {
	_, err := NewGroup("invalid:prime-as-hex")
	assert.EqualError(t, err, "invalid primative root provided")
}
