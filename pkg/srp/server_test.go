package srp

import (
	"crypto"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEphemeralPublicKeyRequiresInitializedServer(t *testing.T) {
	s := &Server{}
	_, err := s.EphemeralPublic()
	assert.EqualError(t, err, "srp.Group not initialized")
}

func TestCreatesEphemeralPublicKey(t *testing.T) {
	srp, _ := NewDefaultSRP()
	srp.Secret = big.NewInt(1234567789000000)
	srp.EphemeralPrivateKey = big.NewInt(1234577890000000000)
	server := &Server{SRP: *srp}
	A, err := server.EphemeralPublic()
	pubHex := "0x7974ccd2f8948e1de2667f9fa367753ecdacd0618177bb867928f2cd99a5" +
		"e27ad0d5d65578af2c39e40a6c98dbe76ff37754ab1d7e12b7b56cb3bc1259348f8e" +
		"b1f62e796b04db57f5d9d038124f806457bd76922e6fc5befd31951876e379e0ef2f" +
		"41f10d2330c87195fd6492b8148523f7cf6f3611d77183efa5a53646da5075f4a727" +
		"0fec90d1380e8ff16c0c3bac0a9b156f6a171f4f75531047f0ea2dfc6a260a1e6f52" +
		"9992774266ce630a17082ce8a376fa3ba754651bc88aaa98c00623b4458d20f906f4" +
		"d0077915bc1fee21d47d72c554d50f8029a5c8e3d087e9c29e916dc710a8b79c2806" +
		"267af18e7b3243acdca70222293cd9eb2499dc5203bb78f421709cfe1b0202654739" +
		"500b03d6f2b2f154abae0c9caff61e2a7844a8581e2a944207ae463f5fe0e26cd172" +
		"986bfccf338f732500dc55a2b2b7df642be27133825c2c6b67d30aae7fa512bf7f7f" +
		"ba68a10a0c3d62d16ec5ed337727c19a0668fde8e1304f2fb5b368183ce35f9f2452" +
		"413ed83ec034262cfd90e819c5df6d273bbb153cc2567cfc53e60c843f620858e4f0" +
		"115b613930a06724b47579aed779aaaefdf67deb509d3cd59923391af09af5ff1eef" +
		"dbec4d177e538c53c41be725d1b88f15bb89e0eb5d46bc7e9d08ccdcfad73b6cd449" +
		"a10df77514ef1ddae602cba23463f69abbb0b20822948f03a375a260bbc3d69c2ec6" +
		"690c596f60de"
	pub, _ := new(big.Int).SetString(pubHex, 0)
	assert.NoError(t, err)
	assert.Equal(t, server.EphemeralPublicKey, A)
	assert.Equal(t, A, pub)
}

func TestCreatesDefaultServer(t *testing.T) {
	server, err := NewDefaultServer()
	assert.NoError(t, err)
	assert.Equal(t, server.H, crypto.SHA256)
}
