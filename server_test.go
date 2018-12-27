package srp

import (
	"crypto"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEphemeralPublicKeyRequiresInitializedServer(t *testing.T) {
	s := &Server{}
	_, err := s.ephemeralPublic()
	assert.EqualError(t, err, "srp.Group not initialized")
}

func TestCreatesEphemeralPublicKey(t *testing.T) {
	srp, _ := NewDefaultSRP()
	srp.Secret = big.NewInt(1234567789000000)
	srp.ephemeralPrivateKey = big.NewInt(1234577890000000000)
	server := &Server{SRP: *srp}
	A, err := server.ephemeralPublic()
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
	assert.Equal(t, server.ephemeralPublicKey, A)
	assert.Equal(t, A, pub)
}

func TestCreatesDefaultServer(t *testing.T) {
	server, err := NewDefaultServer()
	assert.NoError(t, err)
	assert.Equal(t, server.H, crypto.SHA256)
}

func TestServerPremasterSecretRequiresInitializedServer(t *testing.T) {
	server := &Server{}
	_, err := server.premasterSecret()
	assert.EqualError(t, err, "srp.Group not initialized")

	srp, _ := NewDefaultSRP()
	server = &Server{SRP: *srp}
	_, err = server.premasterSecret()
	assert.EqualError(t, err, "shared keys A/B not calculated")

	server, _ = NewDefaultServer()
	server.ephemeralSharedKey = big.NewInt(20)
	server.ephemeralPublicKey = big.NewInt(21)
	server.N = big.NewInt(2)
	_, err = server.premasterSecret()
	assert.EqualError(t, err, "key % N cannot be 0")

	server, _ = NewDefaultServer()
	server.ephemeralSharedKey = big.NewInt(20)
	server.ephemeralPublicKey = big.NewInt(21)
	server.N = big.NewInt(3)
	_, err = server.premasterSecret()
	assert.EqualError(t, err, "key % N cannot be 0")
}

func TestServerCalculatesPremasterSecret(t *testing.T) {
	srp, _ := NewDefaultSRP()
	srp.Secret = big.NewInt(1234567789000000)
	srp.ephemeralPrivateKey = big.NewInt(1234577890000000000)
	server := &Server{SRP: *srp}

	server.ephemeralPublic()
	server.ephemeralSharedKey = big.NewInt(1234577890000000000)

	pHex := "0x184c69c549a5b1b357631c996b214a329a3fabeabbef9565b345d63d9fd2d932" +
		"659c8d3065af73aaa9dbc422063a2450fac3732eb5e3a033514c39ac23d3eec6ac041d" +
		"28ef47323d9de3efa3027a8efa3e1d1a907ba9b5fbd3b828604b4875275289b7464c14" +
		"5224f15e9b27996a9487c1f368df22833a547d8ba1155a8d443f93c1a84fe8519349f5" +
		"c2cd719550cae7a7dc5d620f2da1087b615209a45decb3ad81b63248237e315329df94" +
		"c30433747a93584a97c049a0b34bd11fff1ef003a96cbe8f1d167799ce83bf7fb6d952" +
		"de72cf2aa22225a4ea1e6766f661a60d1274341e04c5b15e540f811533d90d8147dfb7" +
		"14f9d8b275811fd8580975f21cb17a9263413815fb30e485d540dab67e607edf19cea8" +
		"fe121280a4c816d7d043f6f23b627cd7f9b827fce61030f9d9ce840970d98b9e451a6b" +
		"a279bbfa20be98a382d33c2f35d1a16cd62a8be54d562846e11f7ba257e9243cb9d935" +
		"5da1644aa2fbccbd8e10c83cf739082e243aa8c7837fc0d5972df9c353df130383159d" +
		"1e47627f9f69b2ca1945073f24bca68ab06929a802e1fc8e456123253ca2d2171df87b" +
		"3246194954e840d9e7cd37d9f509bca496f79677f348750a35bb739ade38bcde410d54" +
		"bc7572ebf113041d7e170396caa4348439822394bd1747a32ba896f04ca8684ec08f28" +
		"84cffca95f2727532799d2d9f09c822f59c7ade49adc29d243"
	key, _ := new(big.Int).SetString(pHex, 0)

	pms, err := server.premasterSecret()
	assert.NoError(t, err)
	assert.Equal(t, pms, server.PremasterKey)
	assert.Equal(t, pms, key)
}

func TestServerCalculatesProofOfKey(t *testing.T) {
	server, _ := NewDefaultServer()
	server.Secret = big.NewInt(1234567789000000)
	server.ephemeralPrivateKey = big.NewInt(1234577890000000000)
	server.ephemeralSharedKey = big.NewInt(1234577890000000000)
	server.ephemeralPublic()
	server.premasterSecret()

	pHex := "0xbf79e5d42a00bd22b46c4c5792c553697128247ebf13a4487104d3cc470cab73"
	pInt, _ := new(big.Int).SetString(pHex, 0)

	clientProof := big.NewInt(12000000000)
	p, err := server.serverProof(clientProof, server.ephemeralSharedKey)
	assert.NoError(t, err)
	assert.Equal(t, p, pInt)
}
