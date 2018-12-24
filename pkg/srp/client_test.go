package srp

import (
	"crypto"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSecretRequiresInitializedClient(t *testing.T) {
	c := &Client{}
	_, err := c.LongTermSecret()
	assert.EqualError(t, err, "salt, username, and password must be initialized")

	c = &Client{
		SRP: SRP{
			S: "random-salt",
		},
	}
	_, err = c.LongTermSecret()
	assert.EqualError(t, err, "salt, username, and password must be initialized")

	c = &Client{
		Username: "username",
		SRP: SRP{
			S: "random-salt",
		},
	}
	_, err = c.LongTermSecret()
	assert.EqualError(t, err, "salt, username, and password must be initialized")

	c = &Client{
		Password: "password",
		SRP: SRP{
			S: "random-salt",
		},
	}
	_, err = c.LongTermSecret()
	assert.EqualError(t, err, "salt, username, and password must be initialized")
}

func TestCreatesSecret(t *testing.T) {
	c := &Client{
		Password: "password",
		Username: "username",
		SRP: SRP{
			S:      "random-salt",
			Secret: big.NewInt(2),
		},
	}
	X, err := c.LongTermSecret()
	assert.NoError(t, err)
	assert.Equal(t, X, big.NewInt(2))

	c = &Client{
		Password: "password",
		Username: "username",
		SRP: SRP{
			H: crypto.SHA256,
			S: "random-salt",
		},
	}
	X, err = c.LongTermSecret()
	XAsHex := "0xd43b21c189d67f332803c5eb1abd3b5aa25a2bef6bde7c95bcf53b9e5e9055b7"
	secret, _ := new(big.Int).SetString(XAsHex, 0)

	assert.NoError(t, err)
	assert.Equal(t, X, secret)
	assert.Equal(t, c.Secret, X)
}

func TestItCreatesASalt(t *testing.T) {
	c := &Client{}
	assert.True(t, len(c.Salt()) >= 15)

	c = &Client{
		SRP: SRP{
			S: "random-salt",
		},
	}
	assert.Equal(t, c.Salt(), "random-salt")
}

func TestItCreatesAVerifier(t *testing.T) {
	group, _ := NewGroup(Group4096)
	N, _ := group.CalcN()
	c := &Client{
		Username: "username",
		Password: "password",
		SRP: SRP{
			S: "random-salt",
			H: crypto.SHA256,
			G: group.G,
			N: N,
		},
	}
	V, err := c.Verifier()
	VAsHex := "0x918426882c00a88dfb3850d8eafe06ca4d60f4b20f" +
		"20f4fa8754d110fb61d496206bf360d4f4c3a26851ee35f8b7" +
		"d918e97c1dcc4e5a5f04d613521e8c3fee454473e063c82168" +
		"6cbcbdbd2257069a8a57289ed6215dc94ee779ca151392eafd" +
		"62cc5a445e90c880899a3aec5ac12d48f160b5d6dcde6e4d5d" +
		"49e1bbbb3960562b46c038f05a7b30d302c1c1bf39ea5a7843" +
		"5198fb11760eca0885587bde7f64a0330b24850d115624d258" +
		"2212cdca7a79c742f7008bd3c99d96b3a1a5e50864db3f890a" +
		"3757d84fa75e877bd9ccc0abc1cd9e943f5b868f0a41896578" +
		"1c49e0e71e7e96cf6d4a98a6b41c3fa06c1a05fb370e6fa701" +
		"cded7fe3551b6c9a8d3345990db238fba6000f261eebc7fd15" +
		"9f80c1e7b8074ba7c389c697cad617c6e9c12bffc1c73a9692" +
		"d44a55431da6ae34252254117d97188696c83b6e25b9d88c77" +
		"e0294cfae9348d6b47d4b5863f44a4626cff7b76f2ffd720b3" +
		"67e003503fbde6becfe20092a901a4087af56b5a88ec9dde99" +
		"98b39c54e6363a5caa9a6bb9b9f52e0b4db8f2555fc6777217" +
		"59da8a2e2d920187282ab7679fe3aebc32f2f80cb4f81840fb" +
		"fa53171707ad1a8bb72426310bd8adc8738e33328ad6bff223" +
		"59660e2f9deff420b37c208e6bcc1e59415aec492c21d8f656" +
		"9c63484c44882c63bfaa2bedb0b0417cf8807eee9be7ccad0f" +
		"fe8de6f8b289c28b80af9d3fb12a96d0"
	assert.NoError(t, err)
	v, _ := new(big.Int).SetString(VAsHex, 0)
	assert.Equal(t, V, v)
}

func TestVerifierRequiresInitializedClient(t *testing.T) {
	c := &Client{}
	_, err := c.Verifier()
	assert.EqualError(t, err, "srp.Group not initialized")

	c = &Client{
		SRP: SRP{
			G: big.NewInt(2),
			N: big.NewInt(200),
		},
	}
	_, err = c.Verifier()
	errMsg := "failed to generate verifier - salt, username, " +
		"and password must be initialized"
	assert.EqualError(t, err, errMsg)
}

func TestEphemeralPublicRequiresInitializedClient(t *testing.T) {
	c := &Client{}
	_, err := c.EphemeralPublic()
	assert.EqualError(t, err, "srp.Group not initialized")
}

func TestCreatesEphemeralPublicKeys(t *testing.T) {
	srp, _ := NewDefaultSRP()
	pkHex := "0x1bcef521a3e41d63bace63dd5bb0ab541f5edff754b32235febc41b" +
		"c8098f9a014c21b2042f6f353289bf12117d379250a34cd26ed3d54d6bac30" +
		"1b403adcef7"
	pk, _ := new(big.Int).SetString(pkHex, 0)
	// Overwrite the private key so we have a constant value we can test with
	srp.EphemeralPrivateKey = pk
	c := &Client{SRP: *srp}
	A, err := c.EphemeralPublic()
	assert.NoError(t, err)
	assert.Equal(t, c.EphemeralPublicKey, A)
	pubHex := "0x44d65b44985f3becf21426e118adaaee7847c74caff7a89e1b88cac5" +
		"a5263267561208acbd95f368ce656d5ccde03938cce86cd5fb9efa393c6e89dc" +
		"22b2299758407280ca2278b56478b4e56217db2d669f49f251363faaba0c5f92" +
		"3e2316f85e5b3e4330cd9dc500af61e8ab11ef52d21b9391a61857ca958c8b3f" +
		"77a61d1aa496ebc537193d38c68d2d019fcd1027e04e1745b9d8d4a35d60ef8d" +
		"cfe3d6c26a5017bc3c3c6ff356bb276e0c62d18fde1d10bed40c56a0cef89026" +
		"09ef37482d3387c0c6cb4c15b01b46c960f839e134a29be14e452f5b8204aa3b" +
		"41ef431464d82714f45ff312d8d005a4413bbed1ed989efd6ea473baf0702553" +
		"6f599d3519dde97de1b39f8b666517b54092d2ff8788704e20aab15589c8bf5b" +
		"6e68bb3cf3b2e009899470ea11dfce40453720fdd255690b620cf5b52df34c99" +
		"5e6e64fb2ff80bbff4eaf37a0f3a4535c5c267821a29f919cf06c1c5c8469637" +
		"a69be64be279915a5e4f9fb3db4df625776e39cd1529dc72f2010f14c516cdb2" +
		"e7f2dc8e3ab1f4234e4ad6e8f3c7614b7716404dbda460d68973570578b7ca08" +
		"a0f8c9d312720472e6c89d9dc57aee9809da1338f4c55a898b1948853946e11c" +
		"64aaa5796af920bea159e336d0d071bb1ed1969e9e1b924f54b01b53effef438" +
		"60eb00cd85bc890770bbb09a2c47b735aed65822ccf3806e7c728b7aab6cbd43" +
		"975a359a"
	pub, _ := new(big.Int).SetString(pubHex, 0)
	assert.Equal(t, A, pub)
}

func TestCreatesDefaultClient(t *testing.T) {
	username := "jane"
	password := "janedoe"
	client, err := NewDefaultClient(username, password)
	assert.NoError(t, err)
	assert.Equal(t, client.H, crypto.SHA256)
}

func TestClientCalculatesPremasterSecret(t *testing.T) {
	c, _ := NewDefaultClient("username", "password")
	c.EphemeralPrivateKey = big.NewInt(1234577890000000000)
	c.EphemeralSharedKey = big.NewInt(1234599789000000000)
	c.EphemeralPublicKey = big.NewInt(1234599788000000000)
	c.S = "123459978900000022"
	pHex := "0xac63795cddc845c660a2e65aff784be0173a1397f048b1f88046e37e5d3df" +
		"f9150a990a1ed89b496e219f8fab0c27c873e2c6f96b3d6cdd0800c4554316b9c2e" +
		"1e53c288a96bda1bf5651735f4580c9ef8129bed0344b1f78351852cadb3b12c09a" +
		"ae1b182ec92311447ef8fefb38a8df8ed8d04ace455a31e1eef258b4194f34eaadd" +
		"5b89b91f062c22648e8c4762682e4c159f97b56ec444310ed217fa2c592cfb40d33" +
		"a8dc7c368c31e0713ae99b9afc6cb91997fd14a5c167aaff7930e9e52e4b170a8b5" +
		"1e567d643f6847ee2fe59c4258735550dc6dfbe2ee0b65bdee2aab9c497b64ef899" +
		"71a3e47c5c346834a7ce479e6000707dfd5677f5a566dc1c7fbc30e6a0cac6c730b" +
		"fd84f85aa9421ec96072d2b25193c48e91fa573f7a02975b6eeb01b97b77eeb8599" +
		"374ff174dabdae68cc5a8bc4640f9b5f50c979efb94b4ad9ebd8f743a2b0687ca1e" +
		"b202a2cb1c60267c9970fa718ff1248e7149422a4ac877080c2d6d08b61523d823b" +
		"38e551363f5517b88ac98f92c1ecba51d569b23fb652ed2038114ad983905c3b50d" +
		"f89978938c807e225b5abe0669e8c1f87121dc9d8fbf9285f9a9e98102dea7dbea0" +
		"c4e6deea15e5b4d4d5482a43653e61d299f07a28cdb5a640d6145c45db375cd4d10" +
		"d88f0eedc12d21c7d1f5a65de3fb2f0a819dde954b820912038228bfb222ecb8c27" +
		"46c0e1e47b6695077d3216bc2"
	key, _ := new(big.Int).SetString(pHex, 0)
	pms, err := c.PremasterSecret()
	assert.NoError(t, err)
	assert.Equal(t, pms, c.PremasterKey)
	assert.Equal(t, pms, key)
}

func TestClientPremasterSecretRequiresInitializedServer(t *testing.T) {
	c := &Client{}
	_, err := c.PremasterSecret()
	assert.EqualError(t, err, "srp.Group not initialized")

	c, _ = NewDefaultClient("username", "password")
	_, err = c.PremasterSecret()
	assert.EqualError(t, err, "shared keys A/B not calculated")

	c, _ = NewDefaultClient("username", "password")
	c.EphemeralSharedKey = big.NewInt(20)
	c.EphemeralPublicKey = big.NewInt(21)
	c.N = big.NewInt(2)
	_, err = c.PremasterSecret()
	assert.EqualError(t, err, "received invalid public key, key % N cannot be 0")

	c, _ = NewDefaultClient("username", "password")
	c.EphemeralSharedKey = big.NewInt(20)
	c.EphemeralPublicKey = big.NewInt(21)
	c.N = big.NewInt(3)
	_, err = c.PremasterSecret()
	assert.EqualError(t, err, "generated invalid public key, key % N cannot be 0")
}
