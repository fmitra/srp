// Package srp implements the Secure Remote Password Protocol (Version 6a)
package srp

import (
	"crypto"
	rand "crypto/rand"
	"fmt"
	"math/big"
)

// AuthClient is an interface to support client related requests for
// enrollment and authentication.
type AuthClient interface {
	Enroll() (string, string, *big.Int, error)
	Auth() (string, *big.Int)
	ProveIdentity(*big.Int, string) (*big.Int, error)
}

// AuthServer is an interface to support client request validation.
type AuthServer interface {
	ProcessEnroll(u, s string, v *big.Int) bool
	ProcessAuth(u, sa string, A, v *big.Int) (*big.Int, string, error)
	ProcessProof(cp *big.Int) (*big.Int, error)
}

// SRP represents the main parameters used in calculating a
// server/client shared key.
//
// The srp/client and srp/server packages extend SRP from a client
// and server use-case perspective.
type SRP struct {
	// N is a large prime, referred to in RFC 5054 as N.
	N *big.Int
	// G is a primitive root of N, referred to in RFC 5054 as g.
	G *big.Int
	// K is a multiplier param, referred to in RFC 5054 as k.
	k *big.Int
	// U is a scrambling param, referred to in RFC 5054 as u.
	u *big.Int
	// H is a cryptographic hash. RFC 5054 defaults to SHA1.
	H crypto.Hash
	// I is a username, referred to in RFC 5054 as I.
	I string
	// S is a user's salt referred to in RFC 5054 as s.
	S string
	// Long term secret, RFC 5054 refers to this value as x
	// for the client and v for the server.
	Secret       *big.Int
	PremasterKey *big.Int
	// Ephemeral private key, RFC 5054 refers to this value as
	// a for the client and b for the server.
	ephemeralPrivateKey *big.Int
	// Ephemeral public key, RFC 5054 refers to this value as A
	// for the client and B for the server.
	ephemeralPublicKey *big.Int
	// Ephemeral shared secret, it acompanies EphemeralPublicKey
	// and together make up A/B.
	ephemeralSharedKey *big.Int
}

// ephemeralPrivate returns RFC 5054 `a` or `b` (client/server ephemeral secret)
// RFC 5054 2.5.3 recommends this number is 32 bytes or greater, so we default
// to 64.
func (s *SRP) ephemeralPrivate() *big.Int {
	byteSize := 64
	bytes := make([]byte, byteSize)
	rand.Read(bytes)
	ephemeralPrivateKey := &big.Int{}
	ephemeralPrivateKey.SetBytes(bytes)
	s.ephemeralPrivateKey = ephemeralPrivateKey
	return s.ephemeralPrivateKey
}

// multiplierParm returns a multipler paramenter K
// RFC 5054 2.5.3 Defines K as SHA1(N | G)
func (s *SRP) multiplierParam() (*big.Int, error) {
	if s.N == nil || s.G == nil {
		return nil, ErrNoGroupParams
	}

	if s.H == crypto.Hash(0) {
		return nil, ErrNoHash
	}

	h := s.H.New()
	h.Write(s.N.Bytes())
	h.Write(s.G.Bytes())

	k := &big.Int{}
	s.k = k.SetBytes(h.Sum(nil))
	return s.k, nil
}

// scramblingParam returns a scrambling parameter U.
// RFC 5054 2.5.3 Defines U as SHA1(A | B)
func (s *SRP) scramblingParam(a, b *big.Int) *big.Int {
	h := s.H.New()
	h.Write(b.Bytes())
	h.Write(a.Bytes())

	u := &big.Int{}
	s.u = u.SetBytes(h.Sum(nil))
	return s.u
}

// serverProof creates hash to prove prior calculation of the premaster secret.
// Server calculation of proof requires the SRP Client's proof of key (m) as
// a prerequisite. On receipt of the SRP Server proof, the client must run the
// same calculation to confirm it can replicate the proof.
// RFC 2945 Defines the proof as H(A, client-proof, H(premaster-secret))
func (s *SRP) serverProof(m, a *big.Int) (*big.Int, error) {
	if s.PremasterKey == nil {
		return nil, ErrNoPremasterKey
	}

	if m == nil || m == big.NewInt(0) {
		return nil, ErrBadClientProof
	}

	proof := s.H.New()
	pHash := s.H.New()
	proofInt := &big.Int{}

	pHash.Write(s.PremasterKey.Bytes())
	proof.Write(a.Bytes())
	proof.Write(m.Bytes())
	proof.Write(pHash.Sum(nil))

	proofInt.SetBytes(proof.Sum(nil))
	return proofInt, nil
}

// clientProof creates hash to prove prior calculation of the premaster secret.
// Client must send proof of key prior to the Server as client proof is used
// in the Server's own proof of key. On receipt of the SRP Client proof, the server
// must run the same calculation to confirm it can replicate the proof.
// RFC 2945 Defines the proof as H(H(N) XOR H(g), H(I), s, A, B, H(premaster-secret))
func (s *SRP) clientProof(a, b *big.Int) (*big.Int, error) {
	if s.PremasterKey == nil {
		return nil, ErrNoPremasterKey
	}

	// Client proof of key
	proof := s.H.New()
	// Inner hashes for proof of key
	nHash := s.H.New()
	gHash := s.H.New()
	uHash := s.H.New()
	pHash := s.H.New()

	nHash.Write(s.N.Bytes())
	gHash.Write(s.G.Bytes())

	xor := &big.Int{}
	nHashI := &big.Int{}
	gHashI := &big.Int{}
	nHashI.SetBytes(nHash.Sum(nil))
	gHashI.SetBytes(gHash.Sum(nil))
	xor.Xor(nHashI, gHashI)

	uHash.Write([]byte(s.I))
	pHash.Write(s.PremasterKey.Bytes())

	proof.Write(xor.Bytes())
	proof.Write(uHash.Sum(nil))
	proof.Write([]byte(s.S))
	proof.Write(a.Bytes())
	proof.Write(b.Bytes())
	proof.Write(pHash.Sum(nil))

	proofInt := &big.Int{}
	proofInt.SetBytes(proof.Sum(nil))
	return proofInt, nil
}

// NewSRP returns an SRP environment with configurable hashing function
// and group parameters.
func NewSRP(h crypto.Hash, g *Group) (*SRP, error) {
	n, err := g.CalcN()
	if err != nil {
		return &SRP{}, fmt.Errorf("%s - %s", ErrNoGroupParams, err)
	}

	srp := &SRP{
		H: h,
		G: g.G,
		N: n,
	}

	srp.ephemeralPrivate()

	_, err = srp.multiplierParam()
	if err != nil {
		return &SRP{}, err
	}

	return srp, nil
}

// NewDefaultSRP returns an SRP environment preconfigured for parameters
// Group4096 and SHA256 for a hashing function.
func NewDefaultSRP() (*SRP, error) {
	g, _ := NewGroup(Group4096)
	return NewSRP(crypto.SHA256, g)
}
