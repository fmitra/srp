package srp

import (
	"crypto"
	"errors"
	"math/big"
)

// Server represents an SRP Server. Server validates a Client's enrollment
// and authentication.
type Server struct {
	SRP
}

// ProcessEnroll acknowledges an enrollment payload from an SRP Client.
// It returns true if valid credentials have been submitted.
func (s *Server) ProcessEnroll(u, sa string, v *big.Int) bool {
	if u == "" || sa == "" || v == nil {
		return false
	}

	s.I = u
	s.S = sa
	s.Secret = v

	return true
}

// ProcessAuth ackwnowledges an authentication request from a
// pre-enrolled SRP Client. Credentials should be received from the SRP client.
// Salt and verifier should be retrieved from some secure persisted storage
// prior to this call. Retreival of cr2 is outside the scope of this package.
func (s *Server) ProcessAuth(u, sa string, A, v *big.Int) (*big.Int, string, error) {
	s.I = u
	s.ephemeralSharedKey = A
	s.S = sa
	s.Secret = v

	pk := big.Int{}
	if pk.Mod(A, s.N); pk.Sign() == 0 {
		return &big.Int{}, "", errors.New("client public key % N cannot be 0")
	}

	_, err := s.ephemeralPublic()
	if err != nil {
		return &big.Int{}, "", err
	}

	_, err = s.premasterSecret()
	if err != nil {
		return &big.Int{}, "", err
	}

	return s.ephemeralPublicKey, s.S, nil
}

// ProcessProof receives and validates proof from an SRP Client.
func (s *Server) ProcessProof(cp *big.Int) (*big.Int, error) {
	p, err := s.serverProof(cp, s.ephemeralSharedKey)
	if err != nil {
		return &big.Int{}, err
	}

	if !s.IsProofValid(cp) {
		return &big.Int{}, errors.New("invalid client proof received")
	}

	return p, nil
}

// IsProofValid validates a SRP Client's proof of session key.
func (s *Server) IsProofValid(i *big.Int) bool {
	proof, _ := s.clientProof(s.ephemeralSharedKey, s.ephemeralPublicKey)
	isValid := proof.Cmp(i) == 0
	return isValid
}

// EphemeralPublic calculate's the server's ephemeral public key B.
// RFC 5054 Defines B as (k*v + g^b) % N
func (s *Server) ephemeralPublic() (*big.Int, error) {
	if s.G == nil || s.N == nil {
		return nil, errors.New("srp.Group not initialized")
	}

	// k*v
	kv := &big.Int{}
	// g^b
	gB := &big.Int{}
	B := &big.Int{}

	kv.Mul(s.Secret, s.k)
	gB.Exp(s.G, s.ephemeralPrivateKey, s.N)

	kv.Mod(kv, s.N)
	B.Add(kv, gB)
	B.Mod(B, s.N)

	s.ephemeralPublicKey = B
	return B, nil
}

// premasterSecret creates the premaster secret key. If either client/server pair
// fails to calculate the premaster secret, final messages will fail to decrypt.
// RFC 5054 2.6 Defines the server secret as (A * v^u) ^ b % N
func (s *Server) premasterSecret() (*big.Int, error) {
	if s.G == nil || s.N == nil {
		return nil, errors.New("srp.Group not initialized")
	}

	if s.ephemeralPublicKey == nil || s.ephemeralSharedKey == nil {
		return nil, errors.New("shared keys A/B not calculated")
	}

	ownKey := big.Int{}
	if ownKey.Mod(s.ephemeralPublicKey, s.N); ownKey.Sign() == 0 {
		return nil, errors.New("generated invalid public key, key % N cannot be 0")
	}

	otherKey := big.Int{}
	if otherKey.Mod(s.ephemeralSharedKey, s.N); otherKey.Sign() == 0 {
		return nil, errors.New("received invalid public key, key % N cannot be 0")
	}

	s.scramblingParam(s.ephemeralSharedKey, s.ephemeralPublicKey)

	// (A * v^u)
	vU := &big.Int{}
	vU.Exp(s.Secret, s.u, s.N)
	vU.Mul(vU, s.ephemeralSharedKey)

	// vU^b % N
	k := &big.Int{}
	k.Exp(vU, s.ephemeralPrivateKey, s.N)
	s.PremasterKey = k

	return s.PremasterKey, nil
}

// NewServer returns an SRP Server with user defined hash and group.
func NewServer(h crypto.Hash, g *Group) (*Server, error) {
	srp, err := NewSRP(h, g)
	if err != nil {
		return &Server{}, err
	}
	server := &Server{
		SRP: *srp,
	}
	return server, nil
}

// NewDefaultServer returns an SRP server preconfigured for parameters
// Group4096 and SHA256 hashing function.
func NewDefaultServer() (*Server, error) {
	g, _ := NewGroup(Group4096)
	return NewServer(crypto.SHA256, g)
}
