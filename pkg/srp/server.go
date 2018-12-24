package srp

import (
	"errors"
	"math/big"
)

// Server represents an SRP Server. Server validates a Client's enrollment
// and authentication.
type Server struct {
	SRP
}

// EphemeralPublic calculate's the server's ephemeral public key B.
// RFC 5054 Defines B as (k*v + g^b) % N
func (s *Server) EphemeralPublic() (*big.Int, error) {
	if s.G == nil || s.N == nil {
		return nil, errors.New("srp.Group not initialized")
	}

	// k*v
	kv := &big.Int{}
	// g^b
	gB := &big.Int{}
	B := &big.Int{}

	kv.Mul(s.Secret, s.K)
	gB.Exp(s.G, s.EphemeralPrivateKey, s.N)

	kv.Mod(kv, s.N)
	B.Add(kv, gB)
	B.Mod(B, s.N)

	s.EphemeralPublicKey = B
	return B, nil
}

// PremasterSecret creates the premaster secret key. If either client/server pair
// fails to calculate the premaster secret, final messages will fail to decrypt.
// RFC 5054 2.6 Defines the server secret as (A * v^u) ^ b % N
func (s *Server) PremasterSecret() (*big.Int, error) {
	if s.G == nil || s.N == nil {
		return nil, errors.New("srp.Group not initialized")
	}

	if s.EphemeralPublicKey == nil || s.EphemeralSharedKey == nil {
		return nil, errors.New("shared keys A/B not calculated")
	}

	ownKey := big.Int{}
	if ownKey.Mod(s.EphemeralPublicKey, s.N); ownKey.Sign() == 0 {
		return nil, errors.New("generated invalid public key, key % N cannot be 0")
	}

	otherKey := big.Int{}
	if otherKey.Mod(s.EphemeralSharedKey, s.N); otherKey.Sign() == 0 {
		return nil, errors.New("received invalid public key, key % N cannot be 0")
	}

	s.scramblingParam()

	// (A * v^u)
	vU := &big.Int{}
	vU.Exp(s.Secret, s.U, s.N)
	vU.Mul(vU, s.EphemeralSharedKey)

	// vU^b % N
	k := &big.Int{}
	k.Exp(vU, s.EphemeralPrivateKey, s.N)
	s.PremasterKey = k

	return s.PremasterKey, nil
}

// scramblingParam returns a scrambling paramter U.
// RFC 5054 2.5.3 Defines U as SHA1(A | B)
func (s *Server) scramblingParam() *big.Int {
	h := s.H.New()
	h.Write(s.EphemeralPublicKey.Bytes())
	h.Write(s.EphemeralSharedKey.Bytes())

	U := &big.Int{}
	s.U = U.SetBytes(h.Sum(nil))
	return s.U
}

// ProofOfKey creates hash to prove prior calculation of the premaster secret.
// RFC 2945 Defines the proof as H(A, client-proof, H(premaster-secret))
func (s *Server) ProofOfKey() (*big.Int, error) {
	// TODO
	return nil, nil
}

// ValidateProof validates a SRP Client's proof of session key.
func (s *Server) IsProofValid() bool {
	// TODO
	return true
}

// ReceiveEnrollmentRequest acknowledges an enrollment payload from an SRP Client.
func (s *Server) ReceiveEnrollmentRequest() {
	// TODO
}

// ReceiveAuthenticationRequest ackwnowledges an authentication request from a
// pre-enrolled SRP Client.
func (s *Server) ReceiveAuthenticationRequest() {
	// TODO
}

// NewDefaultServer returns an SRP server preconfigured for parameters
// Group4096 and SHA256 hashing function.
func NewDefaultServer() (*Server, error) {
	srp, err := NewDefaultSRP()
	if err != nil {
		return &Server{}, err
	}
	server := &Server{
		SRP: *srp,
	}
	return server, nil
}
