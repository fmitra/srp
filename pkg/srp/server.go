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

// CalculateSessionKey creates a shared session key. RFC 5054 refers to this
// value as K1 and K2 for client/server.
func (c *Server) CalculateSessionKey() error {
	// TODO
	return nil
}

// CalculateProofOfKey creates hash to prove prior calculation of the shared
// session key.
func (c *Server) CalculateProofOfKey() error {
	// TODO
	return nil
}

// ValidateProof validates a SRP Client's proof of session key.
func (c *Server) ValidateProof() bool {
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
