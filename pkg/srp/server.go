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

	s.ScramblingParam(s.EphemeralSharedKey, s.EphemeralPublicKey)

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

// ValidateProof validates a SRP Client's proof of session key.
func (s *Server) IsProofValid(i *big.Int) bool {
	proof, _ := s.ClientProof(s.EphemeralSharedKey, s.EphemeralPublicKey)
	isValid := proof.Cmp(i) == 0
	return isValid
}

// ReceiveEnrollmentRequest acknowledges an enrollment payload from an SRP Client.
// It returns true if valid credentials have been submitted.
func (s *Server) ReceiveEnrollmentRequest(cr *Credentials) bool {
	if cr.Username == "" || cr.Salt == "" || cr.Verifier == nil {
		return false
	}

	s.I = cr.Username
	s.S = cr.Salt
	s.Secret = cr.Verifier

	return true
}

// ReceiveAuthenticationRequest ackwnowledges an authentication request from a
// pre-enrolled SRP Client. Credentials cr1, should be received from the SRP client.
// cr2 should be retrieved from some secure persisted storage prior to this call.
// Retreival of cr2 is outside the scope of this package.
func (s *Server) ReceiveAuthenticationRequest(cr1, cr2 *Credentials) (*Credentials, error) {
	if cr1.Username != cr2.Username {
		return &Credentials{}, errors.New("invalid username supplied")
	}

	s.I = cr1.Username
	s.EphemeralSharedKey = cr1.EphemeralPublicKey
	s.S = cr2.Salt
	s.Secret = cr2.Verifier

	pk := big.Int{}
	if pk.Mod(cr1.EphemeralPublicKey, s.N); pk.Sign() == 0 {
		return &Credentials{}, errors.New("client public key % N cannot be 0")
	}

	_, err := s.EphemeralPublic()
	if err != nil {
		return &Credentials{}, err
	}

	_, err = s.PremasterSecret()
	if err != nil {
		return &Credentials{}, err
	}

	r := &Credentials{
		EphemeralPublicKey: s.EphemeralPublicKey,
		Salt: s.S,
	}
	return r, nil
}

// ReceiveIdentityProof receives and validates proof from an SRP Client.
func (s *Server) ReceiveIdentityProof(cr *Credentials) (*Credentials, error) {
	p, err := s.ServerProof(cr.Proof, s.EphemeralSharedKey)
	if err != nil {
		return &Credentials{}, err
	}

	if !s.IsProofValid(cr.Proof) {
		return &Credentials{}, errors.New("invalid client proof received")
	}

	r := &Credentials{
		Proof: p,
	}
	return r, nil
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
