/*
Package srp implements the Secure Remote Password Protocol (Version 6a)

SRP-6a is a password-authenticated key agreement (PAKE) protocol where a client/user
demonstrates to a server that they know the password without sending the password
or any other information from which a password can be inferred.

The goal of SRP is for both client and server to generate the same session key (K),
which they prove by generating a matching hash (M). A matching value of M confirms
the server and client are each aware of their long term secrets x (client secret)
and v (server secret).

RFC 2945: The SRP Authentication and Key Exchange System
https://tools.ietf.org/html/rfc2945

RFC 5054:  Using the Secure Remote Password (SRP) Protocol for TLS Authentication
https://tools.ietf.org/html/rfc5054

Operations

^: Denotes exponentiation operation
|: Denotes concatenation
%: Denotes modulo operation
H(): Hash Function (eg. SHA256)

Roles

C: Client/User attempting authentication
S: Server authenticating the client

Key

N, g: Group parameters (a large prime N, and a primative root of N)
I: An identifying username belonging to C
p: A password belonging to C
s: A salt belonging to C
x: Private key derived from p and s; x = H(s|H(I|":"|p))
k: A multiplier parameter derived by both C and S; k = H(N, g)
u: A scrambling parameter derived by both C and S; u = H(A, B)
v: The password verifier belonging to S and derived from x; v = g^x % N
a,A: Secret/Public ephemeral values belonging to C
b,B: Secret/Public ephemeral values belonging to S
M: Calculated proof of key generation
K: Calculated shared key

Scenario: Client (C) establishes a password with Server (S)

1. C selects a password p, salt s and computes x = H(s|H(I|":"|p)), v = g^x % N
2. C submits v (password verifier), s, I (username) to S
3. S stores v and s, indexed by I

Scenario: Client (C) demonstrates proof of password to Server (S)

Initial hash of shared public keys

1. C generates secret/public ephemeral values a/A where A = g^a % N
2. C submits I and A to S
3. S generates secret/public ephemeral values b/B where B = (kv + g^b) % N
4. S submits B and s to C
5. C and S both calculate u = H(A, B)

Calculation of keys

1. C calculates Premaster Secret cPS = ((B - k (g^x)) ^ (a + ux)) % N
2. S calculates Premaster Secret sPS = ((A * v^u) ^ b) % N
3. C calculates M1 = H(H(N) XOR H(g), H(I), s, A, B, H(cPS))
4. S calculates M2 = H(A, M1, H(sPS))

Confirmation of proof

1. C submits M1 and S confirms M1 == M2
2. S submits M2 and C onfirms M1 == M2

Client                        Server
----------                    ----------
Calculate a, A
I, A              --------->
                              Calculate b, B
                  <---------  B, s
Calculate K1, M1
M1                --------->  Calculate K2, M2
                              Confirm M2 == M1
                  <---------  M1
Confirm M2 == M1
*/
package srp

import (
	"crypto"
	rand "crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

// SRPCore is the core interface SRP clients and servers
// must implement.
type SRPCore interface {
	EphemeralPrivate() *big.Int
	EphemeralPublic() (*big.Int, error)
	MultiplerParam() (*big.Int, error)
	PremasterSecret() (*big.Int, error)
	ProofOfKey() (*big.Int, error)
	IsProofValid() bool
	scramblingParam() *big.Int
}

// SRPClient is an interface to support client related requests for
// enrollment and authentication.
type SRPClient interface {
	SRPCore
	LongTermSecret() (*big.Int, error)
	Verifier() (*big.Int, error)
	Salt() string
	RequestEnrollment()
	RequestAuthentication()
}

// SRPServer is an interface to support client request validation.
type SRPServer interface {
	SRPCore
	ReceiveEnrollmentRequest()
	ReceiveAuthenticationRequest()
}

// SRP represents the main parameters used in calculating a
// server/client shared key.
//
// The srp/client and srp/server packages extend SRP from a client
// and server use-case perspective.
type SRP struct {
	// N is a large prime, referred to in RFC 5054 as N.
	N *big.Int
	// G is a primative root of N, referred to in RFC 5054 as g.
	G *big.Int
	// K is a multiplier param, referred to in RFC 5054 as k.
	K *big.Int
	// U is a scrambling param, referred to in RFC 5054 as u.
	U *big.Int
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
	EphemeralPrivateKey *big.Int
	// Ephemeral public key, RFC 5054 refers to this value as A
	// for the client and B for the server.
	EphemeralPublicKey *big.Int
	// Ephemeral shared secret, it acompanies EphemeralPublicKey
	// and together make up A/B.
	EphemeralSharedKey *big.Int
}

// EphemeralPrivate returns RFC 5054 `a` or `b` (client/server ephemeral secret)
// RFC 5054 2.5.3 recommends this number is 32 bytes or greater, so we default
// to 64.
func (s *SRP) EphemeralPrivate() *big.Int {
	byteSize := 64
	bytes := make([]byte, byteSize)
	rand.Read(bytes)
	ephemeralPrivateKey := &big.Int{}
	ephemeralPrivateKey.SetBytes(bytes)
	s.EphemeralPrivateKey = ephemeralPrivateKey
	return s.EphemeralPrivateKey
}

// MultiplierParm returns a multipler paramenter K
// RFC 5054 2.5.3 Defines K as SHA1(N | G)
func (s *SRP) MultiplierParam() (*big.Int, error) {
	if s.N == nil {
		return nil, errors.New("prime value not initialized")
	}

	if s.G == nil {
		return nil, errors.New("primative root not initialized")
	}

	if s.H == crypto.Hash(0) {
		return nil, errors.New("hash not initialized")
	}

	h := s.H.New()
	h.Write(s.N.Bytes())
	h.Write(s.G.Bytes())

	K := &big.Int{}
	s.K = K.SetBytes(h.Sum(nil))
	return s.K, nil
}

// NewSRP returns an SRP environment with configurable hashing function
// and group parameters.
func NewSRP(h crypto.Hash, g *Group) (*SRP, error) {
	N, err := g.CalcN()
	if err != nil {
		errMsg := fmt.Sprintf("invalid srp.Group provided %s", err)
		return &SRP{}, errors.New(errMsg)
	}

	srp := &SRP{
		H: h,
		G: g.G,
		N: N,
	}

	srp.EphemeralPrivate()

	_, err = srp.MultiplierParam()
	if err != nil {
		return &SRP{}, err
	}

	return srp, nil
}

// NewDefaultSRP returns an SRP environment preconfigured for parameters
// Group4096 and SHA256 for a hashing function.
func NewDefaultSRP() (*SRP, error) {
	g, _ := NewGroup(Group4096)
	srp, err := NewSRP(crypto.SHA256, g)
	if err != nil {
		return &SRP{}, err
	}
	return srp, nil
}
