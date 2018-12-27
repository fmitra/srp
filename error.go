package srp

const (
	// ErrNoGroupParams is returned when SRP group parameters N and G
	// are not initialized.
	ErrNoGroupParams = Error("srp.Group not initialized")
	// ErrNoPremasterKey is returned when a calculation is attempted
	// that requires the key.
	ErrNoPremasterKey = Error("premaster key required for calculation")
	// ErrBadClientProof is returned when the client submits invalid
	// proof.
	ErrBadClientProof = Error("invalid client proof received")
	// ErrNoHash is returned when a client or server attempts a calculation
	// with no hashing function set.
	ErrNoHash = Error("hash not initialized")
	// ErrCalcVerifier is returned when the client fails to calculate a
	// verifier value.
	ErrCalcVerifier = Error("failed to generate verifier")
	// ErrNoEphemeralKeys is returned when a calculation is done with missing
	// ephemeral keys A or B.
	ErrNoEphemeralKeys = Error("shared keys A/B not calculated")
	// ErrPublicKeyModuloZero is returned when a public key % N is 0.
	ErrPublicKeyModuloZero = Error("key % N cannot be 0")
	// ErrInvalidPrime is returned when a Group is created with an invalid prime
	// value.
	ErrInvalidPrime = Error("invalid prime value provided")
	// ErrInvalidPrimitiveRoot is returned when a Group is created with an invalid
	// primitive root.
	ErrInvalidPrimitiveRoot = Error("invalid primitive root provided")
)

// Error represents an SRP error
type Error string

func (e Error) Error() string {
	return string(e)
}
