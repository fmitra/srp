package srp

import (
	"crypto"
	"fmt"
)

func ExampleSRP_default() {
	c, _ := NewDefaultClient("jane_doe_123", "my-password")
	s, _ := NewDefaultServer()

	// Client salt and verifier and returns public key.
	_, salt, verifier, _ := c.Enroll()
	username, pubKeyA := c.Auth()

	// Server processes auth credentials
	pubKeyB, saltB, _ := s.ProcessAuth(username, salt, pubKeyA, verifier)

	clientProof, err := c.ProveIdentity(pubKeyB, saltB)
	fmt.Println(err)

	serverProof, err := s.ProcessProof(clientProof)
	fmt.Println(err)

	ok := c.IsProofValid(serverProof)
	fmt.Println(ok)
	// Output:
	// <nil>
	// <nil>
	// true
}

func ExampleSRP_specifyGroupAndHash() {
	g, _ := NewGroup(Group8192)
	c, _ := NewClient(crypto.SHA512, g, "jane_doe_123", "my-password")
	s, _ := NewServer(crypto.SHA512, g)

	// Client salt and verifier and returns public key.
	_, salt, verifier, _ := c.Enroll()
	username, pubKeyA := c.Auth()

	// Server processes auth credentials
	pubKeyB, saltB, _ := s.ProcessAuth(username, salt, pubKeyA, verifier)

	clientProof, err := c.ProveIdentity(pubKeyB, saltB)
	fmt.Println(err)

	serverProof, err := s.ProcessProof(clientProof)
	fmt.Println(err)

	ok := c.IsProofValid(serverProof)
	fmt.Println(ok)
	// Output:
	// <nil>
	// <nil>
	// true
}
