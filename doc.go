/*
Package srp implements the Secure Remote Password Protocol (Version 6a)

SRP-6a is a password-authenticated key agreement (PAKE) protocol where a client/user
demonstrates to a server that they know the password without sending the password
or any other information from which a password can be inferred.

The goal of SRP is for both client and server to generate the same session key (K),
which they prove by sharing a hash (M) of several known parameters and attempting to
replicate the value. Validating the value of M proves that the server and client
are each aware of their long term secrets x (client secret) and v (server secret)

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

	N, g: Group parameters (a large prime N, and a primitive root of N)
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

Calculation of keys:

	1. C calculates Premaster Secret cPS = ((B - k (g^x)) ^ (a + ux)) % N
	2. S calculates Premaster Secret sPS = ((A * v^u) ^ b) % N
	3. C calculates M1 = H(H(N) XOR H(g), H(I), s, A, B, H(cPS))
	4. S calculates M2 = H(A, M1, H(sPS))

Confirmation of proof:

	1. C submits M1 and S confirms M1
	2. S submits M2 and C onfirms M2

Full authentication is as follows:

	Client                        Server
	----------                    ----------
	Calculate a, A
	I, A              --------->
								  Calculate b, B
					  <---------  B, s
	Calculate K, M1
	M1                --------->  Calculate K, M2
								  Confirm M2
					  <---------  M2
	Confirm M2

*/
package srp
