// Pakcage SRP implements the Secure Remote Password Protocol (Version 6a)
package srp

/*
SRP-6a is a password-authenticated key agreement (PAKE) protocol where a client/user
demonstrates to a server that they know the password without sending the password
or any other information from which a password can be inferred.

The goal of SRP is for both client and server to generate the same session key (K),
which they prove by generating a match hash (M). Matching value of M confirms the
server and client are each aware of their long term secrets x (client secret) and
v (server secret).

RFC 2945: The SRP Authentication and Key Exchange System
https://tools.ietf.org/html/rfc2945

RFC 5054:  Using the Secure Remote Password (SRP) Protocol for TLS Authentication
https://tools.ietf.org/html/rfc5054

Operations

^: Denotes exponentiation operation
|: Denotes concatenation
H(): Hash Function (eg. SHA256)

Roles

C: Client/User attempting authentication
S: Server authenticating the client

Key

N, g: Group parameters (prime and generator)
I: An identifying username belonging to C
p: A password belonging to C
s: A salt belonging to C
x: Private key derived from p and s; x = H(s|H(I|":"|p))
k: A multiplier parameter derived by both C and S; in SRP-6, k = H(N, g)
v: The password verifier belonging to S and derived from x; v = g^x
a,A: Secret/Public ephemeral values belonging to C
b,B: Secret/Public ephemeral values belonging to S
M: Calculated proof of key generation
K: Calculated shared key

Scenario: Client (C) establishes a password with Server (S)

1. C selects a password p, salt s and computes x = H(s|H(I|":"|p)), v = g^x
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

1. S calculates K2 = H(((A * v^u) ^ b) % N)
2. S calculates M2 = H(K, A, B, I, s, N, g)
3. C calculates x = H(s|H(I|":"|p)) (Secret originally used during registration)
4. C calculates K1 = H(((B - k (g^x)) ^ (a + ux)) % N)
5. C calculates M1 = H(K, A, B, I, s,N, g)

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
type SRP struct {
}
