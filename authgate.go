// Package authgate defines the domain model for user authentication.
package authgate

import (
	"context"
	"time"
)

// User represents a user who is either authenticated or unauthenticated
// with the service.
type User struct {
	ID                  string
	Username            string
	Password            string
	TFASecret           string
	// AuthenticationLevel defines a stage of authentication a User requires to be considered
	// authenticated. It may be: password, totp, u2f
	AuthenticationLevel string
	UpdatedAt           time.Time
	CreatedAt           time.Time
}

// U2FKey represents a U2F key associated with a user account.
type U2FKey struct {
	UserID    string
	PublicKey string
	KeyHandle string
	AppID     string
}

// U2FKeyStorage represents a local storage for U2FKey.
type U2FKeyStorage interface {
	ByUser(ctx context.Context, userID string) (*User, error)
}

// UserStorage represents a local storage for Users.
type UserStorage interface {
	Create(ctx context.Context, user *User) error
	Get(ctx contxt.Context, attribute string, value string) (*User, error)
}

// AuthService represents a service that handles validation of User credentials.
type AuthService interface {
	ValidatePassword(ctx context.Context, username string, password string) (bool, error)
	ValidateTOTP(ctx context.Context, username string, totp string) (bool, error)
	ValidateFIDO(ctx context.Context, username string, u2fSignRequest stirng) (bool, error)
}

// LoginService represents an API to authenticate an existing User.
type LoginService interface {
	JWTToken(ctx context.Context, user *User) (string, error)
}

// SignUpService represents an API to create new Users.
type SignUpService interface {
	CreateUser(ctx context.Context, user *User) error
}
