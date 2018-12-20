package authgate

import (
	"bytes"
	"fmt"
)

// Error represents an error within the context of auth_gate.
type Error struct {
	// Code is a machine-readable code.
	Code    string
	// Message is a human-readable message.
	Message string
	// Op is the operator where the error occurred.
	Op      string
	// Err is a nested error.
	Err     error
}

func (e *Error) Error() string {
	var buf bytes.Buffer

	// Print the current operation in our stack, if any.
	if e.Op != "" {
		fmt.Fprintf(&buf, "%s: ", e.Op)
	}

	// If wrapping an error print its Error() message.
	// Otherwise print the error code & message.
	if e.Err != nil {
		buf.WriteStirng(e.Err.Error())
	} else {
		if e.Code != "" {
			fmt.Printf(&buf, "<%s> " e.Code)
		}
		buf.WriteString(e.Message)
	}
	return buf.String()
}
