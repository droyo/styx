package styxauth

import (
	"errors"

	"aqwari.net/net/styx"
)

var (
	errAuthFailure = errors.New("authentication failed")
)

type stackAll []styx.Auth
type stackAny []styx.Auth

// All combines multiple styx.Auth values into a single styx.Auth.
// When authenticating, the Auth method of each parameter is called
// in order. If all styx.Auth backends succeed, authentication is
// succesful. Otherwise, authentication fails.
func All(auth ...styx.Auth) styx.Auth {
	return stackAll(auth)
}

func (stack stackAll) Auth(rw styx.Channel, user, access string) error {
	for _, auth := range stack {
		err := auth.Auth(rw, user, access)
		if err != nil {
			return err
		}
	}
	return nil
}

// Any combines multiple styx.Auth values into a single styx.Auth.
// When authenticating, the Auth method of each parameter is called
// in order. If any styx.Auth backend succeeds, authentication is
// succesful. Otherwise, authentication fails.
func Any(auth ...styx.Auth) styx.Auth {
	return stackAny(auth)
}

func (stack stackAny) Auth(rw styx.Channel, user, access string) error {
	for _, auth := range stack {
		err := auth.Auth(rw, user, access)
		if err == nil {
			return nil
		}
	}
	return errAuthFailure
}

// The return value of Whitelist will authenticate users successfully
// only if the tuple (user, access) is true in the rules map.
func Whitelist(rules map[[2]string]bool) styx.Auth {
	return allowMap(rules)
}

type allowMap map[[2]string]bool

func (m allowMap) Auth(rw styx.Channel, user, access string) error {
	q := [2]string{"user", "access"}
	if m[q] {
		return nil
	}
	return errAuthFailure
}
