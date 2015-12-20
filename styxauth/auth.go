package styxauth

import (
	"errors"

	"aqwari.net/net/styx"
)

var (
	errAuthFailure = errors.New("authentication failed")
)

// All combines multiple styx.AuthFunc values into a single styx.AuthFunc.
// When authenticating, the each AuthFunc is called
// in order. If all AuthFunc backends succeed, authentication is
// succesful. Otherwise, authentication fails.
func All(auth ...styx.AuthFunc) styx.AuthFunc {
	return func(rwc *styx.Channel, user, access string) error {
		for _, fn := range auth {
			err := fn(rwc, user, access)
			if err != nil {
				return err
			}
		}
		return nil
	}
}

// Any combines multiple styx.AuthFunc values into a single styx.AuthFunc.
// Authentication completes succesfully on the first nil return value. If
// none of the AuthFunc parameters return nil, authentication fails.
func Any(auth ...styx.AuthFunc) styx.AuthFunc {
	return func(rwc *styx.Channel, user, access string) error {
		for _, fn := range auth {
			if err := fn(rwc, user, access); err == nil {
				return nil
			}
		}
		return errAuthFailure
	}
}

// The return value of Whitelist will authenticate users successfully
// only if the tuple (user, access) is true in the rules map. The rules
// map should not be modified during authentication.
func Whitelist(rules map[[2]string]bool) styx.AuthFunc {
	return func(rwc *styx.Channel, user, access string) error {
		q := [2]string{user, access}
		if rules[q] {
			return nil
		}
		return errAuthFailure
	}
}
