package util

// IsTempErr returns true if an error exports a
// Temporary() method that returns true.
func IsTempErr(err error) bool {
	type t interface {
		Temporary() bool
	}
	if err, ok := err.(t); ok {
		return err.Temporary()
	}
	return false
}
