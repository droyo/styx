package styxproto

import "unicode/utf8"

// verification functions for the various fields in a 9P message

func validType(t uint8) bool {
	return int(t) < len(msgParseLUT) && msgParseLUT[t] != nil
}

// check that a message is as big or as small as
// it needs to be, given what we know about its
// type.
func verifySizeAndType(m msg) error {
	t, n := m.Type(), m.Len()
	if !validType(t) {
		return errInvalidMsgType
	}
	if min := int64(minSizeLUT[t]); n < min {
		return errTooSmall
	}
	if max := int64(maxSizeLUT[t]); n > max {
		// Some servers/clients do not seem to "shrink-wrap"
		// messages -- there can be empty space after the message
		// data
		//return errTooBig
	}
	return nil
}

// Verify a string. Strings must be valid UTF8 sequences.
func verifyString(data []byte) error {
	if !utf8.Valid(data) {
		return errInvalidUTF8
	}
	return nil
}

// Verify an element in a file system path. It must be a valid
// UTF8 sequence and cannot contain the '/' character.
func verifyPathElem(data []byte) error {
	for _, v := range data {
		if v == '/' {
			return errContainsSlash
		}
	}
	return verifyString(data)
}

// Verify the first variable-length field. If succesful, returns a nil
// error and the remaining data after the field.  If fill is true, the
// field (including 2-byte size) is expected to fill data, minus
// padding.
func verifyField(data []byte, fill bool, padding int) ([]byte, []byte, error) {
	size := int(guint16(data[:2]))
	if size+2 > len(data)-padding {
		return nil, nil, errOverSize
	} else if fill && size+2 < len(data)-padding {
		// Some clients/servers leave empty space at the end
		// of their messages, and the docs are silent on the matter.
		//return nil, nil, errUnderSize
	}
	field := data[2:]
	return field[:size], field[size:], nil
}
