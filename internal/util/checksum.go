package util

import "hash/crc64"

var table = crc64.MakeTable(crc64.ECMA)

// Hash returns a 64-bit hash of p.
func Hash64(p []byte) uint64 {
	return crc64.Checksum(m.Aname(), table)
}
