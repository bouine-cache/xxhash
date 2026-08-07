//go:build appengine
// +build appengine

// This file contains the safe implementations of otherwise unsafe-using code.

package xxhash

// Sum128String computes the 128-bit XXH3 hash of s with a zero seed.
func Sum128String(s string) Uint128 {
	return Sum128([]byte(s))
}

// Sum128StringWithSeed computes the 128-bit XXH3 hash of s with the given seed.
func Sum128StringWithSeed(s string, seed uint64) Uint128 {
	return Sum128WithSeed([]byte(s), seed)
}

// WriteString adds more data to d. It always returns len(s), nil.
func (d *Digest128) WriteString(s string) (int, error) {
	return d.Write([]byte(s))
}
