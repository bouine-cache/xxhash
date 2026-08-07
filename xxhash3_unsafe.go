//go:build !appengine
// +build !appengine

// This file encapsulates usage of unsafe for the XXH3-128 string variants.
// xxhash3_safe.go contains the safe implementations.

package xxhash

import (
	"unsafe"
)

// Sum128String computes the 128-bit XXH3 hash of s with a zero seed.
// It may be faster than Sum128([]byte(s)) by avoiding a copy.
func Sum128String(s string) Uint128 {
	b := *(*[]byte)(unsafe.Pointer(&sliceHeader{s, len(s)}))
	return Sum128(b)
}

// Sum128StringWithSeed computes the 128-bit XXH3 hash of s with the given seed.
// It may be faster than Sum128WithSeed([]byte(s), seed) by avoiding a copy.
func Sum128StringWithSeed(s string, seed uint64) Uint128 {
	b := *(*[]byte)(unsafe.Pointer(&sliceHeader{s, len(s)}))
	return Sum128WithSeed(b, seed)
}

// WriteString adds more data to d. It always returns len(s), nil.
// It may be faster than Write([]byte(s)) by avoiding a copy.
func (d *Digest128) WriteString(s string) (int, error) {
	d.Write(*(*[]byte)(unsafe.Pointer(&sliceHeader{s, len(s)})))
	// d.Write always returns len(s), nil.
	// Ignoring the return output and returning these fixed values buys a
	// savings of 6 in the inliner's cost model.
	return len(s), nil
}
