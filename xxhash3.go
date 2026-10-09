// This file implements the 128-bit variant of XXH3, also known as XXH128,
// as described at https://xxhash.com/.
//
// The implementation is a faithful port of the official xxHash reference
// implementation by Yann Collet, available at
// https://github.com/Cyan4973/xxHash (commit c0b5ea9).
//
// xxHash is a non-cryptographic hash function. It must not be used for
// password hashing, signatures, authentication, or any adversarial
// security boundary.

package xxhash

import (
	"encoding/binary"
	"math/bits"
)

// XXH3 constants.
const (
	xxh3SecretDefaultSize    = 192
	xxh3SecretSizeMin        = 136
	xxh3StripeLen            = 64
	xxh3SecretConsumeRate    = 8
	xxh3AccNb                = xxh3StripeLen / 8 // 8
	xxh3MidsizeMax           = 240
	xxh3MidsizeStartOffset   = 3
	xxh3MidsizeLastOffset    = 17
	xxh3SecretLastaccStart   = 7
	xxh3SecretMergeaccsStart = 11
	xxh3InternalBufferSize   = 256
)

// XXH3 primes (64-bit and 32-bit).
const (
	xxhPrime32_1 uint32 = 0x9E3779B1
	xxhPrime32_2 uint32 = 0x85EBCA77
	xxhPrime32_3 uint32 = 0xC2B2AE3D
	xxhPrime32_4 uint32 = 0x27D4EB2F
	xxhPrime32_5 uint32 = 0x165667B1
	xxhPrime64_1 uint64 = 0x9E3779B185EBCA87
	xxhPrime64_2 uint64 = 0xC2B2AE3D27D4EB4F
	xxhPrime64_3 uint64 = 0x165667B19E3779F9
	xxhPrime64_4 uint64 = 0x85EBCA77C2B2AE63
	xxhPrime64_5 uint64 = 0x27D4EB2F165667C5
	xxhPrimeMx1  uint64 = 0x165667919E3779F9
	xxhPrimeMx2  uint64 = 0x9FB21C651E98DF25
)

// xxh3Secret is the default pseudorandom secret taken directly from FARSH.
// It is used as the default secret for XXH3 when no custom secret is provided.
var xxh3Secret = [xxh3SecretDefaultSize]byte{
	0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad, 0x1c,
	0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f,
	0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21,
	0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26, 0x4c,
	0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb, 0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3,
	0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19, 0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8,
	0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9, 0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d,
	0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31, 0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64,
	0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb,
	0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e,
	0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc, 0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce,
	0x45, 0xcb, 0x3a, 0x8f, 0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e,
}

// Uint128 is a 128-bit unsigned integer representing the result of XXH3-128.
//
// The mathematical value is Hi << 64 | Lo.
type Uint128 struct {
	Hi uint64
	Lo uint64
}

// Bytes returns the canonical 16-byte representation of the 128-bit hash.
//
// The representation is big-endian: the high 64 bits come first, followed by
// the low 64 bits, each in big-endian byte order. This matches the official
// XXH128 canonical representation (XXH128_canonicalFromHash).
func (u Uint128) Bytes() [16]byte {
	var b [16]byte
	binary.BigEndian.PutUint64(b[0:8], u.Hi)
	binary.BigEndian.PutUint64(b[8:16], u.Lo)
	return b
}

// String returns the hexadecimal representation of the 128-bit hash.
//
// The high 64 bits are printed first, followed by the low 64 bits.
// This matches the mathematical value Hi << 64 | Lo.
func (u Uint128) String() string {
	var buf [32]byte
	hexencode(buf[:16], u.Hi)
	hexencode(buf[16:], u.Lo)
	return string(buf[:])
}

func hexencode(dst []byte, v uint64) {
	const hex = "0123456789abcdef"
	for i := 0; i < 8; i++ {
		b := byte(v >> uint(56-8*i))
		dst[2*i] = hex[b>>4]
		dst[2*i+1] = hex[b&0xf]
	}
}

// --- Helper functions ---

func le32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }
func le64(b []byte) uint64 { return binary.LittleEndian.Uint64(b) }

func swap32(x uint32) uint32 { return bits.ReverseBytes32(x) }
func swap64(x uint64) uint64 { return bits.ReverseBytes64(x) }

func rotl32(x uint32, r int) uint32 { return bits.RotateLeft32(x, r) }
func rotl64(x uint64, r int) uint64 { return bits.RotateLeft64(x, r) }

func xorshift64(v uint64, shift int) uint64 { return v ^ (v >> uint(shift)) }

// mult64to128 computes the full 128-bit product of two 64-bit values.
// Returns (lo, hi) where the mathematical value is hi << 64 | lo.
func mult64to128(lhs, rhs uint64) (lo, hi uint64) {
	hi, lo = bits.Mul64(lhs, rhs)
	return lo, hi
}

// mul128fold64 computes the 128-bit product and folds it to 64 bits via XOR.
func mul128fold64(lhs, rhs uint64) uint64 {
	lo, hi := mult64to128(lhs, rhs)
	return lo ^ hi
}

// mult32to64 returns the product of the low 32 bits of two uint64 values.
func mult32to64(x, y uint64) uint64 {
	return uint64(uint32(x)) * uint64(uint32(y))
}

// mult32to64add64 returns mult32to64(lhs, rhs) + acc.
func mult32to64add64(lhs, rhs, acc uint64) uint64 {
	return mult32to64(lhs, rhs) + acc
}

// xxh64Avalanche is the XXH64 avalanche function.
func xxh64Avalanche(hash uint64) uint64 {
	hash ^= hash >> 33
	hash *= xxhPrime64_2
	hash ^= hash >> 29
	hash *= xxhPrime64_3
	hash ^= hash >> 32
	return hash
}

// xxh3Avalanche is the XXH3 avalanche function.
func xxh3Avalanche(h64 uint64) uint64 {
	h64 = xorshift64(h64, 37)
	h64 *= xxhPrimeMx1
	h64 = xorshift64(h64, 32)
	return h64
}

// --- Short input branches (0-16 bytes) ---

func xxh3Len1to3_128b(input []byte, secret []byte, seed uint64) Uint128 {
	c1 := input[0]
	c2 := input[len(input)>>1]
	c3 := input[len(input)-1]
	combinedl := (uint32(c1) << 16) | (uint32(c2) << 24) | (uint32(c3) << 0) | (uint32(len(input)) << 8)
	combinedh := rotl32(swap32(combinedl), 13)
	bitflipl := uint64(le32(secret[0:4])^le32(secret[4:8])) + seed
	bitfliph := uint64(le32(secret[8:12])^le32(secret[12:16])) - seed
	keyedLo := uint64(combinedl) ^ bitflipl
	keyedHi := uint64(combinedh) ^ bitfliph
	return Uint128{
		Lo: xxh64Avalanche(keyedLo),
		Hi: xxh64Avalanche(keyedHi),
	}
}

func xxh3Len4to8_128b(input []byte, secret []byte, seed uint64) Uint128 {
	seed ^= uint64(swap32(uint32(seed))) << 32
	inputLo := uint64(le32(input[0:4]))
	inputHi := uint64(le32(input[len(input)-4:]))
	input64 := inputLo + (inputHi << 32)
	bitflip := (le64(secret[16:24]) ^ le64(secret[24:32])) + seed
	keyed := input64 ^ bitflip

	mLo, mHi := mult64to128(keyed, xxhPrime64_1+(uint64(len(input))<<2))
	m128 := Uint128{Lo: mLo, Hi: mHi}

	m128.Hi += m128.Lo << 1
	m128.Lo ^= m128.Hi >> 3

	m128.Lo = xorshift64(m128.Lo, 35)
	m128.Lo *= xxhPrimeMx2
	m128.Lo = xorshift64(m128.Lo, 28)
	m128.Hi = xxh3Avalanche(m128.Hi)
	return m128
}

func xxh3Len9to16_128b(input []byte, secret []byte, seed uint64) Uint128 {
	bitflipl := (le64(secret[32:40]) ^ le64(secret[40:48])) - seed
	bitfliph := (le64(secret[48:56]) ^ le64(secret[56:64])) + seed
	inputLo := le64(input[0:8])
	inputHi := le64(input[len(input)-8:])
	mLo, mHi := mult64to128(inputLo^inputHi^bitflipl, xxhPrime64_1)
	m128 := Uint128{Lo: mLo, Hi: mHi}

	m128.Lo += uint64(len(input)-1) << 54
	inputHi ^= bitfliph
	// 64-bit optimized path:
	// m128.high64 += input_hi + ((uint64)input_hi.lo * (XXH_PRIME32_2 - 1))
	m128.Hi += inputHi + mult32to64(inputHi, uint64(xxhPrime32_2-1))

	m128.Lo ^= swap64(m128.Hi)

	// 128x64 multiply: h128 = m128 * XXH_PRIME64_2
	hLo, hHi := mult64to128(m128.Lo, xxhPrime64_2)
	hHi += m128.Hi * xxhPrime64_2
	h128 := Uint128{Lo: hLo, Hi: hHi}

	h128.Lo = xxh3Avalanche(h128.Lo)
	h128.Hi = xxh3Avalanche(h128.Hi)
	return h128
}

func xxh3Len0to16_128b(input []byte, secret []byte, seed uint64) Uint128 {
	if len(input) > 8 {
		return xxh3Len9to16_128b(input, secret, seed)
	}
	if len(input) >= 4 {
		return xxh3Len4to8_128b(input, secret, seed)
	}
	if len(input) > 0 {
		return xxh3Len1to3_128b(input, secret, seed)
	}
	// Empty input
	bitflipl := le64(secret[64:72]) ^ le64(secret[72:80])
	bitfliph := le64(secret[80:88]) ^ le64(secret[88:96])
	return Uint128{
		Lo: xxh64Avalanche(seed ^ bitflipl),
		Hi: xxh64Avalanche(seed ^ bitfliph),
	}
}

// --- Mid-size input branches (17-240 bytes) ---

// xxh3Mix16B mixes 16 bytes of input with 16 bytes of secret.
func xxh3Mix16B(input, secret []byte, seed uint64) uint64 {
	inputLo := le64(input[0:8])
	inputHi := le64(input[8:16])
	return mul128fold64(
		inputLo^(le64(secret[0:8])+seed),
		inputHi^(le64(secret[8:16])-seed),
	)
}

// xxh128Mix32B is a slower but stronger variant of xxh3Mix16B for 128-bit.
func xxh128Mix32B(acc Uint128, input1, input2, secret []byte, seed uint64) Uint128 {
	acc.Lo += xxh3Mix16B(input1, secret[0:16], seed)
	acc.Lo ^= le64(input2[0:8]) + le64(input2[8:16])
	acc.Hi += xxh3Mix16B(input2, secret[16:32], seed)
	acc.Hi ^= le64(input1[0:8]) + le64(input1[8:16])
	return acc
}

func xxh3Len17to128_128b(input, secret []byte, seed uint64) Uint128 {
	var acc Uint128
	acc.Lo = uint64(len(input)) * xxhPrime64_1
	acc.Hi = 0

	if len(input) > 32 {
		if len(input) > 64 {
			if len(input) > 96 {
				acc = xxh128Mix32B(acc, input[48:], input[len(input)-64:], secret[96:], seed)
			}
			acc = xxh128Mix32B(acc, input[32:], input[len(input)-48:], secret[64:], seed)
		}
		acc = xxh128Mix32B(acc, input[16:], input[len(input)-32:], secret[32:], seed)
	}
	acc = xxh128Mix32B(acc, input[0:], input[len(input)-16:], secret[0:], seed)

	var h128 Uint128
	h128.Lo = acc.Lo + acc.Hi
	h128.Hi = acc.Lo*xxhPrime64_1 + acc.Hi*xxhPrime64_4 + (uint64(len(input))-seed)*xxhPrime64_2
	h128.Lo = xxh3Avalanche(h128.Lo)
	h128.Hi = 0 - xxh3Avalanche(h128.Hi)
	return h128
}

func xxh3Len129to240_128b(input, secret []byte, seed uint64) Uint128 {
	var acc Uint128
	acc.Lo = uint64(len(input)) * xxhPrime64_1
	acc.Hi = 0

	// First 128 bytes (8 mix32B calls, i from 32 to 160 step 32)
	for i := 32; i < 160; i += 32 {
		acc = xxh128Mix32B(acc,
			input[i-32:],
			input[i-16:],
			secret[i-32:],
			seed)
	}
	acc.Lo = xxh3Avalanche(acc.Lo)
	acc.Hi = xxh3Avalanche(acc.Hi)

	// Remaining bytes (i from 160 to len step 32)
	for i := 160; i <= len(input); i += 32 {
		acc = xxh128Mix32B(acc,
			input[i-32:],
			input[i-16:],
			secret[xxh3MidsizeStartOffset+i-160:],
			seed)
	}

	// Last bytes
	acc = xxh128Mix32B(acc,
		input[len(input)-16:],
		input[len(input)-32:],
		secret[xxh3SecretSizeMin-xxh3MidsizeLastOffset-16:],
		0-seed)

	var h128 Uint128
	h128.Lo = acc.Lo + acc.Hi
	h128.Hi = acc.Lo*xxhPrime64_1 + acc.Hi*xxhPrime64_4 + (uint64(len(input))-seed)*xxhPrime64_2
	h128.Lo = xxh3Avalanche(h128.Lo)
	h128.Hi = 0 - xxh3Avalanche(h128.Hi)
	return h128
}

// --- Long input branch (>240 bytes) ---

// xxh3Accumulate512 processes a single 64-byte stripe.
//
// The loop is fully unrolled with constant indices so that the compiler can
// keep the accumulators in registers (the official C implementation unrolls
// this loop for scalar targets the same way). With a variable loop index,
// every lane forces the accumulator array to be reloaded and spilled.
func xxh3Accumulate512(acc *[8]uint64, input, secret []byte) {
	data0 := le64(input[0:8])
	key0 := data0 ^ le64(secret[0:8])
	acc[1] += data0
	acc[0] = mult32to64add64(key0, key0>>32, acc[0])

	data1 := le64(input[8:16])
	key1 := data1 ^ le64(secret[8:16])
	acc[0] += data1
	acc[1] = mult32to64add64(key1, key1>>32, acc[1])

	data2 := le64(input[16:24])
	key2 := data2 ^ le64(secret[16:24])
	acc[3] += data2
	acc[2] = mult32to64add64(key2, key2>>32, acc[2])

	data3 := le64(input[24:32])
	key3 := data3 ^ le64(secret[24:32])
	acc[2] += data3
	acc[3] = mult32to64add64(key3, key3>>32, acc[3])

	data4 := le64(input[32:40])
	key4 := data4 ^ le64(secret[32:40])
	acc[5] += data4
	acc[4] = mult32to64add64(key4, key4>>32, acc[4])

	data5 := le64(input[40:48])
	key5 := data5 ^ le64(secret[40:48])
	acc[4] += data5
	acc[5] = mult32to64add64(key5, key5>>32, acc[5])

	data6 := le64(input[48:56])
	key6 := data6 ^ le64(secret[48:56])
	acc[7] += data6
	acc[6] = mult32to64add64(key6, key6>>32, acc[6])

	data7 := le64(input[56:64])
	key7 := data7 ^ le64(secret[56:64])
	acc[6] += data7
	acc[7] = mult32to64add64(key7, key7>>32, acc[7])
}

// xxh3Accumulate processes nbStripes stripes.
func xxh3Accumulate(acc *[8]uint64, input, secret []byte, nbStripes int) {
	for n := 0; n < nbStripes; n++ {
		xxh3Accumulate512(acc, input[n*xxh3StripeLen:], secret[n*xxh3SecretConsumeRate:])
	}
}

// xxh3ScrambleAcc scrambles the accumulators.
//
// Unrolled with constant indices for the same reason as
// xxh3Accumulate512.
func xxh3ScrambleAcc(acc *[8]uint64, secret []byte) {
	acc[0] = xxh3ScrambleLane(acc[0], le64(secret[0:8]))
	acc[1] = xxh3ScrambleLane(acc[1], le64(secret[8:16]))
	acc[2] = xxh3ScrambleLane(acc[2], le64(secret[16:24]))
	acc[3] = xxh3ScrambleLane(acc[3], le64(secret[24:32]))
	acc[4] = xxh3ScrambleLane(acc[4], le64(secret[32:40]))
	acc[5] = xxh3ScrambleLane(acc[5], le64(secret[40:48]))
	acc[6] = xxh3ScrambleLane(acc[6], le64(secret[48:56]))
	acc[7] = xxh3ScrambleLane(acc[7], le64(secret[56:64]))
}

// xxh3ScrambleLane scrambles a single accumulator lane.
func xxh3ScrambleLane(acc64, key64 uint64) uint64 {
	acc64 = xorshift64(acc64, 47)
	acc64 ^= key64
	return acc64 * uint64(xxhPrime32_1)
}


// xxh3InitCustomSecret generates a custom secret from a seed.
func xxh3InitCustomSecret(customSecret *[xxh3SecretDefaultSize]byte, seed uint64) {
	nbRounds := xxh3SecretDefaultSize / 16
	for i := 0; i < nbRounds; i++ {
		lo := le64(xxh3Secret[16*i:16*i+8]) + seed
		hi := le64(xxh3Secret[16*i+8:16*i+16]) - seed
		binary.LittleEndian.PutUint64(customSecret[16*i:16*i+8], lo)
		binary.LittleEndian.PutUint64(customSecret[16*i+8:16*i+16], hi)
	}
}

// xxh3HashLongInternalLoop processes long inputs through the accumulator loop.
func xxh3HashLongInternalLoop(acc *[8]uint64, input []byte, secret []byte) {
	secretSize := len(secret)
	nbStripesPerBlock := (secretSize - xxh3StripeLen) / xxh3SecretConsumeRate
	blockLen := xxh3StripeLen * nbStripesPerBlock
	nbBlocks := (len(input) - 1) / blockLen

	for n := 0; n < nbBlocks; n++ {
		xxh3Accumulate(acc, input[n*blockLen:], secret, nbStripesPerBlock)
		xxh3ScrambleAcc(acc, secret[secretSize-xxh3StripeLen:])
	}

	// Last partial block
	nbStripes := ((len(input) - 1) - (blockLen * nbBlocks)) / xxh3StripeLen
	xxh3Accumulate(acc, input[nbBlocks*blockLen:], secret, nbStripes)

	// Last stripe
	p := input[len(input)-xxh3StripeLen:]
	xxh3Accumulate512(acc, p, secret[secretSize-xxh3StripeLen-xxh3SecretLastaccStart:])
}

// xxh3Mix2Accs mixes two accumulators with 16 bytes of secret.
func xxh3Mix2Accs(acc []uint64, secret []byte) uint64 {
	return mul128fold64(
		acc[0]^le64(secret[0:8]),
		acc[1]^le64(secret[8:16]),
	)
}

// xxh3MergeAccs merges the 8 accumulators into a single 64-bit value.
func xxh3MergeAccs(acc *[8]uint64, secret []byte, start uint64) uint64 {
	result64 := start
	for i := 0; i < 4; i++ {
		result64 += xxh3Mix2Accs(acc[2*i:2*i+2], secret[16*i:16*i+16])
	}
	return xxh3Avalanche(result64)
}

// xxh3FinalizeLong64b produces the 64-bit result for long inputs.
func xxh3FinalizeLong64b(acc *[8]uint64, secret []byte, length uint64) uint64 {
	return xxh3MergeAccs(acc, secret[xxh3SecretMergeaccsStart:], length*xxhPrime64_1)
}

// xxh3FinalizeLong128b produces the 128-bit result for long inputs.
func xxh3FinalizeLong128b(acc *[8]uint64, secret []byte, secretSize int, length uint64) Uint128 {
	return Uint128{
		Lo: xxh3FinalizeLong64b(acc, secret, length),
		Hi: xxh3MergeAccs(acc, secret[secretSize-xxh3StripeLen-xxh3SecretMergeaccsStart:], ^(length * xxhPrime64_2)),
	}
}

// xxh3HashLong128b hashes long inputs (>240 bytes) and returns the 128-bit result.
func xxh3HashLong128b(input []byte, secret []byte) Uint128 {
	acc := [8]uint64{
		uint64(xxhPrime32_3), xxhPrime64_1, xxhPrime64_2, xxhPrime64_3,
		xxhPrime64_4, uint64(xxhPrime32_2), xxhPrime64_5, uint64(xxhPrime32_1),
	}
	xxh3HashLongInternalLoop(&acc, input, secret)
	return xxh3FinalizeLong128b(&acc, secret, len(secret), uint64(len(input)))
}

// xxh3HashLong128bWithSeed hashes long inputs with a seed.
// If seed is 0, the default secret is used. Otherwise a custom secret is generated.
func xxh3HashLong128bWithSeed(input []byte, seed uint64) Uint128 {
	if seed == 0 {
		return xxh3HashLong128b(input, xxh3Secret[:])
	}
	var secret [xxh3SecretDefaultSize]byte
	xxh3InitCustomSecret(&secret, seed)
	return xxh3HashLong128b(input, secret[:])
}

// xxh3Hash128Internal is the main dispatch function for XXH3-128.
func xxh3Hash128Internal(input []byte, seed uint64, secret []byte) Uint128 {
	n := len(input)
	if n <= 16 {
		return xxh3Len0to16_128b(input, secret, seed)
	}
	if n <= 128 {
		return xxh3Len17to128_128b(input, secret, seed)
	}
	if n <= xxh3MidsizeMax {
		return xxh3Len129to240_128b(input, secret, seed)
	}
	return xxh3HashLong128bWithSeed(input, seed)
}

// --- Public one-shot API ---

// Sum128 computes the 128-bit XXH3 hash of b with a zero seed.
func Sum128(b []byte) Uint128 {
	return xxh3Hash128Internal(b, 0, xxh3Secret[:])
}

// Sum128WithSeed computes the 128-bit XXH3 hash of b with the given seed.
func Sum128WithSeed(b []byte, seed uint64) Uint128 {
	return xxh3Hash128Internal(b, seed, xxh3Secret[:])
}
