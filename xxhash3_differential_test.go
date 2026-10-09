package xxhash

import (
	"math/rand"
	"testing"
)

// This file proves that the unrolled XXH3-128 hot loops
// (xxh3Accumulate512, xxh3ScrambleAcc) are bit-for-bit equivalent to the
// original loop-based implementations that shipped before the optimization.
//
// The ref* functions below are copied verbatim from commit 5d88b56
// (the state of the repository immediately before the unroll). The tests
// compare old and new implementations directly, in the same binary:
//
//  1. leaf-level differential over randomized accumulators/inputs/secrets,
//  2. whole-pipeline differential (one-shot Sum128WithSeed vs a pipeline
//     rebuilt from the reference leaves and the unchanged branch functions),
//  3. streaming Digest128 vs the reference one-shot pipeline.
//
// Together with TestSum128CrossCheck (official C reference vectors), this
// pins both equivalence-to-before and absolute correctness.

// refAccumulate512 is the pre-optimization xxh3Accumulate512 (commit 5d88b56).
func refAccumulate512(acc *[8]uint64, input, secret []byte) {
	for lane := 0; lane < xxh3AccNb; lane++ {
		dataVal := le64(input[lane*8 : lane*8+8])
		dataKey := dataVal ^ le64(secret[lane*8:lane*8+8])
		acc[lane^1] += dataVal // swap adjacent lanes
		acc[lane] = mult32to64add64(dataKey, dataKey>>32, acc[lane])
	}
}

// refScrambleAcc is the pre-optimization xxh3ScrambleAcc (commit 5d88b56).
func refScrambleAcc(acc *[8]uint64, secret []byte) {
	for lane := 0; lane < xxh3AccNb; lane++ {
		key64 := le64(secret[lane*8 : lane*8+8])
		acc64 := acc[lane]
		acc64 = xorshift64(acc64, 47)
		acc64 ^= key64
		acc64 *= uint64(xxhPrime32_1)
		acc[lane] = acc64
	}
}

// refAccumulate is the pre-optimization xxh3Accumulate, using refAccumulate512.
func refAccumulate(acc *[8]uint64, input, secret []byte, nbStripes int) {
	for n := 0; n < nbStripes; n++ {
		refAccumulate512(acc, input[n*xxh3StripeLen:], secret[n*xxh3SecretConsumeRate:])
	}
}

// refHashLongInternalLoop is xxh3HashLongInternalLoop rebuilt on the
// reference leaves.
func refHashLongInternalLoop(acc *[8]uint64, input, secret []byte) {
	secretSize := len(secret)
	nbStripesPerBlock := (secretSize - xxh3StripeLen) / xxh3SecretConsumeRate
	blockLen := xxh3StripeLen * nbStripesPerBlock
	nbBlocks := (len(input) - 1) / blockLen

	for n := 0; n < nbBlocks; n++ {
		refAccumulate(acc, input[n*blockLen:], secret, nbStripesPerBlock)
		refScrambleAcc(acc, secret[secretSize-xxh3StripeLen:])
	}

	// Last partial block
	nbStripes := ((len(input) - 1) - (blockLen * nbBlocks)) / xxh3StripeLen
	refAccumulate(acc, input[nbBlocks*blockLen:], secret, nbStripes)

	// Last stripe
	p := input[len(input)-xxh3StripeLen:]
	refAccumulate512(acc, p, secret[secretSize-xxh3StripeLen-xxh3SecretLastaccStart:])
}

// refHashLong128b is xxh3HashLong128b rebuilt on the reference leaves.
func refHashLong128b(input []byte, secret []byte) Uint128 {
	acc := [8]uint64{
		uint64(xxhPrime32_3), xxhPrime64_1, xxhPrime64_2, xxhPrime64_3,
		xxhPrime64_4, uint64(xxhPrime32_2), xxhPrime64_5, uint64(xxhPrime32_1),
	}
	refHashLongInternalLoop(&acc, input, secret)
	return xxh3FinalizeLong128b(&acc, secret, len(secret), uint64(len(input)))
}

// refSum128WithSeed mirrors xxh3Hash128Internal/xxh3HashLong128bWithSeed
// dispatch, but routes the long-input path through the reference leaves.
// Inputs of len <= 240 use the same (unchanged) branch functions as
// production code, so only the >240-byte path can differ.
func refSum128WithSeed(b []byte, seed uint64) Uint128 {
	n := len(b)
	if n <= 16 {
		return xxh3Len0to16_128b(b, xxh3Secret[:], seed)
	}
	if n <= 128 {
		return xxh3Len17to128_128b(b, xxh3Secret[:], seed)
	}
	if n <= xxh3MidsizeMax {
		return xxh3Len129to240_128b(b, xxh3Secret[:], seed)
	}
	if seed == 0 {
		return refHashLong128b(b, xxh3Secret[:])
	}
	var secret [xxh3SecretDefaultSize]byte
	xxh3InitCustomSecret(&secret, seed)
	return refHashLong128b(b, secret[:])
}

// TestAccumulate512Differential proves the unrolled xxh3Accumulate512
// produces bit-for-bit identical accumulator states to the original loop
// version, over randomized inputs, secrets, and starting accumulators
// (including states reached mid-block in real hashing).
func TestAccumulate512Differential(t *testing.T) {
	rng := rand.New(rand.NewSource(0xC0FFEE))
	var input, secret [xxh3StripeLen]byte
	for iter := 0; iter < 10000; iter++ {
		randBytes(rng, input[:])
		randBytes(rng, secret[:])
		var accA, accB [8]uint64
		for lane := range accA {
			accA[lane] = rng.Uint64()
		}
		accB = accA

		xxh3Accumulate512(&accA, input[:], secret[:])
		refAccumulate512(&accB, input[:], secret[:])

		if accA != accB {
			for lane := 0; lane < 8; lane++ {
				if accA[lane] != accB[lane] {
					t.Fatalf("iter %d lane %d: unrolled=0x%016x reference=0x%016x\ninput=%x\nsecret=%x",
						iter, lane, accA[lane], accB[lane], input, secret)
				}
			}
		}
	}
}

// TestScrambleAccDifferential proves the unrolled xxh3ScrambleAcc is
// bit-for-bit identical to the original loop version.
func TestScrambleAccDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(0xBADC0DE))
	var secret [xxh3StripeLen]byte
	for iter := 0; iter < 10000; iter++ {
		randBytes(rng, secret[:])
		var accA, accB [8]uint64
		for lane := range accA {
			accA[lane] = rng.Uint64()
		}
		accB = accA

		xxh3ScrambleAcc(&accA, secret[:])
		refScrambleAcc(&accB, secret[:])

		if accA != accB {
			t.Fatalf("iter %d: unrolled=%x reference=%x\nsecret=%x",
				iter, accA, accB, secret)
		}
	}
}

// TestSum128PipelineDifferential proves the whole one-shot hash, end to end,
// is unchanged by the optimization: every length across all branch
// boundaries, four seeds (including the custom-secret path), and four data
// patterns must match the reference pipeline exactly.
func TestSum128PipelineDifferential(t *testing.T) {
	seeds := []uint64{0, 1, 42, 1<<64 - 1}

	lengths := make([]int, 0, 1100)
	// Exhaustive 0..1024 covers every branch boundary:
	// 0,1,3,4,8,9,16,17,32,64,96,128,129,240,241 and off-by-one neighborhood.
	for n := 0; n <= 1024; n++ {
		lengths = append(lengths, n)
	}
	// Long-path lengths beyond one block (blockLen = 64*16 = 1024... at
	// secretSize=192: nbStripesPerBlock=16, blockLen=1024): include multiples,
	// off-by-ones, and multi-block sizes.
	lengths = append(lengths, 1025, 2047, 2048, 2049, 3072, 4095, 4096,
		8191, 16384, 65536, 100000)

	patterns := []func(i int) byte{
		func(i int) byte { return byte(i) },
		func(i int) byte { return 0 },
		func(i int) byte { return 0xff },
		func(i int) byte { return byte(uint32(i) * 2654435761 >> 16) },
	}

	for _, pattern := range patterns {
		for _, n := range lengths {
			data := make([]byte, n)
			for i := range data {
				data[i] = pattern(i)
			}
			for _, seed := range seeds {
				got := Sum128WithSeed(data, seed)
				want := refSum128WithSeed(data, seed)
				if got != want {
					t.Fatalf("len=%d seed=%d pattern=%T: unrolled lo=0x%016x hi=0x%016x; reference lo=0x%016x hi=0x%016x",
						n, seed, pattern, got.Lo, got.Hi, want.Lo, want.Hi)
				}
			}
		}
	}
}

// TestDigest128VsReferencePipeline proves the streaming API (which routes
// through the same hot loops via xxh3ConsumeStripes) matches the reference
// one-shot pipeline across chunked writes, for every write pattern.
// Transitively this pins streaming-new == streaming-old because the
// pre-optimization streaming path was itself verified equal to the
// pre-optimization one-shot (see TestSum128StreamingMatch, FuzzSum128Consistency).
func TestDigest128VsReferencePipeline(t *testing.T) {
	seeds := []uint64{0, 1, 42, 1<<64 - 1}
	chunkSizes := []int{1, 7, 63, 64, 65, 240, 241, 255, 256, 1023, 1024, 1025, 5000}
	lengths := []int{0, 1, 16, 100, 240, 241, 242, 255, 256, 1024, 1025, 2048,
		4096, 10000, 100001}

	for _, n := range lengths {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(uint32(i) * 2654435761 >> 16)
		}
		want := refSum128WithSeed(data, 0)
		want1 := refSum128WithSeed(data, 1)
		for _, chunk := range chunkSizes {
			for _, seed := range seeds {
				d := New128WithSeed(seed)
				for pos := 0; pos < n; pos += chunk {
					end := pos + chunk
					if end > n {
						end = n
					}
					d.Write(data[pos:end])
				}
				got := d.Sum128()
				var wantSeed Uint128
				switch seed {
				case 0:
					wantSeed = want
				case 1:
					wantSeed = want1
				default:
					wantSeed = refSum128WithSeed(data, seed)
				}
				if got != wantSeed {
					t.Fatalf("len=%d chunk=%d seed=%d: streaming lo=0x%016x hi=0x%016x; reference lo=0x%016x hi=0x%016x",
						n, chunk, seed, got.Lo, got.Hi, wantSeed.Lo, wantSeed.Hi)
				}
			}
		}
	}
}

func randBytes(rng *rand.Rand, b []byte) {
	for i := range b {
		b[i] = byte(rng.Uint32())
	}
}