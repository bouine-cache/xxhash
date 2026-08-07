// This file implements the streaming (incremental) API for XXH3-128.
//
// The streaming implementation mirrors the official xxHash reference
// implementation's XXH3_state_t and related functions.
// See https://github.com/Cyan4973/xxHash (commit c0b5ea9).

package xxhash

// Digest128 is the streaming state for the 128-bit XXH3 hash (XXH128).
//
// A zero-valued Digest128 is not ready to receive writes.
// Call Reset or create a Digest128 using New128 before calling other methods.
//
// Note that Digest128 does not implement hash.Hash because that interface
// requires a 32-bit Sum method returning a uint32, which is incompatible
// with the 128-bit result. Use Sum128 to obtain the 128-bit result.
type Digest128 struct {
	acc               [8]uint64
	customSecret      [xxh3SecretDefaultSize]byte
	buffer            [xxh3InternalBufferSize]byte
	bufferedSize      int
	useSeed           bool
	nbStripesSoFar    int
	totalLen          uint64
	nbStripesPerBlock int
	secretLimit       int
	seed              uint64
	extSecret         []byte // nil when using customSecret (seed-based)
}

// New128 creates a new Digest128 with a zero seed.
func New128() *Digest128 {
	return New128WithSeed(0)
}

// New128WithSeed creates a new Digest128 with the given seed.
func New128WithSeed(seed uint64) *Digest128 {
	var d Digest128
	d.ResetWithSeed(seed)
	return &d
}

// Reset clears the Digest128's state so that it can be reused.
// It uses a seed value of zero.
func (d *Digest128) Reset() {
	d.ResetWithSeed(0)
}

// ResetWithSeed clears the Digest128's state so that it can be reused.
// It uses the given seed to initialize the state.
func (d *Digest128) ResetWithSeed(seed uint64) {
	d.acc[0] = uint64(xxhPrime32_3)
	d.acc[1] = xxhPrime64_1
	d.acc[2] = xxhPrime64_2
	d.acc[3] = xxhPrime64_3
	d.acc[4] = xxhPrime64_4
	d.acc[5] = uint64(xxhPrime32_2)
	d.acc[6] = xxhPrime64_5
	d.acc[7] = uint64(xxhPrime32_1)
	d.seed = seed
	d.useSeed = seed != 0
	d.extSecret = nil
	d.secretLimit = xxh3SecretDefaultSize - xxh3StripeLen
	d.nbStripesPerBlock = d.secretLimit / xxh3SecretConsumeRate
	d.bufferedSize = 0
	d.nbStripesSoFar = 0
	d.totalLen = 0

	if seed != 0 {
		xxh3InitCustomSecret(&d.customSecret, seed)
	}
}

// Size always returns 16 bytes.
func (d *Digest128) Size() int { return 16 }

// BlockSize always returns 64 bytes (the XXH3 stripe size).
func (d *Digest128) BlockSize() int { return xxh3StripeLen }

// Write adds more data to d. It always returns len(b), nil.
func (d *Digest128) Write(b []byte) (int, error) {
	n := len(b)
	d.totalLen += uint64(n)

	if n == 0 {
		return 0, nil
	}

	// Small input: just fill in tmp buffer
	if n <= xxh3InternalBufferSize-d.bufferedSize {
		copy(d.buffer[d.bufferedSize:], b)
		d.bufferedSize += n
		return n, nil
	}

	// Total input is now > XXH3_INTERNALBUFFER_SIZE
	secret := d.secret()

	// Copy accumulators to stack for better optimization (matching C reference)
	acc := d.acc

	// Internal buffer is partially filled; complete it, then consume it.
	if d.bufferedSize > 0 {
		loadSize := xxh3InternalBufferSize - d.bufferedSize
		copy(d.buffer[d.bufferedSize:], b[:loadSize])
		b = b[loadSize:]
		xxh3ConsumeStripes(&acc,
			&d.nbStripesSoFar, d.nbStripesPerBlock,
			d.buffer[:], xxh3InternalBufferSize/xxh3StripeLen,
			secret, d.secretLimit)
		d.bufferedSize = 0
	}

	bEnd := len(b)
	if bEnd > xxh3InternalBufferSize {
		nbStripes := (bEnd - 1) / xxh3StripeLen
		consumed := xxh3ConsumeStripes(&acc,
			&d.nbStripesSoFar, d.nbStripesPerBlock,
			b, nbStripes,
			secret, d.secretLimit)
		// Save the last stripe for later use in digest
		copy(d.buffer[xxh3InternalBufferSize-xxh3StripeLen:], b[consumed-xxh3StripeLen:consumed])
		b = b[consumed:]
	}

	// Some remaining input (always): buffer it
	copy(d.buffer[:], b)
	d.bufferedSize = len(b)

	d.acc = acc
	return n, nil
}

// secret returns the active secret (either the external default secret or the
// custom secret generated from the seed).
func (d *Digest128) secret() []byte {
	if d.extSecret != nil {
		return d.extSecret
	}
	if d.seed != 0 {
		return d.customSecret[:]
	}
	return xxh3Secret[:]
}

// xxh3ConsumeStripes processes nbStripes stripes, handling block boundaries.
func xxh3ConsumeStripes(acc *[8]uint64, nbStripesSoFar *int, nbStripesPerBlock int,
	input []byte, nbStripes int, secret []byte, secretLimit int) int {

	initialSecretOffset := *nbStripesSoFar * xxh3SecretConsumeRate
	inputPos := 0

	// Process full blocks
	if nbStripes >= (nbStripesPerBlock - *nbStripesSoFar) {
		nbStripesThisIter := nbStripesPerBlock - *nbStripesSoFar
		for {
			xxh3Accumulate(acc, input[inputPos:], secret[initialSecretOffset:], nbStripesThisIter)
			xxh3ScrambleAcc(acc, secret[secretLimit:])
			inputPos += nbStripesThisIter * xxh3StripeLen
			nbStripes -= nbStripesThisIter
			nbStripesThisIter = nbStripesPerBlock
			initialSecretOffset = 0
			if nbStripes < nbStripesPerBlock {
				break
			}
		}
		*nbStripesSoFar = 0
	}

	// Process a partial block
	if nbStripes > 0 {
		xxh3Accumulate(acc, input[inputPos:], secret[initialSecretOffset:], nbStripes)
		inputPos += nbStripes * xxh3StripeLen
		*nbStripesSoFar += nbStripes
	}

	return inputPos
}

// xxh3DigestLong processes the final accumulators for long inputs.
func xxh3DigestLong(acc *[8]uint64, state *Digest128, secret []byte) {
	// Copy state accumulators to local copy (state remains unaltered)
	*acc = state.acc

	if state.bufferedSize >= xxh3StripeLen {
		nbStripes := (state.bufferedSize - 1) / xxh3StripeLen
		nbStripesSoFar := state.nbStripesSoFar
		xxh3ConsumeStripes(acc,
			&nbStripesSoFar, state.nbStripesPerBlock,
			state.buffer[:], nbStripes,
			secret, state.secretLimit)
		// lastStripePtr = state.buffer + state.bufferedSize - XXH_STRIPE_LEN
		lastStripe := state.buffer[state.bufferedSize-xxh3StripeLen : state.bufferedSize]
		xxh3Accumulate512(acc, lastStripe, secret[state.secretLimit-xxh3SecretLastaccStart:])
	} else {
		// bufferedSize < XXH_STRIPE_LEN
		// Copy to temp buffer: last stripe from the end of buffer + current data
		catchupSize := xxh3StripeLen - state.bufferedSize
		var lastStripe [xxh3StripeLen]byte
		copy(lastStripe[:], state.buffer[xxh3InternalBufferSize-catchupSize:xxh3InternalBufferSize])
		copy(lastStripe[catchupSize:], state.buffer[:state.bufferedSize])
		xxh3Accumulate512(acc, lastStripe[:], secret[state.secretLimit-xxh3SecretLastaccStart:])
	}
}

// Sum128 returns the current 128-bit hash.
//
// It does not mutate the digest state; you can continue writing after
// calling Sum128.
func (d *Digest128) Sum128() Uint128 {
	secret := d.secret()

	if d.totalLen > xxh3MidsizeMax {
		var acc [8]uint64
		xxh3DigestLong(&acc, d, secret)
		return xxh3FinalizeLong128b(&acc, secret, d.secretLimit+xxh3StripeLen, d.totalLen)
	}

	// totalLen <= XXH3_MIDSIZE_MAX: short code
	if d.useSeed {
		return xxh3Hash128Internal(d.buffer[:d.bufferedSize], d.seed, xxh3Secret[:])
	}
	// Use the secret with the proper size (secretLimit + STRIPE_LEN)
	return xxh3Hash128Internal(d.buffer[:d.bufferedSize], 0, secret[:d.secretLimit+xxh3StripeLen])
}

// Sum appends the current 128-bit hash to b in big-endian canonical
// representation and returns the resulting slice.
//
// The canonical representation places the high 64 bits first, followed by
// the low 64 bits, each in big-endian byte order. This matches the official
// XXH128 canonical representation.
func (d *Digest128) Sum(b []byte) []byte {
	h := d.Sum128()
	bb := h.Bytes()
	return append(b, bb[:]...)
}
