package xxhash

import (
	"bytes"
	"encoding/binary"
	"math"
	"math/rand"
	"testing"
)

// Test vectors generated from the official Cyan4973/xxHash implementation
// (commit c0b5ea9) using XXH3_128bits_withSeed.
// Source: https://github.com/Cyan4973/xxHash
var xxh3TestVectors = []struct {
	name  string
	input string
	seed  uint64
	lo    uint64
	hi    uint64
}{
	{"empty", "", 0, 0x6001c324468d497f, 0x99aa06d3014798d8},
	{"a", "a", 0, 0xe6c632b61e964e1f, 0xa96faf705af16834},
	{"ab", "ab", 0, 0xa873719c24d5735c, 0x89c65ebc828eebac},
	{"abc", "abc", 0, 0x78af5f94892f3950, 0x06b05ab6733a6185},
	{"abcd", "abcd", 0, 0x1be79eecd1b1353d, 0x8d6b60383dfa90c2},
	{"abcde", "abcde", 0, 0x97d5a48ef320eec2, 0x3043c78169f25c3f},
	{"abcdef", "abcdef", 0, 0xda35a6714d34f8a2, 0x389197a55db2b2e4},
	{"abcdefg", "abcdefg", 0, 0x3fe798c0edaa6dc6, 0x2aafd83869a59c31},
	{"abcdefgh", "abcdefgh", 0, 0x42b702b313880f12, 0xdac23237af373533},
	{"abcdefghi", "abcdefghi", 0, 0xc0646b2d7986db98, 0xb43ff5bc5ff2e0ad},
	{"abcdefghij", "abcdefghij", 0, 0xb0a8c058e69ff5a7, 0x9e814df2752571c7},
	{"abcdefghijk", "abcdefghijk", 0, 0x0c30617e220bd2c5, 0xf63802ddeb8a8481},
	{"abcdefghijkl", "abcdefghijkl", 0, 0xca41a0e8a26ef9e2, 0xd5c1c71e1ef3a2b6},
	{"abcdefghijklm", "abcdefghijklm", 0, 0x4c633bfeef25de5b, 0xb3f3c61b89a9d122},
	{"abcdefghijklmn", "abcdefghijklmn", 0, 0xcb0743e0c58a8d23, 0x4d15f6daa22c156b},
	{"abcdefghijklmno", "abcdefghijklmno", 0, 0xd35dc9eaab32b9a0, 0x5e190a0fa5ad0836},
	{"abcdefghijklmnop", "abcdefghijklmnop", 0, 0x3e8e153ff12f6330, 0x1f58fc809b1b8c4b},
	{"17bytes", "0123456789abcdef0", 0, 0x259d04103128b07b, 0x4d011b9cf16c97fc},
	{"32bytes_seq", string(seqBytes(32)), 0, 0x457d9566b6fcd697, 0x25e7c9b3424ceed2},
	{"64bytes_seq", string(seqBytes(64)), 0, 0x90c1971ddb04ce74, 0x9c6e140a465545e5},
	{"96bytes_seq", string(seqBytes(96)), 0, 0x6e53ab55b4f5558b, 0xc57556e9ccb97efa},
	{"128bytes_seq", string(seqBytes(128)), 0, 0x05321a0b64d67b41, 0x14792fc3af88dc6c},
	{"129bytes_seq", string(seqBytes(129)), 0, 0xbc30b63382b09a3b, 0xdd5e74ac6b45f54e},
	{"240bytes_seq", string(seqBytes(240)), 0, 0xc92b68e16f83bbb6, 0x65b5be86da5540e7},
	{"241bytes_seq", string(seqBytes(241)), 0, 0x02e8cd95421c6d02, 0x1da1cb61bcb8a2a1},
	{"1024bytes_seq", string(seqBytes(1024)), 0, 0xa870f92984398d22, 0x83885e853bb6640c},
	{"4096bytes_seq", string(seqBytes(4096)), 0, 0xeb4b7c3707879151, 0x03916578969f7a66},
	{"10000bytes_seq", string(seqBytes(10000)), 0, 0x3eee77440c4c3d08, 0xddd880951f8af004},

	// Seeds
	{"empty_seed1", "", 1, 0x6131b78f753823cd, 0xd9265cc53bb2b9ae},
	{"a_seed1", "a", 1, 0xd2f6d0996f37a720, 0xfdd9b77fdcaf3221},
	{"abcd_seed1", "abcd", 1, 0x1f291598aa9f7b26, 0xafe9893634190439},
	{"16bytes_seed1", "abcdefghijklmnop", 1, 0x400f927385b830cb, 0xd1247db7d4987ba5},
	{"240bytes_seed1", string(seqBytes(240)), 1, 0xdf63dacb5e824c67, 0xe56fed73d92c8ab1},
	{"241bytes_seed1", string(seqBytes(241)), 1, 0xda735d4f53476cb5, 0x55b1f41464ef8ee8},

	{"empty_seedmax", "", math.MaxUint64, 0x2d10110a247d19dd, 0x5334ec22748b5fcd},
	{"a_seedmax", "a", math.MaxUint64, 0x43a7e49bc8a25756, 0x952ec4387f5e4d9f},
	{"abcd_seedmax", "abcd", math.MaxUint64, 0x690e6a398a775d0b, 0x8fd2b99c17135539},
	{"16bytes_seedmax", "abcdefghijklmnop", math.MaxUint64, 0x3adb35c2c70425bc, 0x2f931f984e50b353},
	{"240bytes_seedmax", string(seqBytes(240)), math.MaxUint64, 0x983092413c4ab9a7, 0xba860b4f19a30b59},
	{"241bytes_seedmax", string(seqBytes(241)), math.MaxUint64, 0xb1f001885dc89e7c, 0x076e03dab3f4b344},

	{"16bytes_seed42", "abcdefghijklmnop", 42, 0xba506bad92b05887, 0xb48ce5a4d8afe5d1},
	{"16bytes_seed1000", "abcdefghijklmnop", 1000, 0x8cec386c8695f736, 0x680142e131eb17bc},
	{"241bytes_seed42", string(seqBytes(241)), 42, 0x26e3d358d4e0a1d6, 0xd591e680c65b77ff},

	// Binary data with zeros
	{"100zeros", string(make([]byte, 100)), 0, 0x801fedc74ccd608c, 0x6ba30a4e9dffe1ff},
	{"300zeros", string(make([]byte, 300)), 0, 0x56d0762b20085f91, 0xbe8945035b2f421f},

	// UTF-8
	{"utf8", "Hello\xe4\xb8\x96\xe7\x95\x8c", 0, 0xadeb11f50e558864, 0x629a6b4b41c79e8c},

	// Around boundaries
	{"15bytes_seq", string(seqBytes(15)), 0, 0x0017ea4be19bc787, 0x301a9f754e8f569a},
	{"17bytes_seq", string(seqBytes(17)), 0, 0xc06e233df7729217, 0x685bc458b37d057f},
	{"127bytes_seq", string(seqBytes(127)), 0, 0x060c2e3ddf0f2fb9, 0xd5add870c9c9e00f},
	{"129bytes_seq2", string(seqBytes(129)), 0, 0xbc30b63382b09a3b, 0xdd5e74ac6b45f54e},
	{"239bytes_seq", string(seqBytes(239)), 0, 0xfe21374628fcc539, 0x9843ab31a06be0df},
	{"241bytes_seq2", string(seqBytes(241)), 0, 0x02e8cd95421c6d02, 0x1da1cb61bcb8a2a1},
}

func seqBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func TestSum128(t *testing.T) {
	for _, tt := range xxh3TestVectors {
		t.Run(tt.name, func(t *testing.T) {
			b := []byte(tt.input)
			got := Sum128WithSeed(b, tt.seed)
			if got.Lo != tt.lo || got.Hi != tt.hi {
				t.Fatalf("Sum128WithSeed: got lo=0x%016x hi=0x%016x; want lo=0x%016x hi=0x%016x",
					got.Lo, got.Hi, tt.lo, tt.hi)
			}
			if tt.seed == 0 {
				got = Sum128(b)
				if got.Lo != tt.lo || got.Hi != tt.hi {
					t.Fatalf("Sum128: got lo=0x%016x hi=0x%016x; want lo=0x%016x hi=0x%016x",
						got.Lo, got.Hi, tt.lo, tt.hi)
				}
				got = Sum128String(tt.input)
				if got.Lo != tt.lo || got.Hi != tt.hi {
					t.Fatalf("Sum128String: got lo=0x%016x hi=0x%016x; want lo=0x%016x hi=0x%016x",
						got.Lo, got.Hi, tt.lo, tt.hi)
				}
			}
			got = Sum128StringWithSeed(tt.input, tt.seed)
			if got.Lo != tt.lo || got.Hi != tt.hi {
				t.Fatalf("Sum128StringWithSeed: got lo=0x%016x hi=0x%016x; want lo=0x%016x hi=0x%016x",
					got.Lo, got.Hi, tt.lo, tt.hi)
			}
		})
	}
}

func TestDigest128(t *testing.T) {
	for _, tt := range xxh3TestVectors {
		lastChunkSize := len(tt.input)
		if lastChunkSize == 0 {
			lastChunkSize = 1
		}
		for chunkSize := 1; chunkSize <= lastChunkSize; chunkSize++ {
			name := tt.name + "/chunk=" + itoa(chunkSize)
			t.Run(name, func(t *testing.T) {
				d := New128WithSeed(tt.seed)
				ds := New128WithSeed(tt.seed)
				for i := 0; i < len(tt.input); i += chunkSize {
					chunk := tt.input[i:]
					if len(chunk) > chunkSize {
						chunk = chunk[:chunkSize]
					}
					n, err := d.Write([]byte(chunk))
					if err != nil || n != len(chunk) {
						t.Fatalf("Write: got (%d, %v); want (%d, nil)", n, err, len(chunk))
					}
					n, err = ds.WriteString(chunk)
					if err != nil || n != len(chunk) {
						t.Fatalf("WriteString: got (%d, %v); want (%d, nil)", n, err, len(chunk))
					}
				}
				got := d.Sum128()
				if got.Lo != tt.lo || got.Hi != tt.hi {
					t.Fatalf("Sum128: got lo=0x%016x hi=0x%016x; want lo=0x%016x hi=0x%016x",
						got.Lo, got.Hi, tt.lo, tt.hi)
				}
				got = ds.Sum128()
				if got.Lo != tt.lo || got.Hi != tt.hi {
					t.Fatalf("Sum128 (WriteString): got lo=0x%016x hi=0x%016x; want lo=0x%016x hi=0x%016x",
						got.Lo, got.Hi, tt.lo, tt.hi)
				}
			})
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func TestDigest128Reset(t *testing.T) {
	parts := []string{"The quic", "k br", "o", "wn fox jumps", " ov", "er the lazy ", "dog."}
	d := New128()
	for _, part := range parts {
		d.Write([]byte(part))
	}
	h0 := d.Sum128()

	d.Reset()
	d.Write([]byte(joinStrings(parts)))
	h1 := d.Sum128()

	if h0 != h1 {
		t.Errorf("Reset: 0x%016x%016x != 0x%016x%016x", h0.Hi, h0.Lo, h1.Hi, h1.Lo)
	}
}

func TestDigest128ResetWithSeed(t *testing.T) {
	parts := []string{"The quic", "k br", "o", "wn fox jumps", " ov", "er the lazy ", "dog."}
	d := New128WithSeed(123)
	for _, part := range parts {
		d.Write([]byte(part))
	}
	h0 := d.Sum128()

	d.ResetWithSeed(123)
	d.Write([]byte(joinStrings(parts)))
	h1 := d.Sum128()

	if h0 != h1 {
		t.Errorf("ResetWithSeed: 0x%016x%016x != 0x%016x%016x", h0.Hi, h0.Lo, h1.Hi, h1.Lo)
	}
}

func joinStrings(ss []string) string {
	var n int
	for _, s := range ss {
		n += len(s)
	}
	b := make([]byte, 0, n)
	for _, s := range ss {
		b = append(b, s...)
	}
	return string(b)
}

func TestDigest128Sum(t *testing.T) {
	d := New128()
	d.Write([]byte("abc"))
	h := d.Sum128()
	var want [16]byte
	binary.BigEndian.PutUint64(want[0:8], h.Hi)
	binary.BigEndian.PutUint64(want[8:16], h.Lo)
	got := d.Sum(nil)
	if !bytes.Equal(got, want[:]) {
		t.Fatalf("Sum: got %v; want %v", got, want)
	}
}

func TestDigest128SumAfterSum128(t *testing.T) {
	d := New128()
	d.Write([]byte("abc"))
	h0 := d.Sum128()
	// Write more and check that Sum128 didn't mutate state
	d.Write([]byte("def"))
	h1 := d.Sum128()
	expected := Sum128([]byte("abcdef"))
	if h1 != expected {
		t.Fatalf("after Sum128 + Write: got 0x%016x%016x; want 0x%016x%016x",
			h1.Hi, h1.Lo, expected.Hi, expected.Lo)
	}
	_ = h0
}

func TestDigest128RepeatedSum128(t *testing.T) {
	d := New128()
	d.Write([]byte("hello world"))
	h0 := d.Sum128()
	h1 := d.Sum128()
	if h0 != h1 {
		t.Fatalf("repeated Sum128: 0x%016x%016x != 0x%016x%016x", h0.Hi, h0.Lo, h1.Hi, h1.Lo)
	}
}

func TestDigest128RepeatedSum(t *testing.T) {
	d := New128()
	d.Write([]byte("hello world"))
	s0 := d.Sum(nil)
	s1 := d.Sum(nil)
	if !bytes.Equal(s0, s1) {
		t.Fatalf("repeated Sum: %v != %v", s0, s1)
	}
}

func TestUint128Bytes(t *testing.T) {
	u := Uint128{Hi: 0x0123456789abcdef, Lo: 0xfedcba9876543210}
	b := u.Bytes()
	var expected [16]byte
	binary.BigEndian.PutUint64(expected[0:8], 0x0123456789abcdef)
	binary.BigEndian.PutUint64(expected[8:16], 0xfedcba9876543210)
	if b != expected {
		t.Fatalf("Bytes: got %v; want %v", b, expected)
	}
}

func TestUint128String(t *testing.T) {
	u := Uint128{Hi: 0x0123456789abcdef, Lo: 0xfedcba9876543210}
	s := u.String()
	want := "0123456789abcdeffedcba9876543210"
	if s != want {
		t.Fatalf("String: got %q; want %q", s, want)
	}
}

func TestSum128StreamingMatch(t *testing.T) {
	// Test that one-shot and streaming produce identical results
	// for many lengths, seeds, and chunk sizes
	rng := rand.New(rand.NewSource(42))
	for _, length := range []int{0, 1, 2, 3, 4, 8, 9, 16, 17, 32, 64, 96, 128, 129, 200, 240, 241, 256, 300, 500, 1024, 4096} {
		for _, seed := range []uint64{0, 1, 42, 1000, math.MaxUint64} {
			data := make([]byte, length)
			rng.Read(data)

			oneShot := Sum128WithSeed(data, seed)

			// One big write
			d := New128WithSeed(seed)
			d.Write(data)
			streamBig := d.Sum128()
			if oneShot != streamBig {
				t.Fatalf("len=%d seed=%d: one-shot 0x%016x%016x != stream 0x%016x%016x",
					length, seed, oneShot.Hi, oneShot.Lo, streamBig.Hi, streamBig.Lo)
			}

			// One byte at a time
			d = New128WithSeed(seed)
			for i := 0; i < length; i++ {
				d.Write(data[i : i+1])
			}
			streamByte := d.Sum128()
			if oneShot != streamByte {
				t.Fatalf("len=%d seed=%d: one-shot 0x%016x%016x != stream-byte 0x%016x%016x",
					length, seed, oneShot.Hi, oneShot.Lo, streamByte.Hi, streamByte.Lo)
			}

			// Random chunk sizes
			d = New128WithSeed(seed)
			pos := 0
			for pos < length {
				chunk := rng.Intn(length-pos) + 1
				if pos+chunk > length {
					chunk = length - pos
				}
				d.Write(data[pos : pos+chunk])
				pos += chunk
			}
			streamRand := d.Sum128()
			if oneShot != streamRand {
				t.Fatalf("len=%d seed=%d: one-shot 0x%016x%016x != stream-rand 0x%016x%016x",
					length, seed, oneShot.Hi, oneShot.Lo, streamRand.Hi, streamRand.Lo)
			}
		}
	}
}

func TestSum128ExhaustiveSmall(t *testing.T) {
	// Test all lengths 0-256 with sequential data and multiple seeds
	for length := 0; length <= 256; length++ {
		data := seqBytes(length)
		for _, seed := range []uint64{0, 1, 42, math.MaxUint64} {
			oneShot := Sum128WithSeed(data, seed)
			d := New128WithSeed(seed)
			// Write in chunks of 7 (to cross various boundaries)
			for i := 0; i < length; i += 7 {
				end := i + 7
				if end > length {
					end = length
				}
				d.Write(data[i:end])
			}
			stream := d.Sum128()
			if oneShot != stream {
				t.Fatalf("len=%d seed=%d: one-shot 0x%016x%016x != stream 0x%016x%016x",
					length, seed, oneShot.Hi, oneShot.Lo, stream.Hi, stream.Lo)
			}
		}
	}
}

var sink128 Uint128

func TestAllocs128(t *testing.T) {
	const shortStr = "abcdefghijklmnop"
	// Sum128([]byte(shortString)) shouldn't allocate
	t.Run("Sum128", func(t *testing.T) {
		testAllocs(t, func() {
			sink128 = Sum128([]byte(shortStr))
		})
	})
	// Sum128String shouldn't allocate
	t.Run("Sum128String", func(t *testing.T) {
		testAllocs(t, func() {
			sink128 = Sum128String(shortStr)
		})
	})
	// Creating and using a Digest128 shouldn't allocate
	t.Run("Digest128", func(t *testing.T) {
		b := []byte("asdf")
		testAllocs(t, func() {
			d := New128()
			d.Write(b)
			sink128 = d.Sum128()
		})
	})
}
