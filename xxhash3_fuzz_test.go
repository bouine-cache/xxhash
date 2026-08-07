package xxhash

import (
	"encoding/binary"
	"math"
	"math/rand"
	"testing"
)

func FuzzSum128Consistency(f *testing.F) {
	// Seed corpus with various lengths
	f.Add([]byte(""), uint64(0))
	f.Add([]byte("a"), uint64(0))
	f.Add([]byte("abcd"), uint64(0))
	f.Add([]byte("abcdefghijklmnop"), uint64(0))
	f.Add(make([]byte, 240), uint64(0))
	f.Add(make([]byte, 241), uint64(0))
	f.Add(make([]byte, 1024), uint64(0))
	f.Add([]byte("test"), uint64(42))
	f.Add([]byte("test"), uint64(math.MaxUint64))

	f.Fuzz(func(t *testing.T, data []byte, seed uint64) {
		// One-shot
		oneShot := Sum128WithSeed(data, seed)

		// Streaming with one big write
		d := New128WithSeed(seed)
		d.Write(data)
		stream := d.Sum128()
		if oneShot != stream {
			t.Fatalf("one-shot 0x%016x%016x != stream 0x%016x%016x (len=%d seed=%d)",
				oneShot.Hi, oneShot.Lo, stream.Hi, stream.Lo, len(data), seed)
		}

		// Streaming with one-byte writes
		d = New128WithSeed(seed)
		for i := 0; i < len(data); i++ {
			d.Write(data[i : i+1])
		}
		streamByte := d.Sum128()
		if oneShot != streamByte {
			t.Fatalf("one-shot 0x%016x%016x != stream-byte 0x%016x%016x (len=%d seed=%d)",
				oneShot.Hi, oneShot.Lo, streamByte.Hi, streamByte.Lo, len(data), seed)
		}

		// Streaming with random chunk sizes
		rng := rand.New(rand.NewSource(int64(seed)))
		d = New128WithSeed(seed)
		pos := 0
		for pos < len(data) {
			chunk := rng.Intn(len(data)-pos) + 1
			if pos+chunk > len(data) {
				chunk = len(data) - pos
			}
			d.Write(data[pos : pos+chunk])
			pos += chunk
		}
		streamRand := d.Sum128()
		if oneShot != streamRand {
			t.Fatalf("one-shot 0x%016x%016x != stream-rand 0x%016x%016x (len=%d seed=%d)",
				oneShot.Hi, oneShot.Lo, streamRand.Hi, streamRand.Lo, len(data), seed)
		}

		// Determinism: same input should always produce same output
		oneShot2 := Sum128WithSeed(data, seed)
		if oneShot != oneShot2 {
			t.Fatalf("non-deterministic: 0x%016x%016x != 0x%016x%016x",
				oneShot.Hi, oneShot.Lo, oneShot2.Hi, oneShot2.Lo)
		}

		// Sum should match Sum128 in canonical form
		d = New128WithSeed(seed)
		d.Write(data)
		h := d.Sum128()
		var want [16]byte
		binary.BigEndian.PutUint64(want[0:8], h.Hi)
		binary.BigEndian.PutUint64(want[8:16], h.Lo)
		got := d.Sum(nil)
		if len(got) != 16 {
			t.Fatalf("Sum length: got %d; want 16", len(got))
		}
		var gotBytes [16]byte
		copy(gotBytes[:], got)
		if gotBytes != want {
			t.Fatalf("Sum: got %v; want %v", gotBytes, want)
		}
	})
}

func FuzzSum128NoPanic(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("a"))
	f.Add(make([]byte, 1024))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should never panic
		_ = Sum128(data)
		_ = Sum128WithSeed(data, 0)
		_ = Sum128WithSeed(data, 1)
		_ = Sum128WithSeed(data, math.MaxUint64)

		d := New128()
		d.Write(data)
		_ = d.Sum128()
		_ = d.Sum(nil)

		// Continue writing after Sum128
		d.Write(data)
		_ = d.Sum128()
	})
}

func FuzzSum128Mutation(f *testing.F) {
	f.Add([]byte("test data for mutation"), uint64(0))

	f.Fuzz(func(t *testing.T, data []byte, seed uint64) {
		if len(data) == 0 {
			return
		}
		h0 := Sum128WithSeed(data, seed)

		// Flip one bit in the input
		mutated := make([]byte, len(data))
		copy(mutated, data)
		mutated[0] ^= 1
		h1 := Sum128WithSeed(mutated, seed)

		// The hash should change for a non-empty input mutation
		if h0 == h1 {
			t.Fatalf("hash did not change after flipping bit 0 (len=%d seed=%d)",
				len(data), seed)
		}
	})
}
