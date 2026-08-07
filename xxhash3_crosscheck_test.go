package xxhash

import (
	"bufio"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestSum128CrossCheck reads vectors generated from the official C implementation
// and verifies that our Go implementation matches for all lengths 0-500 and
// multiple seeds.
func TestSum128CrossCheck(t *testing.T) {
	f, err := os.Open("/tmp/vectors2.txt")
	if err != nil {
		t.Skipf("vectors2.txt not available: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	type vector struct {
		length int
		seed   uint64
		lo     uint64
		hi     uint64
	}

	var vectors []vector
	for scanner.Scan() {
		line := scanner.Text()
		// Format: "LEN <len> seed=<seed> lo=0x<hex> hi=0x<hex>"
		parts := strings.Fields(line)
		if len(parts) != 5 || parts[0] != "LEN" {
			continue
		}
		length, err := strconv.Atoi(parts[1])
		if err != nil {
			continue
		}
		seedStr := strings.TrimPrefix(parts[2], "seed=")
		seed, err := strconv.ParseUint(seedStr, 10, 64)
		if err != nil {
			// Handle "max" as MaxUint64
			if seedStr == "max" {
				seed = math.MaxUint64
			} else {
				continue
			}
		}
		loStr := strings.TrimPrefix(parts[3], "lo=0x")
		lo, err := strconv.ParseUint(loStr, 16, 64)
		if err != nil {
			continue
		}
		hiStr := strings.TrimPrefix(parts[4], "hi=0x")
		hi, err := strconv.ParseUint(hiStr, 16, 64)
		if err != nil {
			continue
		}
		vectors = append(vectors, vector{length, seed, lo, hi})
	}

	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner error: %v", err)
	}

	if len(vectors) == 0 {
		t.Skip("no vectors found")
	}

	for _, v := range vectors {
		data := make([]byte, v.length)
		for i := 0; i < v.length; i++ {
			x := uint32(i) * 2654435761
			data[i] = byte(x >> 16)
		}
		got := Sum128WithSeed(data, v.seed)
		if got.Lo != v.lo || got.Hi != v.hi {
			t.Fatalf("len=%d seed=%d: got lo=0x%016x hi=0x%016x; want lo=0x%016x hi=0x%016x",
				v.length, v.seed, got.Lo, got.Hi, v.lo, v.hi)
		}
	}
}