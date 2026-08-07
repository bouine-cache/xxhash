package xxhash

import (
	"strings"
	"testing"
)

var bench128Sizes = []struct {
	name string
	n    int64
}{
	{"0B", 0},
	{"4B", 4},
	{"16B", 16},
	{"64B", 64},
	{"128B", 128},
	{"240B", 240},
	{"241B", 241},
	{"1KB", 1024},
	{"4KB", 4e3},
	{"Large", 1e6},
}

func BenchmarkSum128(b *testing.B) {
	for _, bb := range bench128Sizes {
		in := make([]byte, bb.n)
		for i := range in {
			in[i] = byte(i)
		}
		b.Run(bb.name, func(b *testing.B) {
			b.SetBytes(bb.n)
			for i := 0; i < b.N; i++ {
				_ = Sum128(in)
			}
		})
	}
}

func BenchmarkSum128String(b *testing.B) {
	for _, bb := range bench128Sizes {
		s := strings.Repeat("a", int(bb.n))
		b.Run(bb.name, func(b *testing.B) {
			b.SetBytes(bb.n)
			for i := 0; i < b.N; i++ {
				_ = Sum128String(s)
			}
		})
	}
}

func BenchmarkSum128WithSeed(b *testing.B) {
	for _, bb := range bench128Sizes {
		in := make([]byte, bb.n)
		for i := range in {
			in[i] = byte(i)
		}
		b.Run(bb.name, func(b *testing.B) {
			b.SetBytes(bb.n)
			for i := 0; i < b.N; i++ {
				_ = Sum128WithSeed(in, 42)
			}
		})
	}
}

func BenchmarkDigest128(b *testing.B) {
	for _, bb := range bench128Sizes {
		in := make([]byte, bb.n)
		for i := range in {
			in[i] = byte(i)
		}
		b.Run(bb.name, func(b *testing.B) {
			b.SetBytes(bb.n)
			for i := 0; i < b.N; i++ {
				h := New128()
				h.Write(in)
				_ = h.Sum128()
			}
		})
	}
}

func BenchmarkDigest128String(b *testing.B) {
	for _, bb := range bench128Sizes {
		s := strings.Repeat("a", int(bb.n))
		b.Run(bb.name, func(b *testing.B) {
			b.SetBytes(bb.n)
			for i := 0; i < b.N; i++ {
				h := New128()
				h.WriteString(s)
				_ = h.Sum128()
			}
		})
	}
}

func BenchmarkSum128Allocs(b *testing.B) {
	in := make([]byte, 64)
	for i := range in {
		in[i] = byte(i)
	}
	b.ReportAllocs()
	b.SetBytes(64)
	for i := 0; i < b.N; i++ {
		_ = Sum128(in)
	}
}

func BenchmarkDigest128Allocs(b *testing.B) {
	in := make([]byte, 64)
	for i := range in {
		in[i] = byte(i)
	}
	b.ReportAllocs()
	b.SetBytes(64)
	for i := 0; i < b.N; i++ {
		h := New128()
		h.Write(in)
		_ = h.Sum128()
	}
}
