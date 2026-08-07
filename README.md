# xxhash

[![Go Reference](https://pkg.go.dev/badge/github.com/cespare/xxhash/v2.svg)](https://pkg.go.dev/github.com/cespare/xxhash/v2)
[![Test](https://github.com/cespare/xxhash/actions/workflows/test.yml/badge.svg)](https://github.com/cespare/xxhash/actions/workflows/test.yml)

xxhash is a Go implementation of the 64-bit [xxHash] algorithm, XXH64, and the
128-bit XXH3 algorithm (also called XXH128). These are high-quality hashing
algorithms that are much faster than anything in the Go standard library.

## XXH64

This package provides a straightforward API for the 64-bit XXH64 algorithm:

```
func Sum64(b []byte) uint64
func Sum64String(s string) uint64
type Digest struct{ ... }
    func New() *Digest
```

The `Digest` type implements hash.Hash64. Its key methods are:

```
func (*Digest) Write([]byte) (int, error)
func (*Digest) WriteString(string) (int, error)
func (*Digest) Sum64() uint64
```

## XXH3-128 (XXH128)

The package also implements the 128-bit XXH3 algorithm, known as XXH128.
XXH3 is a different algorithm from XXH64; it is not two XXH64 hashes
concatenated together. XXH3-128 produces a 128-bit result and is designed
for high-quality, high-speed non-cryptographic hashing.

### Result type

The 128-bit result is returned as a `Uint128`:

```go
type Uint128 struct {
    Hi uint64 // high 64 bits
    Lo uint64 // low 64 bits
}
```

The mathematical value is `Hi << 64 | Lo`.

The canonical 16-byte serialization (used by `Sum` and `Bytes`) places the
high 64 bits first, followed by the low 64 bits, each in big-endian byte
order. This matches the official XXH128 canonical representation.

### One-shot API

```go
func Sum128(b []byte) Uint128
func Sum128String(s string) Uint128
func Sum128WithSeed(b []byte, seed uint64) Uint128
func Sum128StringWithSeed(s string, seed uint64) Uint128
```

Example:

```go
h := xxhash.Sum128([]byte("hello world"))
fmt.Printf("%x\n", h) // hex: high bits first, then low bits
```

### Streaming API

```go
type Digest128 struct{ ... }

func New128() *Digest128
func New128WithSeed(seed uint64) *Digest128

func (d *Digest128) Reset()
func (d *Digest128) ResetWithSeed(seed uint64)

func (d *Digest128) Write(b []byte) (int, error)
func (d *Digest128) WriteString(s string) (int, error)

func (d *Digest128) Sum128() Uint128
func (d *Digest128) Sum(b []byte) []byte

func (d *Digest128) Size() int        // always 16
func (d *Digest128) BlockSize() int   // always 64
```

`Digest128` does not implement `hash.Hash` because that interface requires
a 32-bit `Sum` method. Use `Sum128` to obtain the 128-bit result.

Example:

```go
d := xxhash.New128()
d.Write([]byte("hello "))
d.Write([]byte("world"))
h := d.Sum128()
fmt.Printf("%x\n", h)
```

### Seed semantics

The seed is a 64-bit value that modifies the hash output. For inputs of 240
bytes or fewer, the seed is incorporated directly into the short-input
branches. For inputs longer than 240 bytes, a custom secret is derived from
the seed by adding/subtracting it from the default secret words.

When the seed is 0, the default secret is used directly. Custom secrets are
not supported.

### Serialization

The `Uint128.Bytes()` method returns a `[16]byte` array in canonical
big-endian form (high 64 bits first). The `Digest128.Sum` method appends
this canonical representation to the provided byte slice.

The `Uint128.String()` method returns a 32-character hexadecimal string
with the high 64 bits printed first, followed by the low 64 bits.

## Portability and performance

The XXH64 implementation includes optimized assembly for amd64 and arm64.
The `purego` build tag opts into using the Go code even on those
architectures.

The XXH3-128 implementation is pure Go with no architecture-specific code.
It uses `math/bits.Mul64` for 64x64-to-128 multiplication. It is
dependency-free and does not use cgo.

One-shot hashing (`Sum128`, `Sum128String`) does not allocate. Streaming
with `Digest128` also does not allocate for normal use.

## Non-cryptographic

xxHash is a non-cryptographic hash function. It must not be used for
password hashing, digital signatures, authentication, or any adversarial
security boundary. It is designed for speed and quality, not security.

## Compatibility

This package is in a module and the latest code is in version 2 of the module.
You need a version of Go with at least "minimal module compatibility" to use
github.com/cespare/xxhash/v2:

* 1.9.7+ for Go 1.9
* 1.10.3+ for Go 1.10
* Go 1.11 or later

I recommend using the latest release of Go.

## Benchmarks

Here are some quick benchmarks comparing the pure-Go and assembly
implementations of Sum64.

| input size | purego    | asm       |
| ---------- | --------- | --------- |
| 4 B        |  1.3 GB/s |  1.2 GB/s |
| 16 B       |  2.9 GB/s |  3.5 GB/s |
| 100 B      |  6.9 GB/s |  8.1 GB/s |
| 4 KB       | 11.7 GB/s | 16.7 GB/s |
| 10 MB      | 12.0 GB/s | 17.3 GB/s |

These numbers were generated on Ubuntu 20.04 with an Intel Xeon Platinum 8252C
CPU using the following commands under Go 1.19.2:

```
benchstat <(go test -tags purego -benchtime 500ms -count 15 -bench 'Sum64$')
benchstat <(go test -benchtime 500ms -count 15 -bench 'Sum64$')
```

## Projects using this package

- [InfluxDB](https://github.com/influxdata/influxdb)
- [Prometheus](https://github.com/prometheus/prometheus)
- [VictoriaMetrics](https://github.com/VictoriaMetrics/VictoriaMetrics)
- [FreeCache](https://github.com/coocood/freecache)
- [FastCache](https://github.com/VictoriaMetrics/fastcache)
- [Ristretto](https://github.com/dgraph-io/ristretto)
- [Badger](https://github.com/dgraph-io/badger)
