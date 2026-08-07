module github.com/bouine-cache/xxhash/xxhashbench

go 1.13

require (
	github.com/OneOfOne/xxhash v1.2.5
	github.com/bouine-cache/xxhash/v3 v3.0.0-00010101000000-000000000000
	github.com/spaolacci/murmur3 v1.1.0
)

replace github.com/bouine-cache/xxhash/v3 => ../
