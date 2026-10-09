#!/usr/bin/env python3
"""Generate XXH3-128 reference vectors using the official C xxHash tool.

The output file (xxh3_vectors.txt) is consumed by xxhash3_crosscheck_test.go.

Each vector has the form:
    LEN <length> seed=<seed> lo=0x<low 64 bits> hi=0x<high 64 bits>

The test data pattern matches the Go test exactly: byte((i*2654435761)>>16).
xxhsum prints the canonical 128-bit hash as a single 32-hex-digit string
where the first 16 digits are the high 64 bits and the last 16 the low 64.

Usage:
    python3 generate_vectors.py <xxhsum-path> <output-path>

The xxhsum binary can be built from https://github.com/Cyan4973/xxHash:
    make && sudo make install   # installs xxhsum
"""

import subprocess
import sys
import os
import tempfile

LENGTHS = list(range(0, 501)) + [512, 1024, 4096, 10000, 100000, 1000000]
SEEDS = [0, 1, 42, 9223372036854775807]


def data_pattern(length):
    return bytes((((i * 2654435761) & 0xFFFFFFFF) >> 16) & 0xFF
                 for i in range(length))


def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <xxhsum-path> <output-path>", file=sys.stderr)
        sys.exit(1)

    xxhsum, out_path = sys.argv[1], sys.argv[2]
    version = subprocess.run([xxhsum, "--version"], capture_output=True, text=True)
    print(f"# generated with: {version.stdout.strip()}", file=sys.stderr)

    tmpdir = tempfile.mkdtemp(prefix="xxh3vectors")
    lines = []
    for length in LENGTHS:
        data = data_pattern(length)
        path = os.path.join(tmpdir, f"d{length}")
        with open(path, "wb") as f:
            f.write(data)
        for seed in SEEDS:
            proc = subprocess.run(
                [xxhsum, "-H128", f"-s{seed}", path],
                capture_output=True, text=True,
            )
            line = proc.stdout.split("\n")[0]
            if not line:
                print(f"xxhsum failed for len={length} seed={seed}: "
                      f"{proc.stderr}", file=sys.stderr)
                sys.exit(1)
            hexhash = line.split()[0]
            assert len(hexhash) == 32, f"unexpected hash length: {hexhash}"
            lo = int(hexhash[-16:], 16)
            hi = int(hexhash[:-16], 16)
            lines.append(f"LEN {length} seed={seed} lo=0x{lo:016x} hi=0x{hi:016x}")

    with open(out_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"wrote {len(lines)} vectors to {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()