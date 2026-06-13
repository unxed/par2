# unxed/par2

A highly optimized, pure-Go implementation of the PAR2 (Parchive 2.0) specification, designed for high-performance data verification and Reed-Solomon-based error recovery.

It serves as the core recovery engine for the `zipper` console archiver, allowing in-place repairs on arbitrary binary targets and multi-volume archives.

## Features
*   **Pure Go (Zero CGO):** Native cross-compilation with no external dependencies or GCC toolchain required.
*   **High Performance:** Leverages zero-copy `unsafe.Pointer` slice casting and cached Galois Field precomputations.
*   **In-Place Recovery:** Reconstructs corrupted blocks directly on any read/write target streams (`io.ReaderAt` / `io.WriterAt`).
*   **Optimized Verification:** Utilizes fast-path CRC32 pre-filtering and lazy buffer allocation to avoid heap bloat on healthy files.

## Performance & Benchmarks

The following benchmarks compare `unxed/par2` with other prominent pure-Go PAR2 libraries:
*   `github.com/akalin/gopar` (fully-functional bidirectional PAR2 codec)
*   `github.com/danielmorsing/gonzbee/par2` (lightweight read-only verifier)

### Benchmark Results (1MB Dataset)
*Measurements conducted on an Intel(R) Core(TM) i5-6300U CPU @ 2.40GHz (amd64).*

| Operation | unxed/par2 | akalin/gopar | danielmorsing/gonzbee |
| :--- | :--- | :--- | :--- |
| **Create (Generation)** | **5.05 ms** (2.12 MB, 60 allocs) | 5.35 ms (2.14 MB, 122 allocs) | *Not supported* |
| **Repair (Reconstruction)** | **10.71 ms** (2.90 MB, 120 allocs) | 11.80 ms (3.20 MB, 166 allocs) | *Not supported* |
| **Verify (Integrity)** | 2.62 ms (1.05 MB, 60 allocs) | 4.86 ms (2.15 MB, 155 allocs) | **1.80 ms** (0.17 MB, 51 allocs) |

### Performance Analysis

#### 1. Creation and Repair
`unxed/par2` outperforms `akalin/gopar` in both generation and reconstruction phases. Through the use of zero-copy slice casting and localized log-factor caches, `unxed/par2` completes repairs approximately **11% faster** while reducing the heap allocation footprint by over **27%**.

#### 2. Verification
By introducing a **two-pass lazy allocation** strategy, `unxed/par2` avoids pre-allocating buffer slices for the entire index when reading files. Instead, it streams data through a single, reused buffer and filters out undamaged blocks using hardware-accelerated CRC32 checksums before performing heavier MD5 validation.
*   This fast-path cuts verification time in half compared to `gopar` (`2.62 ms` vs `4.86 ms`).
*   `danielmorsing/gonzbee` remains slightly faster (`1.80 ms`) because it is architected solely as a lightweight, read-only fileset parser, completely omitting the Galois matrix solvers and metadata structures required for bidirectional encoding and decoding.