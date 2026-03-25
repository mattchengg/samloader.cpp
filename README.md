# samloader.cpp

Download firmware for Samsung devices from official Samsung servers.

## Build

Requirements:
- CMake 3.16+
- libcurl
- OpenSSL

```
cmake -S . -B build
cmake --build build -j
```

Run:

```
./build/samloader <check|download> [args...]
```

## CLI

- `check`
- `download`

Usage:

```
samloader --model <MODEL> --region <REGION> [--threads <THREADS>] <check|download>

Commands:
  check                             Check the latest firmware version
  download                          Download the latest firmware

Global options:
  -m, --model <MODEL>               Device model (e.g. SM-S931U1)
  -r, --region <REGION>             Region CSC code (e.g. XAA)
  -j, --threads <THREADS>           Number of parallel connections (default: 8)

Download options:
  -O, --out_dir <OUT_DIR>           Output directory
  -o, --out-file <OUT_FILE>         Output file path/name (out_file)
```
