# Binary Fusion

Fuse two Linux ELF executables into one executable that runs both in sequence.

## Author
- Markus Stamm

## Requirements

- Linux
- Python 3.10+
- GCC
- zlib (`-lz` available to linker)
- Python package: `lief`

## Setup

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install lief
```

## Important Input Rule

`fuser.py` accepts compiled ELF binaries only.

- Valid: `sample/jules`, `sample/vincent`
- Invalid: `sample/jules.c`, `sample/vincent.c`

## Quick Start

```bash
gcc sample/jules.c -o sample/jules
gcc sample/vincent.c -o sample/vincent
python3 fuser.py sample/jules sample/vincent -o sample/fused_jv
./sample/fused_jv
```

Expected output:

```text
What do they call it?
They call it a Royale with Cheese.
```

## Build Command

```bash
python3 fuser.py <prog1_elf> <prog2_elf> -o <fused_output> [--compress] [--emit-c] [--cc gcc]
```

## Run Command

```bash
./fused_output [--out1 FILE] [--err1 FILE] [--out2 FILE] [--err2 FILE] -- [args_for_prog1] -- [args_for_prog2]
```

## Static Inputs

```bash
gcc -static sample/jules.c -o sample/jules_static
gcc -static sample/vincent.c -o sample/vincent_static
python3 fuser.py sample/jules_static sample/vincent_static -o sample/fused_static
./sample/fused_static
```
