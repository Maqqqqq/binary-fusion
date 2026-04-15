#!/usr/bin/env python3
"""
Binary Fusion — ELF fuser (with optional compression)
- Validates two ELF binaries (class/arch/type) using LIEF
- Prints key ELF header fields for both inputs
- Generates a C launcher with a single concatenated payload blob
- Uses a custom startup entry stub (_start) to drive execution flow
- CRC32 integrity check (of original bytes)
- Per-program stdout/stderr redirection and argument passing
- Produces fused ELF

Usage:
  python3 fuser.py ./prog1 ./prog2 -o fused_prog [--emit-c] [--cc gcc] [--compress]

Runtime:
  ./fused_prog [--out1 f1] [--err1 e1] [--out2 f2] [--err2 e2] -- [args1] -- [args2]
"""
import argparse
import subprocess
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path

try:
    import lief
except Exception:
    print("[!] LIEF required. Install: pip install lief", file=sys.stderr)
    sys.exit(1)

# ====== Launcher Template ======
LAUNCHER_TEMPLATE = r"""
// Fused launcher (supports optional zlib decompression)
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

extern char **environ;

static const unsigned char BLOB[] = {{ {blob_bytes} }};
// Concatenated alloc sections from both inputs, grouped by permissions.
// .text.* => executable, .rodata.* => read-only, .data.* => writable.
__attribute__((used, section(".text.fused_rx"), aligned(16)))
static const unsigned char FUSED_RX_SECTIONS[] = {{ {fused_rx_bytes} }};

__attribute__((used, section(".rodata.fused_r"), aligned(16)))
static const unsigned char FUSED_R_SECTIONS[] = {{ {fused_r_bytes} }};

__attribute__((used, section(".data.fused_rw"), aligned(16)))
static unsigned char FUSED_RW_SECTIONS[] = {{ {fused_rw_bytes} }};

static const size_t PROG1_OFF = {prog1_off}UL;
static const size_t PROG1_LEN = {prog1_len}UL;
static const size_t PROG1_RAWLEN = {prog1_rawlen}UL;
static const unsigned int PROG1_MODE = {prog1_mode}U;

static const size_t PROG2_OFF = {prog2_off}UL;
static const size_t PROG2_LEN = {prog2_len}UL;
static const size_t PROG2_RAWLEN = {prog2_rawlen}UL;
static const unsigned int PROG2_MODE = {prog2_mode}U;

static const unsigned long PROG1_CRC32 = {prog1_crc32}UL;
static const unsigned long PROG2_CRC32 = {prog2_crc32}UL;

static const int USE_COMPRESS = {use_compress};

// --- zlib decompression path ---
#include <assert.h>
#include <limits.h>

#include <zlib.h>

static unsigned long crc32_custom(const void *data, size_t n_bytes) {{
    static uint32_t table[256];
    static int have_table = 0;
    uint32_t crc = 0xFFFFFFFFu;
    if (!have_table) {{
        for (uint32_t i = 0; i < 256; i++) {{
            uint32_t rem = i;
            for (int j = 0; j < 8; j++) {{
                if (rem & 1) rem = (rem >> 1) ^ 0xEDB88320u;
                else rem >>= 1;
            }}
            table[i] = rem;
        }}
        have_table = 1;
    }}
    const unsigned char *p = (const unsigned char*)data;
    for (size_t i = 0; i < n_bytes; i++) {{
        crc = (crc >> 8) ^ table[(crc ^ p[i]) & 0xFFu];
    }}
    return ~crc;
}}

static unsigned char* maybe_decompress(const unsigned char* data, size_t len, size_t rawlen) {{
    if (!USE_COMPRESS) {{
        unsigned char* out = malloc(len);
        memcpy(out, data, len);
        return out;
    }}
    unsigned char* out = malloc(rawlen);
    if (!out) return NULL;
    uLongf destLen = rawlen;
    if (uncompress(out, &destLen, data, len) != Z_OK || destLen != rawlen) {{
        fprintf(stderr, "[!] Decompression failed\\n");
        free(out);
        return NULL;
    }}
    return out;
}}

static int create_memfd(const char *name) {{
#ifdef SYS_memfd_create
    int mfd = (int)syscall(SYS_memfd_create, name, MFD_CLOEXEC);
    if (mfd >= 0) return mfd;
#endif
    char tmpl[] = "/tmp/fused_XXXXXX";
    int tfd = mkstemp(tmpl);
    if (tfd >= 0) {{ unlink(tmpl); }}
    return tfd;
}}

static int write_payload_to_fd(int fd, const unsigned char* data, size_t len) {{
    size_t off = 0;
    while (off < len) {{
        ssize_t w = write(fd, data + off, len - off);
        if (w < 0) return -1;
        off += (size_t)w;
    }}
    return 0;
}}

static int exec_from_fd(int fd, unsigned int mode, char *const argv[]) {{
    unsigned int out_mode = mode & 0777U;
    if (!(out_mode & 0111U)) out_mode |= 0100U;
    if (fchmod(fd, (mode_t)out_mode) < 0) {{ perror("fchmod"); return -1; }}
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    pid_t pid = fork();
    if (pid < 0) {{ perror("fork"); return -1; }}
    if (pid == 0) {{
        execve(path, argv, environ);
        perror("execve");
        _exit(127);
    }}
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {{ perror("waitpid"); return -1; }}
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return -1;
}}

static int redirect_fd_to_file(int fd, const char* path, int flags, mode_t mode) {{
    if (!path) return 0;
    int newfd = open(path, flags, mode);
    if (newfd < 0) {{ perror("open redirect"); return -1; }}
    if (dup2(newfd, fd) < 0) {{ perror("dup2 redirect"); close(newfd); return -1; }}
    close(newfd);
    return 0;
}}

int fused_main(int argc, char** argv) {{
    const char* out1=NULL,*err1=NULL,*out2=NULL,*err2=NULL;
    int i=1, phase=0;
    const char* p1args[64]; int p1c=0; p1args[p1c++]="prog1";
    const char* p2args[64]; int p2c=0; p2args[p2c++]="prog2";

    while (i < argc) {{
        if (!strcmp(argv[i],"--")) {{ phase++; i++; continue; }}
        if (phase==0) {{
            if (!strcmp(argv[i],"--out1") && i+1<argc) {{ out1=argv[++i]; i++; continue; }}
            if (!strcmp(argv[i],"--err1") && i+1<argc) {{ err1=argv[++i]; i++; continue; }}
            if (!strcmp(argv[i],"--out2") && i+1<argc) {{ out2=argv[++i]; i++; continue; }}
            if (!strcmp(argv[i],"--err2") && i+1<argc) {{ err2=argv[++i]; i++; continue; }}
            i++; continue;
        }} else if (phase==1) {{
            if (p1c<63) p1args[p1c++]=argv[i]; i++;
        }} else {{
            if (p2c<63) p2args[p2c++]=argv[i]; i++;
        }}
    }}
    p1args[p1c]=NULL; p2args[p2c]=NULL;

    const unsigned char* p1 = BLOB + PROG1_OFF;
    const unsigned char* p2 = BLOB + PROG2_OFF;
    unsigned char* raw1 = maybe_decompress(p1, PROG1_LEN, PROG1_RAWLEN);
    unsigned char* raw2 = maybe_decompress(p2, PROG2_LEN, PROG2_RAWLEN);
    if (!raw1||!raw2) return 201;

    if (crc32_custom(raw1, PROG1_RAWLEN) != PROG1_CRC32) {{
        fprintf(stderr,"[!] PROG1 CRC mismatch\\n"); return 202;
    }}
    if (crc32_custom(raw2, PROG2_RAWLEN) != PROG2_CRC32) {{
        fprintf(stderr,"[!] PROG2 CRC mismatch\\n"); return 203;
    }}

    int fd1=create_memfd("prog1"), fd2=create_memfd("prog2");
    if (fd1<0||fd2<0) {{ perror("memfd"); return 210; }}
    if (write_payload_to_fd(fd1, raw1, PROG1_RAWLEN)<0) {{ perror("write1"); return 211; }}
    if (write_payload_to_fd(fd2, raw2, PROG2_RAWLEN)<0) {{ perror("write2"); return 212; }}
    free(raw1); free(raw2);

    int saved_out=dup(STDOUT_FILENO), saved_err=dup(STDERR_FILENO);
    if (out1&&redirect_fd_to_file(STDOUT_FILENO,out1,O_CREAT|O_WRONLY|O_TRUNC,0644)<0) return 220;
    if (err1&&redirect_fd_to_file(STDERR_FILENO,err1,O_CREAT|O_WRONLY|O_TRUNC,0644)<0) return 221;
    int status1=exec_from_fd(fd1,PROG1_MODE,(char* const*)p1args);
    if (saved_out>=0){{dup2(saved_out,STDOUT_FILENO);close(saved_out);}}
    if (saved_err>=0){{dup2(saved_err,STDERR_FILENO);close(saved_err);}}

    saved_out=dup(STDOUT_FILENO); saved_err=dup(STDERR_FILENO);
    if (out2&&redirect_fd_to_file(STDOUT_FILENO,out2,O_CREAT|O_WRONLY|O_TRUNC,0644)<0) return 222;
    if (err2&&redirect_fd_to_file(STDERR_FILENO,err2,O_CREAT|O_WRONLY|O_TRUNC,0644)<0) return 223;
    int status2=exec_from_fd(fd2,PROG2_MODE,(char* const*)p2args);
    if (saved_out>=0){{dup2(saved_out,STDOUT_FILENO);close(saved_out);}}
    if (saved_err>=0){{dup2(saved_err,STDERR_FILENO);close(saved_err);}}

    return status2?status2:status1;
}}
"""

STARTUP_ASM_TEMPLATE_64 = r"""
    .text
    .globl _start
    .type _start, @function
_start:
    xor %ebp, %ebp
    mov %rdx, %r9
    pop %rsi
    mov %rsp, %rdx
    andq $-16, %rsp
    push %rax
    push %rsp
    xor %r8d, %r8d
    xor %ecx, %ecx
    lea fused_main(%rip), %rdi
    call __libc_start_main@PLT
    hlt
    .section .note.GNU-stack,"",@progbits
"""

STARTUP_ASM_TEMPLATE_32 = r"""
    .text
    .globl _start
    .type _start, @function
_start:
    xorl %ebp, %ebp
    popl %esi
    movl %esp, %ecx
    andl $-16, %esp
    pushl %eax
    pushl %esp
    pushl %edx
    pushl $0
    pushl $0
    pushl %ecx
    pushl %esi
    pushl $fused_main
    call __libc_start_main@PLT
    hlt
    .section .note.GNU-stack,"",@progbits
"""

# ===== Helpers =====
@dataclass(frozen=True)
class ElfInfo:
    path: str
    elf_class: str
    machine: str
    file_type: str


def bytes_to_c_array(b: bytes, wrap=12):
    hexes = [f"0x{bb:02x}" for bb in b]
    return ",\n  ".join(", ".join(hexes[i:i+wrap]) for i in range(0, len(hexes), wrap))

def bytes_to_c_array_nonempty(b: bytes):
    # Empty brace-init is not valid in strict C; keep a 1-byte sentinel.
    if not b:
        return "0x00"
    return bytes_to_c_array(b)

def pack_payloads(data1: bytes, data2: bytes, align=1):
    def align_up(n, a):
        return (n + (a - 1)) // a * a

    off1 = 0
    off2 = align_up(len(data1), align)
    pad = off2 - len(data1)
    blob = data1 + (b"\x00" * pad) + data2
    return blob, off1, len(data1), off2, len(data2), pad

def has_flag(value: int, enum_member):
    try:
        return (value & int(enum_member)) != 0
    except Exception:
        try:
            return (value & int(enum_member.value)) != 0
        except Exception:
            return False

def classify_perm(section):
    flags = int(section.flags)
    exec_flag = has_flag(flags, lief.ELF.Section.FLAGS.EXECINSTR)
    write_flag = has_flag(flags, lief.ELF.Section.FLAGS.WRITE)
    if exec_flag:
        return "rx"
    if write_flag:
        return "rw"
    return "r"

def collect_alloc_sections(path: Path, prefix: str):
    parsed = lief.parse(str(path))
    out = []
    for s in parsed.sections:
        # Keep allocated sections with real bytes to support concatenation.
        if not s.size or not s.content:
            continue
        flags = int(s.flags)
        if not has_flag(flags, lief.ELF.Section.FLAGS.ALLOC):
            continue
        align = int(s.alignment) if int(s.alignment) > 0 else 1
        out.append({
            "src": prefix,
            "name": s.name,
            "perm": classify_perm(s),
            "align": align,
            "data": bytes(s.content),
            "size": len(s.content),
        })
    return out

def pack_section_group(items, optimize=True):
    # Alignment-aware packing: highest alignment first to reduce internal padding.
    ordered = sorted(items, key=lambda x: x["align"], reverse=True) if optimize else list(items)
    blob = bytearray()
    layout = []
    total_padding = 0
    for it in ordered:
        align = max(1, it["align"])
        pad = (align - (len(blob) % align)) % align
        if pad:
            blob.extend(b"\x00" * pad)
            total_padding += pad
        off = len(blob)
        blob.extend(it["data"])
        layout.append({
            "src": it["src"],
            "name": it["name"],
            "perm": it["perm"],
            "align": align,
            "offset": off,
            "size": it["size"],
            "pad_before": pad,
        })
    return bytes(blob), layout, total_padding

def elf_info(path: Path):
    parsed = lief.parse(str(path))
    if parsed is None:
        return None
    hdr = parsed.header
    return ElfInfo(
        path=str(path),
        elf_class=hdr.identity_class.name,
        machine=hdr.machine_type.name,
        file_type=hdr.file_type.name,
    )

def file_type_desc(file_type: str):
    kind = {
        "EXEC": "executable file",
        "DYN": "shared object / PIE executable",
        "REL": "relocatable object file",
    }
    return kind.get(file_type, "unsupported/unknown ELF type")

def is_likely_source(path: Path):
    return path.suffix.lower() in {".c", ".cc", ".cpp", ".cxx", ".c++"}

def build_config(elf_class: str, machine: str):
    if machine != "X86_64":
        raise ValueError(f"unsupported architecture for launcher generation: {machine}")
    if elf_class == "ELF64":
        return {
            "cflags": ["-m64"],
            "startup_asm": STARTUP_ASM_TEMPLATE_64,
        }
    if elf_class == "ELF32":
        return {
            "cflags": ["-m32"],
            "startup_asm": STARTUP_ASM_TEMPLATE_32,
        }
    raise ValueError(f"unsupported ELF class: {elf_class}")


def choose_best_layout(items):
    optimized = pack_section_group(items, optimize=True)
    baseline = pack_section_group(items, optimize=False)
    return optimized if optimized[2] <= baseline[2] else baseline, baseline[2]


def validate_inputs(p1: Path, p2: Path):
    info1 = elf_info(p1)
    info2 = elf_info(p2)
    print("[*] ELF1:", info1)
    print("[*] ELF2:", info2)

    if info1 is None or info2 is None:
        bad = [path for path, info in ((p1, info1), (p2, info2)) if info is None]
        print("[!] Non-ELF input detected. fuser.py expects compiled executables, not source files.", file=sys.stderr)
        for path in bad:
            if is_likely_source(path):
                print(f"    compile hint: gcc {path} -o {path.with_suffix('')}", file=sys.stderr)
            else:
                print(f"    invalid ELF: {path}", file=sys.stderr)
        sys.exit(3)

    for label, info in (("ELF1", info1), ("ELF2", info2)):
        print(f"[*] {label} type detail: {info.file_type} ({file_type_desc(info.file_type)})")

    allowed_types = {"EXEC", "DYN"}
    bad_type = [(path, info.file_type) for path, info in ((p1, info1), (p2, info2)) if info.file_type not in allowed_types]
    if bad_type:
        print("[!] Unsupported ELF file type for fusion.", file=sys.stderr)
        print("    Supported types: EXEC, DYN", file=sys.stderr)
        for path, file_type in bad_type:
            print(f"    {path}: {file_type} ({file_type_desc(file_type)})", file=sys.stderr)
        sys.exit(6)

    if info1.machine != info2.machine:
        print(f"[!] Architecture mismatch: {p1}={info1.machine} vs {p2}={info2.machine}", file=sys.stderr)
        sys.exit(4)
    if info1.elf_class != info2.elf_class:
        print(f"[!] ELF class mismatch: {p1}={info1.elf_class} vs {p2}={info2.elf_class}", file=sys.stderr)
        sys.exit(5)

    return info1, info2


def summarize_merged_sections(p1: Path, p2: Path):
    merged_sections = collect_alloc_sections(p1, "prog1") + collect_alloc_sections(p2, "prog2")
    groups = {
        "rx": [section for section in merged_sections if section["perm"] == "rx"],
        "r": [section for section in merged_sections if section["perm"] == "r"],
        "rw": [section for section in merged_sections if section["perm"] == "rw"],
    }

    layouts = {}
    optimized_total_padding = 0
    baseline_total_padding = 0
    for name, items in groups.items():
        (packed, layout, padding), baseline_padding = choose_best_layout(items)
        layouts[name] = (packed, layout, padding)
        optimized_total_padding += padding
        baseline_total_padding += baseline_padding

    print(
        "[*] Merged alloc sections:",
        f"rx={len(layouts['rx'][1])} (pad={layouts['rx'][2]}),",
        f"r={len(layouts['r'][1])} (pad={layouts['r'][2]}),",
        f"rw={len(layouts['rw'][1])} (pad={layouts['rw'][2]})",
    )
    print(
        f"[*] Layout optimization: baseline_pad={baseline_total_padding}, "
        f"optimized_pad={optimized_total_padding}, saved={baseline_total_padding - optimized_total_padding}"
    )
    return layouts


def prepare_payload(path: Path, compress: bool):
    raw = path.read_bytes()
    packed = zlib.compress(raw, 9) if compress else raw
    return {
        "raw": raw,
        "packed": packed,
        "mode": path.stat().st_mode & 0o777,
        "crc32": zlib.crc32(raw) & 0xFFFFFFFF,
    }


def write_sources(cpath: Path, spath: Path, csrc: str, startup_asm: str):
    cpath.write_text(csrc)
    spath.write_text(startup_asm)


def cleanup_sources(*paths: Path):
    for path in paths:
        try:
            path.unlink()
        except OSError:
            pass

# ===== Main =====
def main():
    ap = argparse.ArgumentParser(description="Fuse two ELF executables")
    ap.add_argument("prog1")
    ap.add_argument("prog2")
    ap.add_argument("-o", "--output", default=None)
    ap.add_argument("--emit-c", action="store_true")
    ap.add_argument("--cc", default="gcc")
    ap.add_argument("--compress", action="store_true")
    args = ap.parse_args()

    p1, p2 = Path(args.prog1), Path(args.prog2)
    if not p1.exists() or not p2.exists():
        print("[!] missing input", file=sys.stderr)
        sys.exit(2)

    info1, _ = validate_inputs(p1, p2)
    layouts = summarize_merged_sections(p1, p2)

    payload1 = prepare_payload(p1, args.compress)
    payload2 = prepare_payload(p2, args.compress)
    blob, off1, _, off2, _, pad = pack_payloads(payload1["packed"], payload2["packed"], align=1)
    print(f"[*] Packed payload blob: total={len(blob)} bytes, pad_between={pad} bytes")

    out_name = args.output or f"fused_{p1.stem}"
    out_path = Path(out_name)

    csrc = LAUNCHER_TEMPLATE.format(
        blob_bytes=bytes_to_c_array(blob),
        fused_rx_bytes=bytes_to_c_array_nonempty(layouts["rx"][0]),
        fused_r_bytes=bytes_to_c_array_nonempty(layouts["r"][0]),
        fused_rw_bytes=bytes_to_c_array_nonempty(layouts["rw"][0]),
        prog1_off=off1,
        prog1_len=len(payload1["packed"]),
        prog1_rawlen=len(payload1["raw"]),
        prog1_mode=payload1["mode"],
        prog2_off=off2,
        prog2_len=len(payload2["packed"]),
        prog2_rawlen=len(payload2["raw"]),
        prog2_mode=payload2["mode"],
        prog1_crc32=payload1["crc32"],
        prog2_crc32=payload2["crc32"],
        use_compress=1 if args.compress else 0,
    )
    try:
        cfg = build_config(info1.elf_class, info1.machine)
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        sys.exit(7)

    cpath = out_path.with_suffix(".c")
    spath = out_path.with_suffix(".S")
    write_sources(cpath, spath, csrc, cfg["startup_asm"])

    cmd = [args.cc, *cfg["cflags"], "-O2", "-nostartfiles", str(spath), str(cpath), "-o", str(out_path), "-lz"]
    print("[*] Compiling:", " ".join(cmd))
    subprocess.check_call(cmd)

    if not args.emit_c:
        cleanup_sources(cpath, spath)
    print("-> fused:", out_path)

if __name__ == "__main__":
    main()
