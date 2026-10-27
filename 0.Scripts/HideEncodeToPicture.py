#!/usr/bin/env python3
"""
fib_stego.py - Fibonacci-position steganography for CTF challenges.

Each byte of the payload is stored in ONE pixel. The pixels used are the
Fibonacci numbers taken as indices into the flattened pixel array (row-major):

    byte[0] -> pixel 1
    byte[1] -> pixel 2
    byte[2] -> pixel 3
    byte[3] -> pixel 5
    byte[4] -> pixel 8   ... and so on

The 8 bits of each byte are split 3/3/2 over the low bits of R, G and B, so a
whole byte fits in one pixel and adjacent Fibonacci positions never overlap.
A 0x00 terminator marks the end of the message.

WRAPPING
    Fibonacci grows exponentially, so F(n) runs past the end of the image after
    ~30 bytes. Positions are therefore always reduced modulo the pixel count:

        pos = F(n) mod (width * height)

    While F(n) < total pixels this is a no-op, so short flags are unaffected.
    Once it wraps, two Fibonacci numbers can hit the same pixel; collisions are
    resolved by linear probing forward to the next free pixel. The probe order
    depends only on the bytes already placed, so the decoder reproduces the same
    sequence without knowing the payload length in advance.

Usage:
    python3 fib_stego.py embed   cover.png flag.txt -o challenge.png
    python3 fib_stego.py extract challenge.png
    python3 fib_stego.py extract challenge.png -o recovered.bin --hex
    python3 fib_stego.py capacity cover.png
"""

import argparse
import sys

import numpy as np
from PIL import Image

# Bits taken from each channel: R holds bits 7-5, G holds 4-2, B holds 1-0.
R_BITS, G_BITS, B_BITS = 3, 3, 2
TERMINATOR = 0x00


def fib_stream(limit):
    """Yield (index, pixel, wrapped, probed) forever, modulo `limit`.

    `wrapped` is True once the raw Fibonacci number has exceeded the image.
    `probed` is True when a collision forced a shift to a neighbouring pixel.
    """
    used = set()
    a, b = 1 % limit, 2 % limit
    raw_a, raw_b = 1, 2          # exact values, tracked only until they wrap
    exact = True
    idx = 0

    while True:
        if exact and raw_a >= limit:
            exact = False
        pos = a
        probed = False
        while pos in used:
            pos = (pos + 1) % limit
            probed = True
        used.add(pos)
        yield idx, pos, not exact, probed

        a, b = b, (a + b) % limit
        if exact:
            raw_a, raw_b = raw_b, raw_a + raw_b
        idx += 1


def fib_positions(count, limit):
    """First `count` pixel positions, plus wrap/collision statistics."""
    if count > limit:
        raise ValueError(
            f"Payload of {count} bytes cannot fit: the image has only {limit} "
            f"pixels and each byte needs its own pixel."
        )
    positions, wraps, probes = [], 0, 0
    for idx, pos, wrapped, probed in fib_stream(limit):
        positions.append(pos)
        wraps += wrapped
        probes += probed
        if len(positions) == count:
            break
    return positions, wraps, probes


def clean_capacity(limit):
    """How many bytes fit before the sequence starts wrapping."""
    n, a, b = 0, 1, 2
    while a < limit:
        n += 1
        a, b = b, a + b
    return n


def normalise_payload(data):
    """Clean up a text flag file before embedding.

    A file whose every non-empty line is wrapped in double quotes, e.g.

        "ol48HC>d?`>hl<0@0`@`DAEADA5@ebdhc1M2EAEF6eDhhKE2F@4h8KEB1HDhhkEb"
        "b`488;g2E0dMc1<i4h@?;gdJdjD83aL`J<3lf1G<@22<2`dal1<9@=d1@1L1NBNm"

    is treated as one continuous string: the quotes and the line breaks are
    layout, not payload, so they are dropped and the lines are concatenated.
    Any other text file just gets leading/trailing whitespace stripped, which
    keeps interior newlines intact. Binary payloads are returned untouched.
    """
    if TERMINATOR in data:
        return data

    lines = [line.strip() for line in data.splitlines()]
    lines = [line for line in lines if line]
    if lines and all(len(l) >= 2 and l[:1] == b'"' and l[-1:] == b'"'
                     for l in lines):
        return b"".join(line[1:-1] for line in lines)

    return data.strip()


def load_rgb(path):
    img = Image.open(path)
    if img.mode != "RGB":
        print(f"[i] Converting image from {img.mode} to RGB", file=sys.stderr)
        img = img.convert("RGB")
    return np.array(img, dtype=np.uint8)


def pack(byte):
    return (
        (byte >> (G_BITS + B_BITS)) & 0b111,
        (byte >> B_BITS) & 0b111,
        byte & 0b11,
    )


def unpack(r, g, b):
    return (int(r) << (G_BITS + B_BITS)) | (int(g) << B_BITS) | int(b)


def embed(cover_path, flag_path, out_path, raw=False):
    with open(flag_path, "rb") as fh:
        payload = fh.read()

    # Treat a text flag file leniently; keep binary payloads byte-exact.
    if not raw:
        payload = normalise_payload(payload)
    message = payload

    if not payload:
        sys.exit("[!] Flag file is empty.")
    if TERMINATOR in payload:
        sys.exit("[!] Payload contains a NUL byte, which is the terminator. "
                 "Encode it (base64/hex) before embedding.")

    payload += bytes([TERMINATOR])

    arr = load_rgb(cover_path)
    height, width, _ = arr.shape
    flat = arr.reshape(-1, 3)
    total = height * width

    positions, wraps, probes = fib_positions(len(payload), total)

    for byte, pos in zip(payload, positions):
        r, g, b = pack(byte)
        flat[pos][0] = (flat[pos][0] & 0b11111000) | r
        flat[pos][1] = (flat[pos][1] & 0b11111000) | g
        flat[pos][2] = (flat[pos][2] & 0b11111100) | b

    if not out_path.lower().endswith((".png", ".bmp")):
        print("[!] Warning: lossy formats (JPEG) destroy the payload. "
              "Use PNG or BMP.", file=sys.stderr)
    Image.fromarray(flat.reshape(height, width, 3), mode="RGB").save(out_path)

    print(f"[+] Cover      : {cover_path} ({width}x{height}, {total} px)")
    print(f"[+] Payload    : {len(payload) - 1} bytes + terminator")
    print(f"[+] Output     : {out_path}")
    print(f"[+] Pixels used: {positions[:8]}{' ...' if len(positions) > 8 else ''}")
    if wraps:
        print(f"[i] Modulo wrap: {wraps} of {len(positions)} positions wrapped "
              f"(clean capacity is {clean_capacity(total)} bytes)")
        print(f"[i] Collisions : {probes} resolved by linear probing")
    else:
        print(f"[+] No wrapping needed ({clean_capacity(total)} bytes clean capacity)")

    return message


def extract(stego_path, limit_bytes=None, quiet=False):
    arr = load_rgb(stego_path)
    height, width, _ = arr.shape
    flat = arr.reshape(-1, 3)
    total = height * width

    out = bytearray()
    hit_terminator = False
    cap = limit_bytes if limit_bytes else total

    for idx, pos, _wrapped, _probed in fib_stream(total):
        byte = unpack(flat[pos][0] & 0b111, flat[pos][1] & 0b111, flat[pos][2] & 0b11)
        if byte == TERMINATOR:
            hit_terminator = True
            break
        out.append(byte)
        if len(out) >= cap:
            break

    if not quiet:
        note = "" if hit_terminator else "  [!] no terminator found - truncated?"
        print(f"[+] Recovered {len(out)} bytes from {stego_path}{note}",
              file=sys.stderr)
    return bytes(out)


def hexdump(data, per_line=16):
    for off in range(0, len(data), per_line):
        chunk = data[off:off + per_line]
        hexpart = " ".join(f"{c:02x}" for c in chunk).ljust(per_line * 3 - 1)
        text = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        print(f"{off:08x}  {hexpart}  |{text}|")


def capacity(path):
    arr = load_rgb(path)
    height, width, _ = arr.shape
    total = height * width
    clean = clean_capacity(total)
    print(f"{path}: {width}x{height} = {total} pixels")
    print(f"  clean capacity (no wrapping) : {clean - 1} bytes")
    print(f"  absolute maximum (with mod)  : {total - 1} bytes")
    positions, _, _ = fib_positions(min(clean, 12), total)
    print(f"  first positions              : {positions} ...")


def dispatch(args):
    if args.cmd == "embed":
        original = embed(args.cover, args.flag, args.output, raw=args.raw)
        recovered = extract(args.output, quiet=True)
        ok = recovered == original
        print(f"[{'+' if ok else '!'}] Self-check: {'OK' if ok else 'MISMATCH'} "
              f"-> {recovered[:80].decode('utf-8', 'replace')}")
        if not ok:
            sys.exit(1)

    elif args.cmd == "extract":
        data = extract(args.image, args.max_bytes)
        if args.output:
            with open(args.output, "wb") as fh:
                fh.write(data)
            print(f"[+] Wrote {len(data)} bytes to {args.output}", file=sys.stderr)
        if args.hex:
            hexdump(data)
        else:
            sys.stdout.write(data.decode("utf-8", "replace") + "\n")

    elif args.cmd == "capacity":
        capacity(args.image)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("embed", help="hide a flag file inside a picture")
    p.add_argument("cover")
    p.add_argument("flag")
    p.add_argument("-o", "--output", default="challenge.png")
    p.add_argument("--raw", action="store_true",
                   help="embed the flag file byte-for-byte, keeping quotes, "
                        "newlines and surrounding whitespace")

    p = sub.add_parser("extract", help="recover hidden data from a stego image")
    p.add_argument("image")
    p.add_argument("-o", "--output", help="write raw bytes to this file")
    p.add_argument("-n", "--max-bytes", type=int, default=None,
                   help="stop after this many bytes even without a terminator")
    p.add_argument("--hex", action="store_true", help="print a hexdump")

    p = sub.add_parser("capacity", help="show how much the image can hold")
    p.add_argument("image")

    try:
        dispatch(ap.parse_args())
    except ValueError as exc:
        sys.exit(f"[!] {exc}")


if __name__ == "__main__":
    main()