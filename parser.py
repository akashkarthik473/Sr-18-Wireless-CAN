#!/usr/bin/env python3
"""
flash_ttcontrol_socketcan.py

SocketCAN flasher for the TTControl CAN-Downloader protocol you captured:
  - Host -> ECU uses CAN ID 0x001
  - ECU  -> Host uses CAN ID 0x002
  - Control frames: 0x11, 0x19, 0x0C, 0xDD
  - Data frames:    0x05 0x01 <6 data bytes>

This script:
  1) Parses an Intel HEX (.hex) into a contiguous byte image
  2) Sends the same control sequence observed in your trace
  3) Streams the image in 6-byte chunks with 0x05 0x01 framing
  4) Paces on ECU ACK frames (0x002 starting with 0x02)

IMPORTANT:
  - You MUST verify the control frames (0x19 and 0xDD payloads especially) match your ECU/bootloader.
  - A wrong sequence can fail or brick; test on a bench setup first.

Usage (Linux):
  sudo ip link set can0 up type can bitrate 500000
  python3 flash_ttcontrol_socketcan.py --iface can0 --hex "231 80kw.hex"

Optional overrides:
  --start 0x00C10000 --end 0x00C2DE7F
  --seed 0xF06EF645          (the 4 bytes in your trace's 0x19 frame)
  --dd   00E08000            (the 4 bytes in your trace's 0xDD frame, after 0xDD 0x01)
"""

from __future__ import annotations
import argparse
import os
import random
import sys
import time
from dataclasses import dataclass
from typing import Dict, Tuple, Optional, List

import can


# ---------------- Intel HEX parsing ----------------

@dataclass
class HexImage:
    data_by_addr: Dict[int, int]   # absolute address -> byte
    min_addr: int
    max_addr: int                  # inclusive


def parse_intel_hex(path: str) -> HexImage:
    """
    Minimal Intel HEX parser supporting:
      - Data records (type 00)
      - Extended linear address (type 04)
      - EOF (type 01)

    Returns absolute byte map + min/max address (inclusive).
    """
    data: Dict[int, int] = {}
    upper = 0  # upper 16 bits for extended linear addr
    min_addr = None
    max_addr = None

    def hexbyte(s: str) -> int:
        return int(s, 16)

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            if not line.startswith(":"):
                raise ValueError(f"{path}:{lineno}: not an Intel HEX record (missing ':')")

            # Record layout:
            # :LL AAAA TT [DD..] CC
            try:
                ll = hexbyte(line[1:3])
                aaaa = int(line[3:7], 16)
                rtype = hexbyte(line[7:9])
                dd_str = line[9:9 + ll * 2]
                cc = hexbyte(line[9 + ll * 2:9 + ll * 2 + 2])
            except Exception as e:
                raise ValueError(f"{path}:{lineno}: malformed record: {e}")

            # Verify checksum
            total = ll + (aaaa >> 8) + (aaaa & 0xFF) + rtype
            bytes_list = []
            for i in range(0, len(dd_str), 2):
                b = hexbyte(dd_str[i:i+2])
                bytes_list.append(b)
                total += b
            total = (total + cc) & 0xFF
            if total != 0:
                raise ValueError(f"{path}:{lineno}: checksum mismatch")

            if rtype == 0x00:  # data
                base = (upper << 16) + aaaa
                for i, b in enumerate(bytes_list):
                    addr = base + i
                    data[addr] = b
                    if min_addr is None or addr < min_addr:
                        min_addr = addr
                    if max_addr is None or addr > max_addr:
                        max_addr = addr

            elif rtype == 0x01:  # EOF
                break

            elif rtype == 0x04:  # extended linear address
                if ll != 2:
                    raise ValueError(f"{path}:{lineno}: type 04 with length != 2")
                upper = (bytes_list[0] << 8) | bytes_list[1]

            else:
                # other record types exist, but not needed for your file
                pass

    if min_addr is None or max_addr is None:
        raise ValueError("HEX contained no data records")

    return HexImage(data_by_addr=data, min_addr=min_addr, max_addr=max_addr)


def build_contiguous_image(img: HexImage, start: int, end: int, fill: int = 0xFF) -> bytes:
    """
    Build a contiguous byte array covering [start, end] inclusive.
    Missing addresses are filled with `fill` (0xFF matches erased flash).
    """
    if end < start:
        raise ValueError("end < start")
    out = bytearray((end - start + 1))
    for i in range(len(out)):
        out[i] = fill
    for addr, b in img.data_by_addr.items():
        if start <= addr <= end:
            out[addr - start] = b
    return bytes(out)


# ---------------- CAN protocol helpers ----------------

def be32(x: int) -> bytes:
    return bytes([(x >> 24) & 0xFF, (x >> 16) & 0xFF, (x >> 8) & 0xFF, x & 0xFF])

def be16(x: int) -> bytes:
    return bytes([(x >> 8) & 0xFF, x & 0xFF])

def send_frame(bus: can.BusABC, arb_id: int, data: bytes) -> None:
    msg = can.Message(arbitration_id=arb_id, is_extended_id=False, data=data)
    bus.send(msg)

def wait_for_ack(
    reader: can.BufferedReader,
    predicate,
    timeout_s: float,
) -> Optional[can.Message]:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        msg = reader.get_message(timeout=0.05)
        if msg is None:
            continue
        if predicate(msg):
            return msg
    return None


# ---------------- Main flasher ----------------

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="can0", help="SocketCAN interface (default: can0)")
    ap.add_argument("--hex", required=True, help="Path to Intel HEX file")
    ap.add_argument("--start", default=None, help="Override start address (hex), e.g. 0x00C10000")
    ap.add_argument("--end", default=None, help="Override end address (hex), e.g. 0x00C2DE7F")
    ap.add_argument("--fill", default="0xFF", help="Fill for gaps (default 0xFF)")

    # These two are the ones most likely to differ by bootloader version; override if needed
    ap.add_argument("--seed", default="0xF06EF645",
                    help="4-byte value used in the 0x19 command (default from your trace)")
    ap.add_argument("--dd", default="0x00E08000",
                    help="4-byte value used in the 0xDD command (default from your trace)")

    ap.add_argument("--session", default=1, type=int, help="Session/node selector byte (default 1)")
    ap.add_argument("--txid", default="0x001", help="Host->ECU CAN ID (default 0x001)")
    ap.add_argument("--rxid", default="0x002", help="ECU->Host CAN ID (default 0x002)")

    ap.add_argument("--ack_timeout", default=2.0, type=float, help="Timeout waiting for ACKs (s)")
    ap.add_argument("--window", default=64, type=int,
                    help="Max data frames to send before requiring a 0x02 ACK (default 64)")
    ap.add_argument("--sleep", default=0.0, type=float,
                    help="Optional small sleep between data frames (seconds)")

    args = ap.parse_args()

    txid = int(args.txid, 16)
    rxid = int(args.rxid, 16)
    sess = args.session & 0xFF
    fill = int(args.fill, 16) & 0xFF
    seed = int(args.seed, 16) & 0xFFFFFFFF
    ddv = int(args.dd, 16) & 0xFFFFFFFF

    # Parse HEX and determine range
    hx = parse_intel_hex(args.hex)
    start = int(args.start, 16) if args.start else hx.min_addr
    end = int(args.end, 16) if args.end else hx.max_addr

    image = build_contiguous_image(hx, start, end, fill=fill)

    print(f"[i] HEX data range: 0x{hx.min_addr:08X}..0x{hx.max_addr:08X} (from file)")
    print(f"[i] Flashing range: 0x{start:08X}..0x{end:08X} ({len(image)} bytes)")

    # Set up CAN
    bus = can.Bus(interface="socketcan", channel=args.iface, receive_own_messages=False)
    reader = can.BufferedReader()
    notifier = can.Notifier(bus, [reader])

    try:
        # RandomID like your trace (host chooses it)
        random_id = random.getrandbits(32)

        def is_rx(msg: can.Message) -> bool:
            return (not msg.is_extended_id) and msg.arbitration_id == rxid

        # ---- 1) CONNECT (0x11) ----
        # Trace: 11 01 <rand32> 01  (7 bytes). ECU replies: 11 01 <rand32>
        connect = bytes([0x11, sess]) + be32(random_id) + bytes([0x01])
        send_frame(bus, txid, connect)
        ack = wait_for_ack(
            reader,
            lambda m: is_rx(m) and len(m.data) >= 6 and m.data[0] == 0x11 and m.data[1] == sess and bytes(m.data[2:6]) == be32(random_id),
            args.ack_timeout
        )
        if not ack:
            print("[!] No CONNECT ACK (0x11) received. Wrong IDs/bus/bootloader state?", file=sys.stderr)
            return 2
        print("[+] CONNECT ok")

        # ---- 2) SEED/STEP (0x19) ----
        # Trace: 19 01 F0 6E F6 45   and ECU: 19 01 01
        step19 = bytes([0x19, sess]) + be32(seed)
        send_frame(bus, txid, step19)
        ack = wait_for_ack(
            reader,
            lambda m: is_rx(m) and len(m.data) >= 3 and m.data[0] == 0x19 and m.data[1] == sess and m.data[2] == 0x01,
            args.ack_timeout
        )
        if not ack:
            print("[!] No 0x19 ACK received. This value may be bootloader/version-specific; override with --seed.", file=sys.stderr)
            return 3
        print("[+] STEP 0x19 ok")

        # ---- 3) RANGE SETUP (0x0C) ----
        # Trace format observed:
        #   0C 01 <start32> FF FF
        #   0C 01 <end_high32> <end_low16>
        # Where end_high32 looked like 00 C2 00 00 and end_low16 = DE 7F.
        start_cmd = bytes([0x0C, sess]) + be32(start) + bytes([0xFF, 0xFF])
        end_high = end & 0xFFFF0000
        end_cmd = bytes([0x0C, sess]) + be32(end_high) + be16(end & 0xFFFF)

        send_frame(bus, txid, start_cmd)
        ack = wait_for_ack(
            reader,
            lambda m: is_rx(m) and len(m.data) >= 3 and m.data[0] == 0x0C and m.data[1] == sess and m.data[2] == 0x01,
            args.ack_timeout
        )
        if not ack:
            print("[!] No 0x0C ACK after start range.", file=sys.stderr)
            return 4

        send_frame(bus, txid, end_cmd)
        ack = wait_for_ack(
            reader,
            lambda m: is_rx(m) and len(m.data) >= 3 and m.data[0] == 0x0C and m.data[1] == sess and m.data[2] == 0x01,
            args.ack_timeout
        )
        if not ack:
            print("[!] No 0x0C ACK after end range.", file=sys.stderr)
            return 5
        print("[+] RANGE set ok")

        # ---- 4) ERASE/PREP (0xDD) ----
        # Trace: DD 01 00 E0 80 00  (6 bytes) and ECU: DD 01 (2 bytes)
        dd_cmd = bytes([0xDD, sess]) + be32(ddv)
        send_frame(bus, txid, dd_cmd)
        ack = wait_for_ack(
            reader,
            lambda m: is_rx(m) and len(m.data) >= 2 and m.data[0] == 0xDD and m.data[1] == sess,
            max(args.ack_timeout, 5.0)  # erase can take longer
        )
        if not ack:
            print("[!] No 0xDD ACK received. This value may be bootloader/version-specific; override with --dd.", file=sys.stderr)
            return 6
        print("[+] ERASE/PREP ok")

        # ---- 5) DATA STREAM (0x05) ----
        # Frame: 05 01 <6 bytes>
        # ACK/status: on 0x002: 02 01  (or 02 01 00 42 00 00 etc.)
        total = len(image)
        sent = 0
        frames_since_ack = 0

        def got_data_ack(msg: can.Message) -> bool:
            return is_rx(msg) and len(msg.data) >= 2 and msg.data[0] == 0x02 and msg.data[1] == sess

        print("[i] Streaming data...")
        while sent < total:
            chunk = image[sent:sent+6]
            if len(chunk) < 6:
                chunk = chunk + bytes([fill] * (6 - len(chunk)))
            frame = bytes([0x05, sess]) + chunk
            send_frame(bus, txid, frame)
            sent += 6
            frames_since_ack += 1

            if args.sleep > 0:
                time.sleep(args.sleep)

            # Require an ACK periodically (windowed pacing)
            if frames_since_ack >= args.window:
                ack = wait_for_ack(reader, got_data_ack, args.ack_timeout)
                if not ack:
                    print("[!] Timed out waiting for data ACK (0x02). Try smaller --window or add --sleep.", file=sys.stderr)
                    return 7
                frames_since_ack = 0

            # progress
            if (sent // 1024) != ((sent - 6) // 1024):
                pct = min(100.0, 100.0 * sent / total)
                print(f"  {pct:6.2f}%  ({min(sent,total)}/{total} bytes)", end="\r", flush=True)

        # Drain final ACK if needed
        wait_for_ack(reader, got_data_ack, 0.5)

        print("\n[+] Data stream complete.")
        print("[i] NOTE: Your trace likely has a finalize/verify/reset step after the stream.")
        print("    If your ECU requires it, you must replay those final control frames too.")
        print("    (Search in your trace right after the last 0x05 burst for non-0x05 messages.)")

        return 0

    finally:
        notifier.stop()
        bus.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
