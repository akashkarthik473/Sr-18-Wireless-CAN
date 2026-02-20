#!/usr/bin/env python3
"""
flash_ttcontrol_socketcan.py

SocketCAN flasher for the TTControl CAN-Downloader protocol matching your trace.

Observed from your capture (key points):
  Host -> ECU uses CAN ID 0x001
  ECU  -> Host uses CAN ID 0x002

Initialization (present in your trace, missing in your original script):
  - 0x18  <sess> <seed32>                  -> ECU: 0x18 <sess>
  - 0x0D  <sess> <(start+0x80)>            -> ECU: 0x0D <sess>
  - 0x10  <sess> <(image_len-0x80)>        -> ECU: 0x10 <sess> <token32>
  - keepalive: 0x11 0xFF 00 00 00 00 00

Connect / security / range (you already had most of this):
  - 0x11  <sess> <rand32> 0x01             -> ECU echoes 0x11 <sess> <rand32>
  - 0x19  <sess> <seed32>                  -> ECU: 0x19 <sess> 0x01
  - 0x0C  <sess> <start32> FF FF           -> ECU: 0x0C <sess> 0x01
  - 0x0C  <sess> <end_high32> <end_low16>  -> ECU: 0x0C <sess> 0x01

Erase/Prep:
  - TRACE USES 0x0D (NOT 0xDD): 0x0D <sess> <ddv32>  (ddv32 looked like 0x00E08000)

Data streaming:
  - Data frames: 0x05 <sess> <6 data bytes>
  - Flow control is HOST-initiated polling:
      host: 0x02 <sess>
      ecu : 0x02 <sess> <status...>  (often: 00 42 00 00)
    Trace cadence looks like ~11 data frames between polls.

Finalization (present in your trace):
  - final poll: 0x02 <sess> -> ECU status
  - 0x0D <sess> <final_addr32>  (trace looked like 0x00C28000)
  - 0x0B <sess> <ddv32> <crc16>  (crc16 in trace looked like 0x5E7F)
      ECU: 0x0B <sess> 0x01

IMPORTANT:
  - Flashing a live ECU can brick it. Bench test first.
  - This reproduces your trace shape; if your ECU has variants, use overrides.
  - You said assume 0x19 security is constant: this script assumes that, using --seed.

Usage:
  sudo ip link set can0 up type can bitrate 500000
  python3 flash_ttcontrol_socketcan.py --iface can0 --hex "231 80kw.hex"

Recommended starting options (match trace pacing):
  --window 11
  --sleep 0.0005   (if needed on noisy busses)

Optional overrides:
  --start 0x00C10000 --end 0x00C2DE7F
  --seed 0xF06EF645
  --dd   0x00E08000
  --final_addr 0x00C28000
  --final_crc  0x5E7F
"""

from __future__ import annotations

import argparse
import random
import sys
import time
from dataclasses import dataclass
from typing import Dict, Optional, Callable

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
    min_addr: Optional[int] = None
    max_addr: Optional[int] = None

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
                b = hexbyte(dd_str[i:i + 2])
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
    out[:] = bytes([fill]) * len(out)

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
    predicate: Callable[[can.Message], bool],
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


def wait_simple_ack(reader: can.BufferedReader, rxid: int, opcode: int, sess: int, timeout_s: float) -> Optional[can.Message]:
    return wait_for_ack(
        reader,
        lambda m: (not m.is_extended_id)
        and m.arbitration_id == rxid
        and len(m.data) >= 2
        and m.data[0] == opcode
        and m.data[1] == sess,
        timeout_s,
    )


# ---------------- Main flasher ----------------

def main() -> int:
    ap = argparse.ArgumentParser()

    ap.add_argument("--iface", default="can0", help="SocketCAN interface (default: can0)")
    ap.add_argument("--hex", required=True, help="Path to Intel HEX file")

    ap.add_argument("--start", default=None, help="Override start address (hex), e.g. 0x00C10000")
    ap.add_argument("--end", default=None, help="Override end address (hex), e.g. 0x00C2DE7F")
    ap.add_argument("--fill", default="0xFF", help="Fill for gaps (default 0xFF)")

    # Security / seed assumed constant per your ask
    ap.add_argument("--seed", default="0xF06EF645",
                    help="4-byte value used in init 0x18 and security 0x19 (default from your trace)")

    # ddv is used in erase/prep (0x0D) and finalize (0x0B) per trace
    ap.add_argument("--dd", default="0x00E08000",
                    help="4-byte value used in erase/prep 0x0D and finalize 0x0B (default from your trace)")

    ap.add_argument("--session", default=1, type=int, help="Session/node selector byte (default 1)")
    ap.add_argument("--txid", default="0x001", help="Host->ECU CAN ID (default 0x001)")
    ap.add_argument("--rxid", default="0x002", help="ECU->Host CAN ID (default 0x002)")

    ap.add_argument("--ack_timeout", default=2.0, type=float, help="Timeout waiting for ACKs (s)")

    # Trace cadence looked ~11 data frames per poll
    ap.add_argument("--window", default=11, type=int,
                    help="Data frames to send before a 0x02 poll (default 11, matches trace)")

    ap.add_argument("--sleep", default=0.0, type=float,
                    help="Optional small sleep between data frames (seconds)")

    # Init/finalize parameters (trace-derived defaults are computed if omitted)
    ap.add_argument("--init_addr80", default=None,
                    help="0x0D init address (hex). Default: start+0x80 (matches trace pattern)")
    ap.add_argument("--init_len", default=None,
                    help="0x10 init length (hex). Default: (image_size - 0x80) (matches trace pattern)")

    ap.add_argument("--final_addr", default=None,
                    help="0x0D final address (hex). Default: (end&0xFFFF0000)+0x8000 (matches trace 00 C2 80 00)")
    ap.add_argument("--final_crc", default="0x5E7F",
                    help="CRC/check value appended in 0x0B (default from trace: 0x5E7F)")

    args = ap.parse_args()

    txid = int(args.txid, 16)
    rxid = int(args.rxid, 16)
    sess = args.session & 0xFF
    fill = int(args.fill, 16) & 0xFF
    seed = int(args.seed, 16) & 0xFFFFFFFF
    ddv = int(args.dd, 16) & 0xFFFFFFFF
    final_crc = int(args.final_crc, 16) & 0xFFFF

    # Parse HEX and determine range
    hx = parse_intel_hex(args.hex)
    start = int(args.start, 16) if args.start else hx.min_addr
    end = int(args.end, 16) if args.end else hx.max_addr
    image = build_contiguous_image(hx, start, end, fill=fill)

    print(f"[i] HEX data range: 0x{hx.min_addr:08X}..0x{hx.max_addr:08X} (from file)")
    print(f"[i] Flashing range: 0x{start:08X}..0x{end:08X} ({len(image)} bytes)")
    print(f"[i] Session: {sess}  TXID: 0x{txid:03X}  RXID: 0x{rxid:03X}")

    init_addr80 = int(args.init_addr80, 16) if args.init_addr80 else (start + 0x80)
    init_len = int(args.init_len, 16) if args.init_len else (len(image) - 0x80)
    final_addr = int(args.final_addr, 16) if args.final_addr else ((end & 0xFFFF0000) + 0x8000)

    # Set up CAN
    bus = can.Bus(interface="socketcan", channel=args.iface, receive_own_messages=False)
    reader = can.BufferedReader()
    notifier = can.Notifier(bus, [reader])

    try:
        def is_rx(msg: can.Message) -> bool:
            return (not msg.is_extended_id) and msg.arbitration_id == rxid

        # ---------------- Initialization (trace-matching) ----------------

        # 0x18 <sess> <seed32> -> ECU: 0x18 <sess>
        cmd18 = bytes([0x18, sess]) + be32(seed)
        send_frame(bus, txid, cmd18)
        if not wait_simple_ack(reader, rxid, 0x18, sess, args.ack_timeout):
            print("[!] No 0x18 ACK received.", file=sys.stderr)
            return 20
        print("[+] INIT 0x18 ok")

        # 0x0D <sess> <start+0x80> -> ECU: 0x0D <sess>
        cmd0d_init = bytes([0x0D, sess]) + be32(init_addr80)
        send_frame(bus, txid, cmd0d_init)
        if not wait_simple_ack(reader, rxid, 0x0D, sess, args.ack_timeout):
            print("[!] No 0x0D(init) ACK received.", file=sys.stderr)
            return 21
        print(f"[+] INIT 0x0D ok (addr=0x{init_addr80:08X})")

        # 0x10 <sess> <len-0x80> -> ECU: 0x10 <sess> <token32>
        cmd10 = bytes([0x10, sess]) + be32(init_len)
        send_frame(bus, txid, cmd10)
        ack10 = wait_for_ack(
            reader,
            lambda m: is_rx(m) and len(m.data) >= 6 and m.data[0] == 0x10 and m.data[1] == sess,
            max(args.ack_timeout, 5.0),
        )
        if not ack10:
            print("[!] No 0x10 ACK received.", file=sys.stderr)
            return 22
        token10 = int.from_bytes(bytes(ack10.data[2:6]), "big")
        print(f"[+] INIT 0x10 ok (len=0x{init_len:08X}, token=0x{token10:08X})")

        # keepalive like trace
        send_frame(bus, txid, bytes([0x11, 0xFF, 0, 0, 0, 0, 0]))

        # ---------------- Connect / Security / Range ----------------

        # RandomID like your trace (host chooses it)
        random_id = random.getrandbits(32)

        # 0x11 CONNECT: 11 <sess> <rand32> 01  -> ECU echoes: 11 <sess> <rand32>
        connect = bytes([0x11, sess]) + be32(random_id) + bytes([0x01])
        send_frame(bus, txid, connect)
        ack = wait_for_ack(
            reader,
            lambda m: is_rx(m)
            and len(m.data) >= 6
            and m.data[0] == 0x11
            and m.data[1] == sess
            and bytes(m.data[2:6]) == be32(random_id),
            args.ack_timeout,
        )
        if not ack:
            print("[!] No CONNECT ACK (0x11) received. Wrong IDs/bus/bootloader state?", file=sys.stderr)
            return 2
        print("[+] CONNECT ok")

        # 0x19 security step: 19 <sess> <seed32> -> ECU: 19 <sess> 01
        step19 = bytes([0x19, sess]) + be32(seed)
        send_frame(bus, txid, step19)
        ack = wait_for_ack(
            reader,
            lambda m: is_rx(m) and len(m.data) >= 3 and m.data[0] == 0x19 and m.data[1] == sess and m.data[2] == 0x01,
            args.ack_timeout,
        )
        if not ack:
            print("[!] No 0x19 ACK received. You assumed constant security; verify seed/session.", file=sys.stderr)
            return 3
        print("[+] STEP 0x19 ok")

        # 0x0C RANGE SETUP (two frames)
        start_cmd = bytes([0x0C, sess]) + be32(start) + bytes([0xFF, 0xFF])
        end_high = end & 0xFFFF0000
        end_cmd = bytes([0x0C, sess]) + be32(end_high) + be16(end & 0xFFFF)

        send_frame(bus, txid, start_cmd)
        if not wait_for_ack(reader, lambda m: is_rx(m) and len(m.data) >= 3 and m.data[0] == 0x0C and m.data[1] == sess and m.data[2] == 0x01, args.ack_timeout):
            print("[!] No 0x0C ACK after start range.", file=sys.stderr)
            return 4

        send_frame(bus, txid, end_cmd)
        if not wait_for_ack(reader, lambda m: is_rx(m) and len(m.data) >= 3 and m.data[0] == 0x0C and m.data[1] == sess and m.data[2] == 0x01, args.ack_timeout):
            print("[!] No 0x0C ACK after end range.", file=sys.stderr)
            return 5
        print("[+] RANGE set ok")

        # ---------------- Erase/Prep (trace uses 0x0D with ddv) ----------------
        # 0x0D <sess> <ddv32> -> ECU: 0x0D <sess>
        cmd0d_erase = bytes([0x0D, sess]) + be32(ddv)
        send_frame(bus, txid, cmd0d_erase)
        if not wait_simple_ack(reader, rxid, 0x0D, sess, max(args.ack_timeout, 10.0)):
            print("[!] No 0x0D(erase/prep) ACK received. Override --dd if needed.", file=sys.stderr)
            return 6
        print("[+] ERASE/PREP ok")

        # ---------------- Flow control (host poll 0x02) ----------------
        def poll_flow_control(expect_reply: bool = True) -> Optional[can.Message]:
            # host->ECU poll
            send_frame(bus, txid, bytes([0x02, sess]))
            if not expect_reply:
                return None
            # ECU->host response
            resp = wait_for_ack(
                reader,
                lambda m: is_rx(m) and len(m.data) >= 2 and m.data[0] == 0x02 and m.data[1] == sess,
                args.ack_timeout,
            )
            return resp

        # ---------------- Data stream (0x05) ----------------
        total = len(image)
        sent = 0
        frames_since_poll = 0

        print("[i] Streaming data...")
        while sent < total:
            chunk = image[sent:sent + 6]
            if len(chunk) < 6:
                chunk = chunk + bytes([fill] * (6 - len(chunk)))

            frame = bytes([0x05, sess]) + chunk
            send_frame(bus, txid, frame)

            sent += 6
            frames_since_poll += 1

            if args.sleep > 0:
                time.sleep(args.sleep)

            if frames_since_poll >= args.window:
                resp = poll_flow_control(expect_reply=True)
                if not resp:
                    print("[!] Timed out waiting for 0x02 flow-control response. Try --window 11 and/or add --sleep.", file=sys.stderr)
                    return 7
                # Log status bytes if present (trace often: 00 42 00 00)
                if len(resp.data) > 2:
                    status = bytes(resp.data[2:])
                    print(f"[i] 0x02 status: {status.hex().upper()}")
                frames_since_poll = 0

            # progress
            if (sent // 2048) != ((sent - 6) // 2048):
                pct = min(100.0, 100.0 * min(sent, total) / total)
                print(f"  {pct:6.2f}%  ({min(sent, total)}/{total} bytes)", end="\r", flush=True)

        # Final poll like trace
        print("\n[i] Final flow-control poll...")
        resp = poll_flow_control(expect_reply=True)
        if not resp:
            print("[!] Final 0x02 poll failed.", file=sys.stderr)
            return 30
        if len(resp.data) > 2:
            status = bytes(resp.data[2:])
            print(f"[i] Final 0x02 status: {status.hex().upper()}")

        # ---------------- Finalization (trace-matching) ----------------

        # 0x0D <sess> <final_addr32> -> ECU: 0x0D <sess>
        cmd0d_final = bytes([0x0D, sess]) + be32(final_addr)
        send_frame(bus, txid, cmd0d_final)
        if not wait_simple_ack(reader, rxid, 0x0D, sess, max(args.ack_timeout, 10.0)):
            print("[!] No 0x0D(final) ACK received.", file=sys.stderr)
            return 31
        print(f"[+] FINAL 0x0D ok (addr=0x{final_addr:08X})")

        # 0x0B <sess> <ddv32> <crc16> -> ECU: 0x0B <sess> 0x01
        cmd0b = bytes([0x0B, sess]) + be32(ddv) + be16(final_crc)
        send_frame(bus, txid, cmd0b)
        ack0b = wait_for_ack(
            reader,
            lambda m: is_rx(m) and len(m.data) >= 3 and m.data[0] == 0x0B and m.data[1] == sess and m.data[2] == 0x01,
            max(args.ack_timeout, 15.0),
        )
        if not ack0b:
            print("[!] No 0x0B finalize ACK received. Try overriding --final_crc and verify ddv.", file=sys.stderr)
            return 32
        print("[+] FINAL 0x0B ok (program/verify complete)")

        print("[+] Done.")
        return 0

    finally:
        notifier.stop()
        bus.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
