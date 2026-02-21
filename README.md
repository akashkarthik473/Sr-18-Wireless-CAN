# Sr-18-Wireless-CAN

## Constants

| Name | Value |
|---|---|
| Session token | `81 16 92 AE` |

---

## Boot / Flash Sequence

### `0x14` — Bootloader Entry

TTC sends a sequence from `14 01` up to `14 FF` (~31ms per step) until it sees `14 01 <session token>` echoed back from the VCU — this is the VCU's ack that it has entered bootloader mode.

```
→ 14 00                    (ping, no response)
→ 14 01
← 14 01 81 16 92 AE        (VCU ack — now in bootloader)
→ 14 02
→ 14 03
  ... (counts up every ~31ms)
→ 14 7F
```

---

### `0x11` — Session Management

**Frame layout:** `11 <node> <session token> <flag>`

| Flag | Meaning |
|---|---|
| `01` | Open session / start operation |
| `00` | Close session / end operation |

**VCU always echoes:** `11 <node> <session token>` (drops the flag byte)

#### Variants

- `11 FF 00 00 00 00 01` — Global startup broadcast (sent once at very start, before `0x14`)
- `11 FF 00 00 00 00 00` — Broadcast keepalive (sent periodically, no VCU response)
- `11 01 <token> 01` → VCU echo — open session
- `11 01 <token> 00` → VCU echo — close session

#### Sequence after `0x14` ack

```
→ 11 FF 00 00 00 00 00     (broadcast keepalive)
→ 11 01 81 16 92 AE 01     (open session)
← 11 01 81 16 92 AE        (VCU echo)
  [0x17 handshake here]
→ 11 FF 00 00 00 00 00     (keepalive)
→ 11 FF 00 00 00 00 00     (keepalive)
→ 11 01 81 16 92 AE 01     (re-open session)
← 11 01 81 16 92 AE        (VCU echo)
  [flash commands follow]
```

---

### `0x17` — Security Handshake

Two-step exchange. Host sends a 4-byte seed, VCU responds with a 4-byte value + constant trailer `02 0A` (protocol version).

```
→ 17 01 <seed32> 00        (step 1: initiate)
← 17 01 <resp32> 02 0A     (VCU responds with challenge)

→ 17 01 <val32>  01        (step 2: complete)
← 17 01 <resp32> 02 0A     (VCU confirms)
```

- `02 0A` trailer is **always constant** (bootloader version 2.10)
- The 4-byte seed used in step 1 is the **same value** reused for `0x19` security later
- Values are fixed per tool run but change between runs (generated once at startup)
