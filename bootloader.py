from os import WCONTINUED

import can
import time
from typing import Optional

can_id = {
    "pc2vcu": 0x001,
    "vcu2pc": 0x002,
    "0x19bytes": 0x019
}

bus = can.Bus(interface='socketcan', channel='can0')

def server_response(canid: int, data: list[int], timeout: Optional[float] = 0.3) -> bool:
    target = bytes(data)
    end = time.monotonic() + timeout

    while True:
        remaining = end - time.monotonic()
        if remaining <= 0:
            return False

        msg = bus.recv(timeout=remaining)  # one frame per call
        if msg and msg.arbitration_id == canid and bytes(msg.data) == target:
            return True

def send_can(canid: int, data: list[int], delay: Optional[float] = 0.5):
    # id = can_id[canid] # ex. 0x001

    msg = can.Message(
        arbitration_id=canid,
        data=data,
        is_extended_id=False
        # DLC handled internally
    )
    bus.send(msg)
    time.sleep(delay/1000) # ms -> s

# Random frames (not sure what they do)
send_can(canid=0x001, data=[0x11, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x01], delay=0.5)
send_can(canid=0x001, data=[0x03, 0xFF], delay=0.7)
send_can(canid=0x001, data=[0x01, 0xFF], delay=0.9)

# Frame blast
for i in range(0x600, 0x700):
    send_can(canid=i, data=[0x2B, 0x25, 0x10, 0x01, 0x13, 0x03, 0x00, 0x00], delay=2.42) # averaged delay
    send_can(canid=0x001, data=[0x01, 0xFF], delay=1.73) # averaged delay


# 01 FF silence
for i in range(650):
    send_can(canid=0x001, data=[0x01, 0xFF], delay=6)

time.sleep(42)

# Server ack thing idek im just tryna copy the trc
server_ack = False
# while server_ack != True:

for i in range(0x00, 0x100):
    send_can(canid=0x001, data=[0x14, i], delay=6)
    server_response(canid=0x002, data=[])