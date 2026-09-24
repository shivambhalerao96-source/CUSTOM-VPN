#!/usr/bin/env python3
from scapy.all import sniff, send
import time

SERVER_IP = "35.226.148.101"
SERVER_PORT = 8080
IFACE = "wlo1"

def capture_one_packet(timeout=15):
    print(f"Sniffing on {IFACE} for a packet to {SERVER_IP}:{SERVER_PORT} "
          f"(trigger real client traffic now)...")
    pkts = sniff(
        filter=f"udp and dst host {SERVER_IP} and dst port {SERVER_PORT}",
        iface=IFACE,
        count=1,
        timeout=timeout
    )
    if not pkts:
        raise RuntimeError("No packet captured - did client traffic actually flow "
                           "to that IP/port while this was running?")
    return pkts[0]

def replay_packet(pkt, delay=2, repeats=50):
    for i in range(repeats):
        time.sleep(delay)
        send(pkt, verbose=False, iface=IFACE)
        print(f"[replay {i+1}/{repeats}] resent captured packet "
              f"({len(pkt)} bytes) to {SERVER_IP}:{SERVER_PORT}")

if __name__ == "__main__":
    pkt = capture_one_packet()
    print(f"Captured packet: {pkt.summary()}")
    replay_packet(pkt)
    print("Now check server logs - it should log a dropped/rejected duplicate, "
          "not process the payload again.")