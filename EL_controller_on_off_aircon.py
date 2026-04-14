#!/usr/bin/env python3
from __future__ import annotations
import time

import socket
from dataclasses import dataclass
from typing import Optional


ECHONET_PORT = 3610
DEFAULT_TIMEOUT = 5.0
INTERVAL = 60  # 1 minutes (60 seconds)

@dataclass
class EchonetConfig:
    target_ip: str
    target_port: int = ECHONET_PORT
    local_bind_ip: str = "0.0.0.0"
    local_bind_port: int = 0
    timeout: float = DEFAULT_TIMEOUT


class EchonetLiteClient:
    def __init__(self, config: EchonetConfig) -> None:
        self.config = config
        self.sock: Optional[socket.socket] = None
        self.tid = 1

    def __enter__(self) -> "EchonetLiteClient":
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.config.local_bind_ip, self.config.local_bind_port))
        self.sock.settimeout(self.config.timeout)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.sock:
            self.sock.close()
            self.sock = None

    def _next_tid(self) -> int:
        current = self.tid
        self.tid = (self.tid + 1) & 0xFFFF
        if self.tid == 0:
            self.tid = 1
        return current

    @staticmethod
    def build_seti_packet(
        tid: int,
        seoj: bytes,
        deoj: bytes,
        epc: int,
        edt: bytes,
    ) -> bytes:
        if len(seoj) != 3 or len(deoj) != 3:
            raise ValueError("SEOJ and DEOJ must be exactly 3 bytes.")
        if not (0 <= epc <= 0xFF):
            raise ValueError("EPC must be 0..255.")
        if len(edt) > 255:
            raise ValueError("EDT too long.")

        ehd1 = 0x10
        ehd2 = 0x81
        esv = 0x60  # SETI
        opc = 0x01
        pdc = len(edt)

        packet = bytearray()
        packet.extend([ehd1, ehd2])
        packet.extend(tid.to_bytes(2, "big"))
        packet.extend(seoj)
        packet.extend(deoj)
        packet.extend([esv, opc, epc, pdc])
        packet.extend(edt)
        return bytes(packet)

    def send_packet(self, packet: bytes, label: str = "ECHONET") -> None:
        if not self.sock:
            raise RuntimeError("Socket is not initialized.")

        print(f"[SEND] {label}: {packet.hex().upper()}")
        self.sock.sendto(packet, (self.config.target_ip, self.config.target_port))

        try:
            data, addr = self.sock.recvfrom(2048)
            print(f"[RECV] from {addr[0]}:{addr[1]} -> {data.hex().upper()}")
        except socket.timeout:
            print("[INFO] No response received (timeout).")

    def send_seti(self, seoj: bytes, deoj: bytes, epc: int, edt: bytes, label: str) -> None:
        packet = self.build_seti_packet(
            tid=self._next_tid(),
            seoj=seoj,
            deoj=deoj,
            epc=epc,
            edt=edt,
        )
        self.send_packet(packet, label=label)

    def set_power(
        self,
        seoj: bytes,
        deoj: bytes,
        power_epc: int,
        power_on_edt: bytes,
        power_off_edt: bytes,
        on: bool,
    ) -> None:
        edt = power_on_edt if on else power_off_edt
        label = "Set power ON" if on else "Set power OFF"
        self.send_seti(seoj, deoj, power_epc, edt, label)


def main() -> None:
    # Use only for an emulator or a sandbox device you are explicitly authorized to test.
    cfg = EchonetConfig(target_ip="192.168.1.203") # Sharp Air Con

    # Fill these from your own approved device documentation / lab trace.
    controller_eoj = bytes.fromhex("05FF01")
    target_device_eoj = bytes.fromhex("013001")

    # Fill these from your own approved docs.


    POWER_EPC = 0x80
    POWER_ON_EDT = bytes([0x30])
    POWER_OFF_EDT = bytes([0x31])


    with EchonetLiteClient(cfg) as client:
        client.set_power(
            seoj=controller_eoj,
            deoj=target_device_eoj,
            power_epc=POWER_EPC,
            power_on_edt=POWER_ON_EDT,
            power_off_edt=POWER_OFF_EDT,
            on=True,
        )
        time.sleep(INTERVAL)

        client.set_power(
            seoj=controller_eoj,
            deoj=target_device_eoj,
            power_epc=POWER_EPC,
            power_on_edt=POWER_ON_EDT,
            power_off_edt=POWER_OFF_EDT,
            on=False,
        )
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()