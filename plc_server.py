#!/usr/bin/env python3
"""
plc_server.py
Safe Modbus TCP PLC simulator for lab use.

Registers:
  Holding Register 0 -> cylinder_position (0-100)
  Holding Register 1 -> pressure (0-200)
Coils:
  Coil 0 -> cylinder_enable (0/1)

Run:
  python plc_server.py
"""

from pymodbus.server import StartTcpServer
from pymodbus import ModbusDeviceIdentification
from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusDeviceContext,
    ModbusServerContext,
)

HOST = "127.0.0.1"
PORT = 5020  # use 5020 instead of 502 to avoid admin privileges


def build_context() -> ModbusServerContext:
    device = ModbusDeviceContext(
        di=ModbusSequentialDataBlock(0, [0] * 10),
        co=ModbusSequentialDataBlock(0, [0] * 10),
        hr=ModbusSequentialDataBlock(0, [0] * 10),
        ir=ModbusSequentialDataBlock(0, [0] * 10),
    )

    # Function code mappings in datastore:
    # 1 = coils, 2 = discrete inputs, 3 = holding registers, 4 = input registers
    device.setValues(3, 0, [50, 80])  # HR0=50, HR1=80
    device.setValues(1, 0, [1])       # Coil0=True

    return ModbusServerContext(devices={1: device}, single=False)


def build_identity() -> ModbusDeviceIdentification:
    identity = ModbusDeviceIdentification()
    identity.VendorName = "OpenAI Lab"
    identity.ProductCode = "PLC_SIM"
    identity.VendorUrl = "https://example.local"
    identity.ProductName = "Simple PLC Simulator"
    identity.ModelName = "Modbus TCP PLC"
    identity.MajorMinorRevision = "1.0"
    return identity


def main() -> None:
    context = build_context()
    identity = build_identity()

    print(f"[PLC] Starting Modbus TCP server at {HOST}:{PORT}")
    print("[PLC] Unit ID / Device ID = 1")
    print("[PLC] HR0 = cylinder_position")
    print("[PLC] HR1 = pressure")
    print("[PLC] Coil0 = cylinder_enable")

    StartTcpServer(
        context=context,
        identity=identity,
        address=(HOST, PORT),
    )


if __name__ == "__main__":
    main()