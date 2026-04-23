#!/usr/bin/env python3
"""
hmi_client.py
Safe Modbus TCP HMI simulator for lab use.
"""

from pymodbus.client import ModbusTcpClient

HOST = "127.0.0.1"
PORT = 5020
DEVICE_ID = 1


def read_status(client: ModbusTcpClient) -> None:
    rr = client.read_holding_registers(0, count=2, device_id=DEVICE_ID)
    rc = client.read_coils(0, count=1, device_id=DEVICE_ID)

    if rr.isError() or rc.isError():
        print("[HMI] Error reading PLC data")
        return

    print("\n[HMI] Current PLC Status")
    print(f"  Cylinder Position : {rr.registers[0]}")
    print(f"  Pressure          : {rr.registers[1]}")
    print(f"  Cylinder Enable   : {rc.bits[0]}")


def set_cylinder_position(client: ModbusTcpClient, value: int) -> None:
    if not 0 <= value <= 100:
        print("[HMI] Refused: cylinder position must be between 0 and 100")
        return

    result = client.write_register(0, value=value, device_id=DEVICE_ID)
    if result.isError():
        print("[HMI] Error writing cylinder position")
    else:
        print(f"[HMI] Cylinder position set to {value}")


def set_cylinder_enable(client: ModbusTcpClient, enabled: bool) -> None:
    result = client.write_coil(0, value=enabled, device_id=DEVICE_ID)
    if result.isError():
        print("[HMI] Error writing cylinder enable")
    else:
        print(f"[HMI] Cylinder enable set to {enabled}")


def main() -> None:
    client = ModbusTcpClient(HOST, port=PORT)

    if not client.connect():
        print(f"[HMI] Could not connect to PLC at {HOST}:{PORT}")
        return

    print(f"[HMI] Connected to PLC at {HOST}:{PORT}")

    try:
        while True:
            print("\n=== HMI MENU ===")
            print("1. Read PLC status")
            print("2. Set cylinder position")
            print("3. Enable cylinder")
            print("4. Disable cylinder")
            print("5. Exit")

            choice = input("Select: ").strip()

            if choice == "1":
                read_status(client)
            elif choice == "2":
                try:
                    value = int(input("Enter position (0-100): ").strip())
                    set_cylinder_position(client, value)
                except ValueError:
                    print("[HMI] Invalid number")
            elif choice == "3":
                set_cylinder_enable(client, True)
            elif choice == "4":
                set_cylinder_enable(client, False)
            elif choice == "5":
                break
            else:
                print("[HMI] Invalid menu choice")
    finally:
        client.close()
        print("[HMI] Disconnected")


if __name__ == "__main__":
    main()