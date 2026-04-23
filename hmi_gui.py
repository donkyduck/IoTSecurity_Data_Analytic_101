#!/usr/bin/env python3
"""
hmi_gui.py
Tkinter-based HMI for a safe Modbus TCP lab.

Tested for pymodbus 3.11.0

PLC mapping:
  Holding Register 0 -> cylinder_position (0-100)
  Holding Register 1 -> pressure (0-200)
  Coil 0             -> cylinder_enable (True/False)

Run:
  python hmi_gui.py
"""

import tkinter as tk
from tkinter import ttk, messagebox
from pymodbus.client import ModbusTcpClient

HOST = "127.0.0.1"
PORT = 5020
DEVICE_ID = 1


class HMIGUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Modbus HMI - PLC Lab")


        self.root.geometry("640x520")
        self.root.minsize(640, 520)
        self.root.resizable(True, True)

        self.client = None
        self.connected = False

        self.status_text = tk.StringVar(value="Disconnected")
        self.position_text = tk.StringVar(value="--")
        self.pressure_text = tk.StringVar(value="--")
        self.enable_text = tk.StringVar(value="--")
        self.new_position_text = tk.StringVar(value="50")

        self._build_ui()

    def _build_ui(self) -> None:
        main = ttk.Frame(self.root, padding=16)
        main.pack(fill="both", expand=True)

        title = ttk.Label(main, text="Human Machine Interface (HMI)", font=("Arial", 16, "bold"))
        title.pack(anchor="w", pady=(0, 10))

        conn_frame = ttk.LabelFrame(main, text="Connection", padding=12)
        conn_frame.pack(fill="x", pady=(0, 10))

        ttk.Label(conn_frame, text=f"Target PLC: {HOST}:{PORT}").grid(row=0, column=0, sticky="w", padx=4, pady=4)
        ttk.Label(conn_frame, text="Status:").grid(row=1, column=0, sticky="w", padx=4, pady=4)
        ttk.Label(conn_frame, textvariable=self.status_text).grid(row=1, column=1, sticky="w", padx=4, pady=4)

        ttk.Button(conn_frame, text="Connect", command=self.connect).grid(row=0, column=2, padx=6, pady=4)
        ttk.Button(conn_frame, text="Disconnect", command=self.disconnect).grid(row=1, column=2, padx=6, pady=4)

        state_frame = ttk.LabelFrame(main, text="PLC State", padding=12)
        state_frame.pack(fill="x", pady=(0, 10))

        ttk.Label(state_frame, text="Cylinder Position:").grid(row=0, column=0, sticky="w", padx=4, pady=6)
        ttk.Label(state_frame, textvariable=self.position_text, font=("Arial", 11, "bold")).grid(row=0, column=1, sticky="w", padx=4, pady=6)

        ttk.Label(state_frame, text="Pressure:").grid(row=1, column=0, sticky="w", padx=4, pady=6)
        ttk.Label(state_frame, textvariable=self.pressure_text, font=("Arial", 11, "bold")).grid(row=1, column=1, sticky="w", padx=4, pady=6)

        ttk.Label(state_frame, text="Cylinder Enable:").grid(row=2, column=0, sticky="w", padx=4, pady=6)
        ttk.Label(state_frame, textvariable=self.enable_text, font=("Arial", 11, "bold")).grid(row=2, column=1, sticky="w", padx=4, pady=6)

        ttk.Button(state_frame, text="Read PLC Status", command=self.read_status).grid(row=3, column=0, columnspan=2, pady=(10, 0))

        control_frame = ttk.LabelFrame(main, text="Control", padding=12)
        control_frame.pack(fill="x", pady=(0, 10))

        ttk.Label(control_frame, text="New Cylinder Position (0-100):").grid(row=0, column=0, sticky="w", padx=4, pady=6)
        ttk.Entry(control_frame, textvariable=self.new_position_text, width=10).grid(row=0, column=1, sticky="w", padx=4, pady=6)
        ttk.Button(control_frame, text="Write Position", command=self.write_position).grid(row=0, column=2, padx=6, pady=6)

        ttk.Button(control_frame, text="Enable Cylinder", command=lambda: self.write_enable(True)).grid(row=1, column=0, padx=4, pady=8, sticky="w")
        ttk.Button(control_frame, text="Disable Cylinder", command=lambda: self.write_enable(False)).grid(row=1, column=1, padx=4, pady=8, sticky="w")

        note_frame = ttk.LabelFrame(main, text="Notes", padding=12)
        note_frame.pack(fill="both", expand=True)

        note = (
            "This GUI is for a safe lab demo.\n"
            "It reads Modbus holding registers and coils from the PLC simulator.\n"
            "Wireshark filter: tcp.port == 5020"
        )
        ttk.Label(note_frame, text=note, justify="left").pack(anchor="w")

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def connect(self) -> None:
        if self.connected:
            messagebox.showinfo("Info", "Already connected.")
            return

        try:
            self.client = ModbusTcpClient(HOST, port=PORT)
            ok = self.client.connect()
            if ok:
                self.connected = True
                self.status_text.set("Connected")
                messagebox.showinfo("Connected", f"Connected to PLC at {HOST}:{PORT}")
                self.read_status()
            else:
                self.client = None
                self.status_text.set("Disconnected")
                messagebox.showerror("Connection Failed", f"Could not connect to PLC at {HOST}:{PORT}")
        except Exception as e:
            self.client = None
            self.connected = False
            self.status_text.set("Disconnected")
            messagebox.showerror("Error", f"Connection error:\n{e}")

    def disconnect(self) -> None:
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass

        self.client = None
        self.connected = False
        self.status_text.set("Disconnected")
        self.position_text.set("--")
        self.pressure_text.set("--")
        self.enable_text.set("--")

    def ensure_connected(self) -> bool:
        if not self.connected or self.client is None:
            messagebox.showwarning("Not Connected", "Please connect to the PLC first.")
            return False
        return True

    def read_status(self) -> None:
        if not self.ensure_connected():
            return

        try:
            rr = self.client.read_holding_registers(0, count=2, device_id=DEVICE_ID)
            rc = self.client.read_coils(0, count=1, device_id=DEVICE_ID)

            if rr.isError() or rc.isError():
                messagebox.showerror("Read Error", "Failed to read PLC data.")
                return

            position = rr.registers[0]
            pressure = rr.registers[1]
            enabled = rc.bits[0]

            self.position_text.set(str(position))
            self.pressure_text.set(str(pressure))
            self.enable_text.set("ON" if enabled else "OFF")

        except Exception as e:
            messagebox.showerror("Read Error", f"Error while reading:\n{e}")

    def write_position(self) -> None:
        if not self.ensure_connected():
            return

        raw = self.new_position_text.get().strip()
        try:
            value = int(raw)
        except ValueError:
            messagebox.showwarning("Invalid Input", "Cylinder position must be an integer.")
            return

        if not 0 <= value <= 100:
            messagebox.showwarning("Out of Range", "Cylinder position must be between 0 and 100.")
            return

        try:
            result = self.client.write_register(0, value=value, device_id=DEVICE_ID)
            if result.isError():
                messagebox.showerror("Write Error", "Failed to write cylinder position.")
                return

            self.read_status()
            messagebox.showinfo("Success", f"Cylinder position set to {value}.")
        except Exception as e:
            messagebox.showerror("Write Error", f"Error while writing:\n{e}")

    def write_enable(self, enabled: bool) -> None:
        if not self.ensure_connected():
            return

        try:
            result = self.client.write_coil(0, value=enabled, device_id=DEVICE_ID)
            if result.isError():
                messagebox.showerror("Write Error", "Failed to write cylinder enable.")
                return

            self.read_status()
            state = "enabled" if enabled else "disabled"
            messagebox.showinfo("Success", f"Cylinder {state}.")
        except Exception as e:
            messagebox.showerror("Write Error", f"Error while writing:\n{e}")

    def on_close(self) -> None:
        self.disconnect()
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    try:
        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")
    except Exception:
        pass

    HMIGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()