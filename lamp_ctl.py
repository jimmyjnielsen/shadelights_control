#!/usr/bin/env python3
"""
Shadelights ØS1 lamp control via BLE extended advertising (BT5).

Protocol (reverse-engineered from iOS Better Light app BLE traces):
  - Lamp scans for BT5 extended advertising (LE Meta subevent 0x0d), not legacy BLE.
  - Apple Manufacturer Specific Data (company 0x004c), type 0x10:
      Controller format (len=6):  [byte0] 1d [nonce:3B] [cmd]
      Lamp state format   (len=7): [byte0] 1f [device-id:4B] [state]
  - cmd/state byte: 0x38 = ON, 0x08/0x28/0x68 = OFF
  - byte0 encodes current power state flags (0x4e=ON prefix, 0x44=OFF prefix)
  - 3-byte nonce: session-specific in app; testing with 0x000000 first.
  - OFF uses two advertising rounds (35ms apart).

Usage (requires root for raw HCI):
    sudo python3 lamp_ctl.py on
    sudo python3 lamp_ctl.py off
    sudo python3 lamp_ctl.py on d6b970    # with a captured session nonce
"""

import struct
import subprocess
import sys
import time

HCI_DEV = 'hci0'
ADV_HANDLE = 0x00          # extended advertising handle
ADV_DURATION_S = 1.5       # seconds to advertise per round
INTERVAL_MS = 270          # advertising interval in ms


def build_apple_mfg(on: bool, nonce: bytes, round2: bool = False) -> bytes:
    """Build the Apple Manufacturer Specific AD element payload (after company ID)."""
    byte0 = 0x4e if on else 0x44
    cmd   = 0x38 if on else (0x68 if round2 else 0x28)
    return bytes([0x10, 0x06, byte0, 0x1d]) + nonce + bytes([cmd])


def build_adv_data(on: bool, nonce: bytes, round2: bool = False) -> bytes:
    """Full advertising data payload (AD structure)."""
    apple    = build_apple_mfg(on, nonce, round2)
    mfg_body = struct.pack('<H', 0x004c) + apple      # Apple company ID LE
    flags    = bytes([0x02, 0x01, 0x1a])              # LE General Discoverable
    txpwr    = bytes([0x02, 0x0a, 0x0c])              # TX Power +12 dBm
    mfg      = bytes([1 + len(mfg_body), 0xff]) + mfg_body
    return flags + txpwr + mfg


def hci(ogf: int, ocf: int, params: bytes = b'') -> int:
    """Send HCI command via hcitool, print response, return 0 on success."""
    opcode_bytes = [f'0x{ogf:02x}', f'0x{ocf:04x}']
    param_bytes  = [f'0x{b:02x}' for b in params]
    cmd = ['hcitool', '-i', HCI_DEV, 'cmd'] + opcode_bytes + param_bytes
    r = subprocess.run(cmd, capture_output=True, text=True)
    # hcitool prints the HCI response to stdout; last line has status byte
    for line in r.stdout.strip().splitlines():
        if line.strip():
            print(f'    {line.strip()}')
    if r.returncode != 0 or 'Error' in r.stdout:
        print(f'  [ERROR] OGF={ogf:#04x} OCF={ocf:#06x}: {r.stderr.strip()}', file=sys.stderr)
    return r.returncode


def ext_adv_disable():
    # LE_Set_Extended_Advertising_Enable: disable all
    hci(0x08, 0x0039, bytes([0x00, 0x00]))


def ext_adv_set_params():
    # LE_Set_Extended_Advertising_Parameters (OCF 0x0036)
    # handle(1) properties(2) interval_min(3) interval_max(3) channel_map(1)
    # own_addr_type(1) peer_addr_type(1) peer_addr(6) filter(1)
    # tx_power(1) primary_phy(1) secondary_max_skip(1) secondary_phy(1)
    # advertising_sid(1) scan_request_notify(1)
    interval = int(INTERVAL_MS / 0.625)          # 270ms → 432 = 0x01b0
    interval_b = struct.pack('<I', interval)[:3]  # 3 bytes LE
    params = bytes([
        ADV_HANDLE,
        0x00, 0x00,             # properties: non-connectable, non-scannable, extended PDU
    ]) + interval_b + interval_b + bytes([
        0x07,                   # channel map: 37+38+39
        0x00,                   # own address type: public
        0x00,                   # peer address type: public
    ]) + bytes(6) + bytes([     # peer address: unused
        0x00,                   # filter policy: none
        0x7f,                   # tx power: host has no preference
        0x01,                   # primary PHY: LE 1M
        0x00,                   # secondary max skip: 0
        0x01,                   # secondary PHY: LE 1M
        0x00,                   # advertising SID: 0
        0x00,                   # scan request notify: disabled
    ])
    hci(0x08, 0x0036, params)


def ext_adv_set_data(on: bool, nonce: bytes, round2: bool = False):
    # LE_Set_Extended_Advertising_Data (OCF 0x0037)
    # handle(1) operation(1) fragment_preference(1) data_length(1) data(...)
    data = build_adv_data(on, nonce, round2)
    params = bytes([
        ADV_HANDLE,
        0x03,                   # operation: complete data (no fragmentation)
        0x01,                   # fragment preference: no fragmentation
        len(data),
    ]) + data
    hci(0x08, 0x0037, params)


def ext_adv_enable():
    # LE_Set_Extended_Advertising_Enable: enable handle ADV_HANDLE
    # enable(1) num_sets(1) [handle(1) duration(2) max_events(1)]
    params = bytes([
        0x01,           # enable
        0x01,           # num sets
        ADV_HANDLE,
        0x00, 0x00,     # duration: 0 = advertise until disabled
        0x00,           # max events: 0 = no limit
    ])
    hci(0x08, 0x0039, params)


def send_command(on: bool, nonce: bytes):
    label = 'ON' if on else 'OFF'

    print(f'  Disabling any existing extended advertising...')
    ext_adv_disable()

    print(f'  Setting extended advertising params (1M PHY, {INTERVAL_MS}ms, all channels)...')
    ext_adv_set_params()

    print(f'  [{label} round 1]  nonce={nonce.hex()}  '
          f'byte0={"0x4e" if on else "0x44"}  cmd={"0x38" if on else "0x28"}')
    ext_adv_set_data(on, nonce, round2=False)
    ext_adv_enable()
    time.sleep(ADV_DURATION_S)
    ext_adv_disable()

    if not on:
        time.sleep(0.035)
        print(f'  [OFF round 2]  cmd=0x68')
        ext_adv_set_data(on, nonce, round2=True)
        ext_adv_enable()
        time.sleep(ADV_DURATION_S)
        ext_adv_disable()


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ('on', 'off'):
        print(f'Usage: sudo {sys.argv[0]} on|off [nonce_hex]')
        sys.exit(1)

    on    = sys.argv[1] == 'on'
    nonce = bytes.fromhex(sys.argv[2]) if len(sys.argv) > 2 else b'\x00\x00\x00'

    print(f"\nShadelights ØS1 — {'ON' if on else 'OFF'}  (nonce={nonce.hex()})")
    print('Stopping bluetoothd to take direct HCI control...')
    subprocess.run(['systemctl', 'stop', 'bluetooth'], check=True)
    time.sleep(0.3)
    subprocess.run(['hciconfig', HCI_DEV, 'up'], check=False)

    try:
        send_command(on, nonce)
        print('Command sent.')
    finally:
        print('Restarting bluetoothd...')
        subprocess.run(['systemctl', 'start', 'bluetooth'])


if __name__ == '__main__':
    main()
