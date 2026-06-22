#!/usr/bin/env python3
"""
Shadelights ØS1 GATT exploration and control test.

Connects to a lamp and:
1. Subscribes to Mesh Proxy Data Out notifications
2. Tries the vendor write characteristic with simple ON/OFF values
3. Tries a Proxy Configuration message (no NetKey needed) to provoke a response
4. Dumps anything the lamp sends back
"""

import asyncio
import struct
from bleak import BleakClient, BleakScanner

# Known lamp addresses from initial scan
LAMPS = [
    'DD:ED:D3:82:3D:DD',   # lamp 1, mesh addr 0x0002
    'C8:67:B4:3E:E7:CC',   # lamp 2
]

# Standard BLE Mesh Proxy (0x1828)
PROXY_DATA_IN  = '00002add-0000-1000-8000-00805f9b34fb'  # write-without-response
PROXY_DATA_OUT = '00002ade-0000-1000-8000-00805f9b34fb'  # notify

# Vendor service A characteristics (base 3d1c-019e-ab4a-65fd86e87333)
VENDOR_WRITE   = '00001523-3d1c-019e-ab4a-65fd86e87333'  # write only
VENDOR_READ_F  = '0000152f-3d1c-019e-ab4a-65fd86e87333'  # 00000000
VENDOR_READ_8  = '00001528-3d1c-019e-ab4a-65fd86e87333'  # 000000000000


def proxy_pdu(msg_type: int, data: bytes) -> bytes:
    """Wrap data in a Mesh Proxy PDU header (SAR=complete, msg_type)."""
    # Bits [7:6] = SAR (00 = complete), bits [5:0] = message type
    header = (0b00 << 6) | (msg_type & 0x3f)
    return bytes([header]) + data


async def explore(addr: str):
    print(f'\n=== Connecting to {addr} ===')
    async with BleakClient(addr, timeout=15) as client:
        print(f'Connected. MTU={client.mtu_size}')

        # --- Subscribe to proxy notifications ---
        def on_proxy_notify(_, data: bytearray):
            msg_type = data[0] & 0x3f
            sar      = (data[0] >> 6) & 0x03
            payload  = data[1:]
            types = {0: 'NetworkPDU', 1: 'Beacon', 2: 'ProxyCfg', 3: 'Provisioning'}
            print(f'  [NOTIFY] SAR={sar} type={msg_type}({types.get(msg_type,"?")}) '
                  f'payload={payload.hex()}')

        await client.start_notify(PROXY_DATA_OUT, on_proxy_notify)
        print('Subscribed to Mesh Proxy Data Out. Waiting 2s for unsolicited beacons...')
        await asyncio.sleep(2)

        # --- Proxy Configuration: Set Filter (whitelist, no entries = get status) ---
        print('\n[1] Sending Proxy Config: Set Filter Type = whitelist (no crypto required)')
        # Proxy Configuration PDU, opcode 0x00 = Set Filter Type, value 0x00 = whitelist
        proxy_cfg = proxy_pdu(0x02, bytes([0x00, 0x00]))
        try:
            await client.write_gatt_char(PROXY_DATA_IN, proxy_cfg, response=False)
            print(f'  Sent: {proxy_cfg.hex()}')
        except Exception as e:
            print(f'  Error: {e}')
        await asyncio.sleep(1)

        # --- Try vendor write characteristic ---
        print('\n[2] Trying vendor write char with ON (0x01)...')
        try:
            await client.write_gatt_char(VENDOR_WRITE, bytes([0x01]), response=False)
            print('  Sent 0x01 → watch for lamp reaction')
        except Exception as e:
            print(f'  Error: {e}')
        await asyncio.sleep(2)

        print('\n[3] Trying vendor write char with OFF (0x00)...')
        try:
            await client.write_gatt_char(VENDOR_WRITE, bytes([0x00]), response=False)
            print('  Sent 0x00 → watch for lamp reaction')
        except Exception as e:
            print(f'  Error: {e}')
        await asyncio.sleep(2)

        # --- Try a few more vendor formats ---
        for label, payload in [
            ('ON  [0x01 0x00]',    bytes([0x01, 0x00])),
            ('OFF [0x00 0x00]',    bytes([0x00, 0x00])),
            ('ON  [0x00 0x01 0x00]', bytes([0x00, 0x01, 0x00])),
        ]:
            print(f'\n[?] Trying vendor write: {label}  {payload.hex()}')
            try:
                await client.write_gatt_char(VENDOR_WRITE, payload, response=False)
            except Exception as e:
                print(f'  Error: {e}')
            await asyncio.sleep(1.5)

        await client.stop_notify(PROXY_DATA_OUT)
        print('\nDone.')


async def main():
    for addr in LAMPS:
        try:
            await explore(addr)
            break   # stop after first successful connection
        except Exception as e:
            print(f'Could not connect to {addr}: {e}')


if __name__ == '__main__':
    asyncio.run(main())
