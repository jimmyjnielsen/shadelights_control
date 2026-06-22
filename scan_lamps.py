#!/usr/bin/env python3
"""
Scan for Shadelights ØS1 lamps and enumerate their GATT services.
Looks for devices advertising Mesh Proxy Service (0x1828).
"""

import asyncio
from bleak import BleakScanner, BleakClient

MESH_PROXY_SERVICE  = '00001828-0000-1000-8000-00805f9b34fb'
MESH_PROXY_DATA_IN  = '00002adc-0000-1000-8000-00805f9b34fb'
MESH_PROXY_DATA_OUT = '00002add-0000-1000-8000-00805f9b34fb'

SCAN_SECONDS = 10


async def scan():
    print(f'Scanning {SCAN_SECONDS}s for BLE devices...\n')
    devices = await BleakScanner.discover(timeout=SCAN_SECONDS, return_adv=True)

    candidates = []
    for addr, (dev, adv) in devices.items():
        name = dev.name or '(no name)'
        # Look for Mesh Proxy service in advertisement
        has_mesh = MESH_PROXY_SERVICE.lower() in [s.lower() for s in (adv.service_uuids or [])]
        # Also flag by name
        shade_name = any(w in name.lower() for w in ('shade', 'orb', 'light'))
        if has_mesh or shade_name:
            print(f'  *** LAMP CANDIDATE ***')
        print(f'  {addr}  "{name}"'
              f'  rssi={adv.rssi}'
              f'  mesh_proxy={has_mesh}'
              + (f'  svcs={adv.service_uuids}' if adv.service_uuids else ''))
        if has_mesh or shade_name:
            candidates.append(addr)

    if not candidates:
        print('\nNo lamp candidates found. Try moving closer.')
        return

    target = candidates[0]
    print(f'\nConnecting to {target} ...')
    async with BleakClient(target, timeout=15) as client:
        print(f'Connected: {client.is_connected}')
        print(f'\nGATT Services:')
        for svc in client.services:
            print(f'  Service {svc.uuid}  "{svc.description}"')
            for ch in svc.characteristics:
                props = ','.join(ch.properties)
                print(f'    Char {ch.uuid}  [{props}]  "{ch.description}"')
                if 'read' in ch.properties:
                    try:
                        val = await client.read_gatt_char(ch.uuid)
                        print(f'      value: {val.hex()}')
                    except Exception as e:
                        print(f'      read error: {e}')


if __name__ == '__main__':
    asyncio.run(scan())
