#!/usr/bin/env python3
"""
Parse the Better Light app's provisionModelData file and print everything
needed to configure mesh_crypto.py: keys, lamp addresses, and configured moods.

The file is found at:
  Container/Documents/shade    (exported via iMazing)

Usage:
  python3 parse_provision_data.py /path/to/shade
"""

import sys, json, base64

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    raw = open(sys.argv[1], 'rb').read()
    top = json.loads(raw)

    pmd     = json.loads(base64.b64decode(top['provisionModelData']))
    net_key = bytes(pmd['netKey']).hex()
    app_key = bytes(pmd['appKey']).hex()
    # IV index and provisioner address are not stored (both default to 0 / 0x0001)
    iv_index  = 0
    prov_addr = 0x0001

    print("=" * 60)
    print("  mesh_crypto.py configuration")
    print("=" * 60)
    print(f"NET_KEY    = '{net_key}'")
    print(f"APP_KEY    = '{app_key}'")
    print(f"IV_INDEX   = 0x{iv_index:08x}" if isinstance(iv_index, int) else f"IV_INDEX   = {iv_index}")
    print(f"PROV_ADDR  = 0x{prov_addr:04x}" if isinstance(prov_addr, int) else f"PROV_ADDR  = {prov_addr}")

    # houseData is a base64-encoded JSON blob
    house_raw = top.get('houseData')
    if not house_raw:
        print("\n(no houseData found)")
        return

    house = json.loads(base64.b64decode(house_raw))

    for room in house.get('rooms', []):
        print(f"\n{'=' * 60}")
        print(f"  Room: {room.get('name', '?')}")
        print(f"{'=' * 60}")

        print("\nLamps (ORBs):")
        for orb in room.get('orbs', []):
            addr = orb.get('address', '?')
            mac  = orb.get('mac', '?')
            name = orb.get('name', '?').strip()
            fw   = orb.get('firmwareAppVersion', '?')
            print(f"  {name:12s}  mac={mac}  mesh=0x{addr:04x}  fw={fw}")

        print("\nMesh buttons (nodes):")
        for btn in room.get('eclipses', []):
            addr = btn.get('address', '?')
            mac  = btn.get('mac', '?')
            name = btn.get('name', '?').strip()
            print(f"  {name:12s}  mac={mac}  mesh=0x{addr:04x}")

        moods = room.get('moodMap', {}).get('moods', [])
        if moods:
            print(f"\nConfigured moods/scenes ({len(moods)} total):")
            print(f"  {'Idx':>3}  {'Icon':<10}  {'Name':<20}  Channel values")
            print(f"  {'-'*3}  {'-'*10}  {'-'*20}  {'-'*40}")
            for mood in moods:
                idx  = mood.get('index', '?')
                name = mood.get('name', '?')
                icon = mood.get('icon', '?')
                ch   = {k: v for k, v in mood.items()
                        if k not in ('index', 'name', 'icon') and v != 0}
                print(f"  {idx:>3}  {icon:<10}  {name:<20}  {ch}")
            print()
            print("  Use scene index + 1 as the argument to mesh_crypto.py scene <n>")
            print("  e.g. scene 1 = index 0, scene 4 = index 3")

if __name__ == '__main__':
    main()
