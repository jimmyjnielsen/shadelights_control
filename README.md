# Shadelights ØS1 — BLE Mesh reverse engineering

Standalone Python control for the **Shadelights ØS1** smart pendant lamp, normally controlled by the now-abandoned *Better Light* iOS/Android app (`one.shade.app`). No app, no cloud, no dependency on the vendor.

Works from a **Raspberry Pi** (or any Linux/macOS machine with Bluetooth) using the standard BLE Mesh GATT Proxy bearer.

## What works

| Command | Protocol |
|---------|----------|
| `on` / `off` | SIG Mesh Generic OnOff Set Unacknowledged (opcode `0x8203`) |
| `scene <1-4>` | Nordic vendor model (company `0x0059`, opcode `0x23`) |
| `info` | Print derived key material (NID, AID, EncKey, PrivKey) |

## Protocol summary

The lamp runs **Bluetooth SIG Mesh 1.0** (not CSRmesh as the hardware vintage might suggest). It exposes a standard Mesh GATT Proxy service (UUID `0x1828`), so any device that supports BLE can send mesh messages over a normal GATT connection — no need to be a mesh node.

**Scene control** uses a Nordic Semiconductor vendor model:

```
Access PDU: E3 59 00 <scene_idx> <TID>
            └─┬──┘  └────┬─────┘ └─┬─┘
     opcode 0x23       0-based     transaction ID
    company 0x0059    scene (0–3)  (increment each send)
```

The TID prevents the lamp's replay-protection cache from dropping duplicate commands. Using `seq & 0xff` as the TID works fine.

**Network PDU** format is standard SIG Mesh with:
- NID derived via `k2(NetKey)`
- AID derived via `k4(AppKey)`
- 4-byte NetMIC, 4-byte TransMIC

## Hardware

- **Lamp**: Shadelights ØS1 (firmware circa 2017–2018)
- **Controller**: Raspberry Pi 3/4/5 with built-in Bluetooth, or any Linux box with a BT adapter
- **Sniffer** (optional, for further reverse engineering): nRF52840 Dongle (Nordic PCA10059)

## Setup

### 1. Install dependencies

```bash
pip install bleak cryptography
```

### 2. Extract your keys from the Better Light app

The mesh keys are stored unencrypted in the app's local storage. Use [iMazing](https://imazing.com) (free tier is enough) to pull the app container from your iPhone:

1. iMazing → select device → Apps → Better Light → "Manage App" → "Export Documents"
2. Navigate to `Container/Documents/shade/`
3. Open `provisionModelData` — it's JSON containing:
   - `netKey` → your `NET_KEY`
   - `appKeys[0].key` → your `APP_KEY`
   - `unicastAddress` → provisioner address (usually `0x0001`)
   - `ivIndex` → IV index (usually `0`)
   - Per-lamp entries with `unicastAddress` (mesh addr) and the BLE MAC address

Fill these into the constants at the top of `mesh_crypto.py`.

### 3. Find your lamp addresses

```bash
python3 scan_lamps.py
```

This scans for BLE devices advertising the Mesh Proxy service and prints their MACs. Match them to the addresses in `provisionModelData`.

### 4. Copy to Pi and run

```bash
scp mesh_crypto.py pi@raspberrypi:~/
ssh pi@raspberrypi
python3 mesh_crypto.py on
python3 mesh_crypto.py scene 2
python3 mesh_crypto.py off
```

The first connection takes 3–5 seconds (BLE establishment). Subsequent calls are the same since each opens a fresh connection.

## Sequence numbers

BLE Mesh has replay protection: the lamp ignores any message with a `(SRC, SEQ)` pair it has seen before. The script persists the sequence counter in `~/.shade_seq` and increments it on every call. If you move the script to a new device, start the counter above the last value used.

## Further reverse engineering

### Capture more vendor opcodes

To discover opcodes for brightness, color temperature, or RGB control:

1. Flash the **nRF52840 Dongle** with Nordic's sniffer firmware:
   ```bash
   ./nrfutil install ble-sniffer
   ./nrfutil ble-sniffer bootstrap
   # Hold SW1 (small edge button) while plugging in dongle → red LED pulses
   ./nrfutil device list          # get serial number
   ./nrfutil device program \
     --firmware ~/.nrfutil/share/nrfutil-ble-sniffer/firmware/sniffer_nrf52840dongle_nrf52840_4.1.1.zip \
     --serial-number <SN>
   ```
2. Open Wireshark — the dongle appears as a capture interface
3. Capture while adjusting sliders in the Better Light app; save as `.pcapng`
4. Decrypt with `decrypt_capture.py` (uses the same NetKey/AppKey):
   ```bash
   python3 decrypt_capture.py
   ```
   This deobfuscates and decrypts all BLE Mesh network PDUs, printing the plaintext access PDU opcode and parameters for each message.

### Lamp zones

The ØS1 has 8 LED channels across 3 zones:

| Zone | Channels |
|------|----------|
| Top ring | TopWarm, TopCold |
| Middle ring | MidRed, MidGreen, MidBlue, MidWarm |
| Bottom ring | BottomWarm, BottomCold |

The four built-in scenes blend these channels. Custom per-channel control likely uses additional Nordic vendor opcodes (not yet captured).

## Files

| File | Purpose |
|------|---------|
| `mesh_crypto.py` | Main control script — on/off/scene |
| `decrypt_capture.py` | Decrypt a `.pcapng` BLE sniffer capture using known keys |
| `scan_lamps.py` | BLE scan to find lamps advertising Mesh Proxy service |
| `lamp_ctl.py` | Early exploration script |
| `lamp_gatt.py` | GATT service discovery script |
| `extract_ios_appdata.py` | Helper to parse `provisionModelData` JSON |
| `shadelights-ble-reverse-engineering-plan.md` | Full analysis plan and notes |

## License

MIT
