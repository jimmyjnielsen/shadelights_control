# Shadelights ØS1 / The ORB — standalone BLE control for smart home integration

Standalone Python control for the **Shadelights ØS1** (also sold as **The ORB**) smart pendant lamp, normally controlled by the now-abandoned *Better Light* iOS/Android app (`one.shade.app`). No app, no cloud, no dependency on the vendor.

Works from a **Raspberry Pi** (or any Linux/macOS machine with Bluetooth) using the standard BLE Mesh GATT Proxy bearer.

## What works

| Command | Protocol |
|---------|----------|
| `on` / `off` | SIG Mesh Generic OnOff Set Unacknowledged (opcode `0x8203`) |
| `scene <n>` | Nordic vendor model (company `0x0059`, opcode `0x23`) |
| `color` | Nordic vendor model (company `0x0059`, opcodes `0x18`/`0x19`) — direct per-channel control |
| `info` | Print derived key material (NID, AID, EncKey, PrivKey) |

## Protocol summary

The lamp runs **Bluetooth SIG Mesh 1.0** (not CSRmesh as the hardware vintage might suggest). It exposes a standard Mesh GATT Proxy service (UUID `0x1828`), so any device that supports BLE can send mesh messages over a normal GATT connection — no need to be a mesh node.

**Scene control** uses a Nordic Semiconductor vendor model:

```
Access PDU: E3 59 00 <scene_idx> <TID>
            └─┬──┘  └────┬─────┘ └─┬─┘
     opcode 0x23       0-based     transaction ID
    company 0x0059    scene index  (increment each send)
```

The TID prevents the lamp's replay-protection cache from dropping duplicate commands. Using `seq & 0xff` as the TID works fine.

**Color control** uses two Nordic vendor PDUs sent back-to-back over the same connection:

```
Opcode 0x18 access PDU: D8 59 00 | [TopWarm TopCold BotWarm BotCold packed] | TID
Opcode 0x19 access PDU: D9 59 00 | [MidWarm MidRed  MidGreen MidBlue packed] | TID

Channel values are 12-bit (0–4095), four per PDU, packed big-endian:
  byte0 = ch0[11:4]
  byte1 = ch0[3:0]<<4 | ch1[11:8]
  byte2 = ch1[7:0]
  byte3 = ch2[11:4]
  byte4 = ch2[3:0]<<4 | ch3[11:8]
  byte5 = ch3[7:0]
```

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

> **Prerequisite**: You need a working installation of the Better Light app (`one.shade.app`) that has already paired and provisioned your lamps. The app is no longer on the App Store, so use a backup copy (e.g. from iMazing's app library or an old iTunes backup). **Do not update the app or the lamp firmware** — user reports confirm this breaks pairing.

#### iOS (tested)

The mesh keys are stored unencrypted in the app's local storage. Use [iMazing](https://imazing.com) (free tier is enough) to pull the app container from your iPhone:

1. iMazing → select device → Apps → Better Light → "Manage App" → "Export Documents"
2. Navigate to `Container/Documents/shade/`
3. Open `provisionModelData` — it's JSON containing:
   - `netKey` → your `NET_KEY`
   - `appKeys[0].key` → your `APP_KEY`
   - `unicastAddress` → provisioner address (usually `0x0001`)
   - `ivIndex` → IV index (usually `0`)
   - Per-lamp entries with `unicastAddress` (mesh addr) and the BLE MAC address

#### Android (untested — likely works)

The app package is `one.shade.app`. On Android the equivalent data file is likely stored under the app's internal storage at a path such as:

```
/data/data/one.shade.app/files/shade/provisionModelData
```

To access it without root you can use [ADB](https://developer.android.com/tools/adb) with a backup, or on a rooted device pull the file directly:

```bash
adb shell "run-as one.shade.app cat files/shade/provisionModelData" > provisionModelData
```

The JSON structure should be identical to the iOS version. **This has not been tested** — if you try it, please open an issue or PR with your findings.

---

Once you have the file, run the parser to print everything you need — keys, lamp addresses, and all your configured moods:

```bash
python3 parse_provision_data.py /path/to/shade
```

The mood names and scene indices are personal — they reflect whatever you configured in the app. Use the printed index + 1 as the argument to `mesh_crypto.py scene <n>`.

Fill the printed values into the constants at the top of `mesh_crypto.py`.

### 3. Find your lamp addresses

```bash
python3 scan_lamps.py
```

This scans for BLE devices advertising the Mesh Proxy service and prints their MACs. Match them to the addresses in `provisionModelData`.

### 4. Copy scripts to the Pi

```bash
scp mesh_crypto.py shade_api.py pi@raspberrypi:~/shadelights/
```

You can test commands directly:

```bash
ssh pi@raspberrypi
python3 ~/shadelights/mesh_crypto.py on
python3 ~/shadelights/mesh_crypto.py scene 2
python3 ~/shadelights/mesh_crypto.py off
```

Each direct call opens a fresh BLE connection, which takes 3–5 seconds. For faster and persistent control, run `shade_api.py` as a service instead (see below).

### 5. Run as a persistent REST API service

`shade_api.py` is a small Flask HTTP server that keeps a permanent BLE connection open to the lamp. Commands sent to it respond in under a second since no reconnection is needed.

Install and start it as a systemd service:

```bash
sudo cp shadelights.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable shadelights   # start automatically on boot
sudo systemctl start shadelights
```

Test the endpoints:

```bash
curl -X POST http://raspberrypi.local:8765/on
curl -X POST http://raspberrypi.local:8765/scene/2
curl -X POST http://raspberrypi.local:8765/off
curl http://raspberrypi.local:8765/status

# Set all 8 LED channels directly (values 0-4095):
curl -X POST http://raspberrypi.local:8765/color \
  -H 'Content-Type: application/json' \
  -d '{"top_warm":2000,"top_cold":500,"bottom_warm":1500,"bottom_cold":0,
       "mid_warm":0,"mid_red":1200,"mid_green":300,"mid_blue":0}'
```

The service reconnects automatically if the BLE connection drops, and retries once on failure.

### 6. Home Assistant integration

If Home Assistant runs on the same Pi as the service (e.g. in a Docker container with `--network=host`), it can reach the API directly on `localhost:8765`. If HA is on a separate machine, replace `localhost` with the Pi's hostname or IP.

Append the following to your `configuration.yaml`:

```yaml
rest_command:
  shadelights_on:
    url: "http://localhost:8765/on"
    method: POST
  shadelights_off:
    url: "http://localhost:8765/off"
    method: POST
  shadelights_scene:
    url: "http://localhost:8765/scene/{{ scene }}"
    method: POST

command_line:
  - switch:
      name: Shadelights
      unique_id: shadelights_power
      command_on: "curl -s -X POST http://localhost:8765/on"
      command_off: "curl -s -X POST http://localhost:8765/off"
      command_state: "curl -s http://localhost:8765/status"
      value_template: "{{ value_json.power == 'on' }}"
      icon: mdi:ceiling-light

input_select:
  shadelights_scene:
    name: Shadelights Scene
    options:
      - "1 - Soft Nude"       # replace with your own mood names
      - "2 - Gamer's Light"
      - "3 - Lucky Green"
      - "4 - Golden Latte"
    icon: mdi:palette
```

Add the following to `automations.yaml` to apply the selected scene:

```yaml
- id: shadelights_scene_changed
  alias: "Shadelights: apply scene"
  trigger:
    - platform: state
      entity_id: input_select.shadelights_scene
  action:
    - action: rest_command.shadelights_scene
      data:
        scene: "{{ trigger.to_state.state[0] }}"
  mode: single
```

Restart Home Assistant. Two entities will appear:
- **Shadelights** — a switch for on/off, polls `/status` every 30 seconds to stay in sync
- **Shadelights Scene** — a dropdown for scene selection; update the option labels to match your own mood names from `parse_provision_data.py`

A ready-to-use copy of both snippets is in `homeassistant.yaml`.

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

| Zone | Channels | Opcode |
|------|----------|--------|
| Top ring | TopWarm, TopCold | `0x18` |
| Bottom ring | BottomWarm, BottomCold | `0x18` |
| Middle ring | MidWarm, MidRed, MidGreen, MidBlue | `0x19` |

Scenes blend these channels with stored presets. The `/color` endpoint sets all 8 channels directly with 12-bit resolution (0–4095).

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

## Acknowledgements

The reverse engineering process — packet parsing, protocol identification, key extraction, crypto implementation, and Home Assistant integration — was carried out with [Claude Code](https://claude.ai/code) (Anthropic). The iterative analysis of BLE captures and decoding of vendor opcodes would have taken significantly longer without it.

## License

MIT
