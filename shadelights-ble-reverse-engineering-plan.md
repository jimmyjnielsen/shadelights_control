# Shadelights ØS1 — How the BLE Protocol Was Reverse Engineered

## Background

The Shadelights ØS1 is a smart pendant lamp originally sold via shadelights.com (now defunct) around 2016. It is controlled by the **Better Light** app (`one.shade.app`), which was pulled from the App Store and Google Play. User reports on the old Facebook page confirm that updating the app — or the lamp firmware — can break pairing permanently. The lamps are still sold in the US/Canada under the brand **Phil Zen**.

Control is fully local over Bluetooth — no cloud account or internet dependency.

## Initial Hypothesis: CSRmesh

Because the lamp dates from 2016, the initial hypothesis was **CSRmesh** — the proprietary BLE mesh protocol from CSR (acquired by Qualcomm in 2015), which was the dominant mesh solution for BLE lighting hardware in that era. The Bluetooth SIG Mesh specification wasn't published until mid-2017, too late for this product.

This turned out to be wrong.

## Step 1: Capturing BLE Traffic from the iOS App

Traffic was captured passively using Apple's **PacketLogger** tool:

1. The Apple Bluetooth logging profile was installed on the iPhone via `developer.apple.com`.
2. PacketLogger was used to start an iOS trace over USB.
3. The Better Light app was used to perform isolated actions (connect, on, off, disconnect) while the trace ran.
4. The capture was saved as a `.pklg` file, which Wireshark can open natively.

## Step 2: Parsing the Capture

The `.pklg` format uses little-endian length and timestamp fields. After correcting for this (an initial big-endian assumption produced zero records), the capture was parsed with Python and filtered to BLE Mesh Proxy PDUs.

## The `shade` File Format

The file at `Container/Documents/shade` is a JSON object with four top-level keys:

| Key | Type | Content |
|-----|------|---------|
| `provisionModelData` | base64 string | JSON blob with mesh keys |
| `houseData` | base64 string | JSON blob with rooms, lamps, buttons, moods |
| `version` | integer | App data format version |
| `extraString` | base64 string | Additional data (not needed for control) |

**`provisionModelData`** (after base64 decode) contains:

```json
{
  "netKey": [14, 52, 57, ...],   // 16-byte array → NET_KEY
  "appKey": [120, 110, 67, ...], // 16-byte array → APP_KEY
  "authKey": [...],
  "currentGroupId": 49153,       // 0xC001 — group address for all lamps
  "currentDeviceId": 129
}
```

**`houseData`** (after base64 decode) contains the room/device hierarchy:

```json
{
  "rooms": [{
    "name": "Køkken",
    "groupId": 49153,
    "orbs": [{                         // ORB = pendant lamp
      "name": "ØS1",
      "mac": "DD:ED:D3:82:3D:DD",     // BLE MAC address
      "address": 33,                   // mesh unicast address (0x0021)
      "firmwareAppVersion": 17,
      "moods": [...]                   // per-lamp copy of the moods
    }],
    "eclipses": [{                     // eclipse = mesh button
      "name": "Node",
      "mac": "C4:53:3D:22:07:24",
      "address": 97                    // mesh unicast address (0x0061)
    }],
    "moodMap": {
      "count": 4,
      "moods": [{
        "index": 0,                    // 0-based; use index+1 with mesh_crypto.py
        "name": "Soft nude",           // user-defined name
        "icon": "NIGHT",               // one of ~19 predefined icons
        "MidRed": 44,                  // LED channel values (0 = off)
        "MidGreen": 0,
        "MidBlue": 0,
        "MidWarm": 0,
        "TopWarm": 0,
        "TopCold": 0,
        "BottomWarm": 32,
        "BottomCold": 0
      }, ...]
    }
  }]
}
```

The IV index and provisioner unicast address are not stored in the file — they default to `0x00000000` and `0x0001` respectively.

Mood names, icons, and channel values are entirely user-defined in the app. The number of moods is also variable (up to the number of slots the app supports). `parse_provision_data.py` decodes all of this and prints it in a ready-to-use form.

## Step 3: Identifying the Protocol

Contrary to the CSRmesh hypothesis, GATT service discovery revealed the lamps expose the **standard Bluetooth SIG Mesh 1.0 GATT Proxy service** (UUID `0x1828`). This means the lamps accept standard mesh messages over a normal BLE connection — no proprietary stack needed.

The mesh keys (NetKey and AppKey) were extracted from the Better Light iOS app's local storage using **iMazing**, which exports the app container without requiring a jailbreak. The file `Container/Documents/shade/provisionModelData` contained all provisioning data in plain JSON, including keys, IV index, and per-lamp mesh addresses.

## Step 4: Implementing On/Off Control

With the keys and addresses in hand, a Python script was written using `bleak` (BLE library) to send **Generic OnOff Set Unacknowledged** messages (SIG Mesh opcode `0x8203`) over the GATT Proxy bearer. This worked immediately.

Key implementation details:
- The mesh network PDU must be correctly constructed: AES-CCM encryption at both the application and network layers, header obfuscation with a privacy key, and a monotonically increasing sequence number per source address.
- The sequence number must persist between invocations (stored in `~/.shade_seq`) — the lamp rejects replayed `(SRC, SEQ)` pairs.

## Step 5: Discovering the Scene Control Protocol

On/off worked, but scene and color control did not respond to any standard SIG Mesh model opcodes tried (Light Lightness, Light CTL, Generic Level, Scene Recall).

Capturing scene switches via PacketLogger failed because Apple's HCI scan filter only passes Apple Continuity advertising packets — BLE Mesh advertising (AD type `0x29`) is silently filtered out before it reaches the capture layer.

The solution was to use an **nRF52840 Dongle** (Nordic PCA10059) as a passive BLE sniffer:

1. The dongle was flashed with Nordic's nRF Sniffer for Bluetooth LE firmware using `nrfutil`.
2. The Wireshark extcap plugin was registered via `nrfutil ble-sniffer bootstrap`.
3. A capture was taken while switching between the 4 scenes in the Better Light app twice.

Since the NID derived from our NetKey (`0x7c`) matched the NID in the captured packets, all PDUs could be decrypted with our known keys. `decrypt_capture.py` deobfuscates and decrypts each PDU and prints the plaintext access PDU opcode and parameters.

## Step 6: Decoding the Scene Command

Decryption revealed all scene commands use a **Nordic Semiconductor vendor model**:

- Company ID: `0x0059` (Nordic Semiconductor)
- Vendor opcode: `0x23`
- 3-byte opcode in the access PDU: `0xE3 0x59 0x00`
- Parameters: `[scene_index, TID]`
  - `scene_index`: 0-based scene number (0–3 for scenes 1–4)
  - `TID`: transaction identifier, incremented each send to prevent duplicate suppression

The pattern across two sweeps through all 4 scenes confirmed the encoding unambiguously:

| Scene | Sweep 1 params | Sweep 2 params |
|-------|---------------|---------------|
| 1     | `00 cc`        | `00 d0`       |
| 2     | `01 cd`        | `01 d1`       |
| 3     | `02 ce`        | `02 d2`       |
| 4     | `03 cf`        | `03 d3`       |

## Result

Full on/off and scene control (all 4 presets) from a Raspberry Pi using standard Python and `bleak`. A Flask REST API (`shade_api.py`) with a persistent BLE connection provides near-instant response and integrates with Home Assistant via `rest_command`.

## What Remains Unknown

- Opcodes for direct brightness, color temperature, and RGB control (the 4 scenes blend the lamp's 8 LED channels across 3 zones). A further sniffer capture while adjusting sliders in the app would reveal these.
