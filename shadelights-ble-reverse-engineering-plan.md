# Shadelights ØS1 — BLE Protocol Reverse Engineering Plan

## Background

- Device: Shadelights ØS1 smart pendant lamp(s), originally sold via **shadelights.com** (now defunct — site doesn't load, Facebook page "SHADE" inactive for 6-7 years).
- Product dates from **2016**. This rules out standard Bluetooth SIG Mesh, since that spec wasn't published until mid-2017. The leading candidate is **CSRmesh** — the proprietary BLE mesh protocol from CSR (acquired by Qualcomm in 2015), which was the dominant "mesh" solution in BLE lighting SoCs through 2015–2016.
- Lamps are still sold in the US/Canada under the brand **Phil Zen**, but app support status under that brand is unclear.
- Control app: **"Better Light"**, package name `one.shade.app`. Pulled from Google Play (confirmed 404 on the store listing). Last known version: **1.2.2**, last updated **26 June 2020**.
- There are user complaints on the old Facebook page about losing control of their lamps after an app update — likely an app update that changed provisioning/keys or pushed an OTA firmware change the lamp's old firmware didn't handle well. Conclusion: **do not update the working app**; capture traffic from the device that already works.
- Control is fully **local over Bluetooth** — no cloud account or internet dependency confirmed.
- Lamps are currently controlled successfully from an **iPad/iPhone (iOS)** with a working install of the Better Light app. This is the device to capture traffic from — not the spare Android (Nokia) phone, since it doesn't have a working/paired install and sideloading a fresh APK carries the same "update broke it" risk.

## Goal

Reverse engineer the BLE control protocol used by the Better Light app to talk to the ØS1 lamps, well enough to replicate on/off, dimming, and color control independently — from a Raspberry Pi (Python, `bleak`/`bluepy`) or an ESP32 (NimBLE/Arduino BLE) — without depending on the original app or company infrastructure.

## Capture Method (iOS, via Mac)

This is a passive logging method — it does not modify the app or lamp firmware, so it carries no risk of the "broken after update" issue seen by other users.

1. On the iPhone/iPad: visit `https://developer.apple.com/bug-reporting/profiles-and-logs/`, sign in with a free Apple ID, install the **Bluetooth** profile under Settings → Profile Downloaded → Install. Reboot the device.
2. On the Mac: download **"Additional Tools for Xcode"** (matching macOS/Xcode version) from `developer.apple.com/download/all/`, open the .dmg, go to the Hardware folder, and install **PacketLogger** to Applications.
3. Connect the iPad/iPhone to the Mac via cable, trust the computer.
4. In PacketLogger: File → New iOS Trace → select the device. A pulse/signal indicator appears in the iOS status bar once tracing starts.
5. In the Better Light app, perform **one isolated action at a time**, with a pause between each, so each action is easy to isolate in the trace:
   - Power on
   - Power off
   - Dim to a few different levels
   - Change color / color temperature (each distinct setting separately)
6. Stop the trace in PacketLogger. Export to **btsnoop** format (PacketLogger supports this directly), or save as `.pklg` (modern Wireshark can open `.pklg` natively).

## What to Hand to Claude Code

- The exported `.pklg` or `.btsnoop` capture file(s), ideally one file per isolated action (or one file with clear timestamps/notes on when each action occurred).
- A short text log noting **wall-clock time (or trace timestamp) → action performed** for each isolated action in the capture, to correlate packets to commands.

## Analysis Tasks for Claude Code

1. **Parse the capture** (via `pyshark`, `scapy`, or direct btsnoop parsing) and filter to ATT/GATT (`btatt`) traffic plus advertising/`btle` packets.
2. **Identify the lamp's BLE address** and isolate its traffic from anything else nearby.
3. **Service discovery check**: extract the GATT services/characteristics the lamp exposes during connection setup. Specifically check for:
   - Service UUID `0xFEF1` (known CSRmesh service UUID) — confirms/denies the CSRmesh hypothesis.
   - Any other vendor-specific 128-bit UUIDs.
4. **Classify the protocol type**:
   - If you see plain `ATT Write Request`/`Write Command` operations with stable handles and short payloads → likely simple GATT control, easier to replicate directly.
   - If you see `Mesh Provisioning`/`Mesh Proxy` PDUs or CSRmesh-specific opcodes → mesh-based, will need network/application key material, which may need to be extracted via the LTK/session key route (iOS PacketLogger can sometimes expose LE Secure Connections keys — flag if encryption is in play).
5. **Correlate isolated actions to specific writes**: for each labeled action (on/off/dim level/color), extract the exact ATT write payload(s) sent, and diff between actions to identify which bytes encode which parameter (brightness level, RGB/color temp value, on/off flag, etc.).
6. **Check for CSRmesh-known structure**: if confirmed as CSRmesh, compare payload structure against publicly documented/reverse-engineered CSRmesh implementations (several exist as open-source Python projects) to map opcodes faster instead of starting from scratch.
7. **Produce a command map**: a clear table/spec of "action → exact bytes to write to which handle/characteristic," suitable for reimplementing in a standalone script.
8. **Draft a minimal reference implementation**: a Python script using `bleak` (cross-platform, good fit for Raspberry Pi) that connects to the lamp and replays the identified commands for on/off, dim, and color — as a first working proof of concept before porting to ESP32 if desired.

## Open Questions / Risks to Flag During Analysis

- Whether the protocol uses **encryption at the ATT layer** (LE Secure Connections) — if so, captured payloads may be ciphertext, and we'd need session keys from the capture (PacketLogger sometimes logs these) or another approach.
- Whether commands include any **rolling/sequence counter** or other state that needs to be tracked, not just static payloads.
- Whether multiple lamps on the same mesh require a **device/group ID** in the payload, vs. each lamp being addressed individually.

## End Goal Deliverable

A standalone script (Python on Raspberry Pi, or C/C++ on ESP32) that can control the ØS1 lamps' power, dimming, and color directly over BLE, with no dependency on the Better Light app or Shadelights/Phil Zen infrastructure.
