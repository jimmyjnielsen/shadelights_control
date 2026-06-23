#!/usr/bin/env python3
"""
Shadelights ØS1 REST API with persistent BLE connection.

Uses Quart (async Flask) so BLE and HTTP share one asyncio event loop —
no cross-thread issues with bleak's BlueZ backend.

Endpoints:
  POST /on
  POST /off
  POST /scene/<n>
  POST /color   JSON body: {top_warm, top_cold, bottom_warm, bottom_cold,
                             mid_warm, mid_red, mid_green, mid_blue}  (0-4095)
  GET  /status
"""

import asyncio, sys
from quart import Quart, jsonify, request
from bleak import BleakClient, BleakScanner, BleakError

import mesh_crypto as mc

HOST = '0.0.0.0'
PORT = 8765
LAMP_ADDRS = list(mc.LAMP_GATT.values())   # try each until one answers

app = Quart(__name__)
_state = {'power': 'off', 'scene': None}
_client: BleakClient | None = None
_send_lock = asyncio.Lock()

async def _ensure_connected() -> BleakClient:
    global _client
    if _client and _client.is_connected:
        return _client
    # Scan to populate BlueZ's device cache, then try each known lamp address.
    found = {d.address: d
             for d in await BleakScanner.discover(timeout=8)
             if d.address in LAMP_ADDRS}
    for addr in LAMP_ADDRS:
        device = found.get(addr)
        if device is None:
            continue
        try:
            _client = BleakClient(device, timeout=12)
            await _client.connect()
            return _client
        except (BleakError, Exception):
            _client = None
    raise BleakError(f"No lamp found among {LAMP_ADDRS}")

async def _send(*make_access_fns) -> bool:
    """Send one or more mesh commands. make_access(tid) -> bytes per fn."""
    global _client
    async with _send_lock:
        for attempt in range(2):
            try:
                client = await _ensure_connected()
                for make_access in make_access_fns:
                    seq    = mc.next_seq()
                    access = make_access(seq & 0xff)
                    pdu    = mc.build_network_pdu_raw(access, mc.GROUP_ADDR, seq)
                    proxy  = mc.proxy_pdu(0x00, pdu)
                    await client.write_gatt_char(mc.PROXY_DATA_IN, proxy, response=False)
                return True
            except (BleakError, Exception):
                _client = None
                if attempt == 0:
                    await asyncio.sleep(0.5)
    return False

# ── Routes ────────────────────────────────────────────────────────────────────

@app.post('/on')
async def turn_on():
    ok = await _send(lambda tid: bytes([0x82, 0x03, 0x01, tid]))
    if ok:
        _state['power'] = 'on'
    return jsonify({'ok': ok, 'state': _state}), (200 if ok else 500)

@app.post('/off')
async def turn_off():
    ok = await _send(lambda tid: bytes([0x82, 0x03, 0x00, tid]))
    if ok:
        _state['power'] = 'off'
    return jsonify({'ok': ok, 'state': _state}), (200 if ok else 500)

@app.post('/scene/<int:n>')
async def set_scene(n):
    if n < 1:
        return jsonify({'error': 'scene must be >= 1'}), 400
    scene_idx = n - 1
    ok = await _send(lambda tid: bytes([0xE3, 0x59, 0x00, scene_idx, tid]))
    if ok:
        _state['power'] = 'on'
        _state['scene'] = n
        _state.pop('color', None)
    return jsonify({'ok': ok, 'state': _state}), (200 if ok else 500)

@app.post('/color')
async def set_color():
    body = await request.get_json(silent=True) or {}
    keys = ['top_warm', 'top_cold', 'bottom_warm', 'bottom_cold',
            'mid_warm', 'mid_red', 'mid_green', 'mid_blue']
    try:
        vals = {k: int(body[k]) for k in keys}
    except (KeyError, ValueError, TypeError) as e:
        return jsonify({'error': f'missing or invalid field: {e}'}), 400
    for k, v in vals.items():
        if not 0 <= v <= 4095:
            return jsonify({'error': f'{k} must be 0-4095'}), 400

    def make_18(tid):
        a18, _ = mc.build_color_access_pdus(
            vals['top_warm'], vals['top_cold'],
            vals['bottom_warm'], vals['bottom_cold'],
            vals['mid_warm'], vals['mid_red'], vals['mid_green'], vals['mid_blue'],
            tid=tid,
        )
        return a18

    def make_19(tid):
        _, a19 = mc.build_color_access_pdus(
            vals['top_warm'], vals['top_cold'],
            vals['bottom_warm'], vals['bottom_cold'],
            vals['mid_warm'], vals['mid_red'], vals['mid_green'], vals['mid_blue'],
            tid=tid,
        )
        return a19

    ok = await _send(make_18, make_19)
    if ok:
        _state['power'] = 'on'
        _state['color'] = vals
        _state['scene'] = None
    return jsonify({'ok': ok, 'state': _state}), (200 if ok else 500)

@app.post('/brightness')
async def set_brightness():
    body = await request.get_json(silent=True) or {}
    try:
        pct = int(body['pct'])
    except (KeyError, ValueError, TypeError) as e:
        return jsonify({'error': f'missing or invalid field: {e}'}), 400
    if not 0 <= pct <= 100:
        return jsonify({'error': 'pct must be 0-100'}), 400

    lightness = int(pct / 100 * 65535) & 0xFFFF
    lo, hi = lightness & 0xff, (lightness >> 8) & 0xff

    # Light Lightness Set Unacknowledged (SIG Mesh opcode 0x824C)
    ok = await _send(lambda tid: bytes([0x82, 0x4c, lo, hi, tid]))
    if ok:
        _state['brightness'] = pct
    return jsonify({'ok': ok, 'state': _state}), (200 if ok else 500)

@app.get('/status')
async def status():
    return jsonify(_state)

if __name__ == '__main__':
    app.run(host=HOST, port=PORT)
