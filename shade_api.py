#!/usr/bin/env python3
"""
Shadelights ØS1 REST API with persistent BLE connection.

Keeps a permanent BleakClient open to one lamp so commands are sent
immediately over an established connection (~50ms) rather than waiting
for a new BLE connection on every request (~3-5s).

Endpoints:
  POST /on
  POST /off
  POST /scene/<1-4>
  GET  /status
"""

import asyncio, threading, sys
from flask import Flask, jsonify
from bleak import BleakClient, BleakError

sys.path.insert(0, '/home/jjn/shadelights')
import mesh_crypto as mc

HOST = '0.0.0.0'
PORT = 8765
LAMP_ADDR = list(mc.LAMP_GATT.values())[0]   # proxy into the mesh via one lamp

app = Flask(__name__)
_state = {'power': 'off', 'scene': None}

# ── Persistent BLE connection in a background asyncio loop ────────────────────

_loop = asyncio.new_event_loop()
threading.Thread(target=_loop.run_forever, daemon=True).start()

_client: BleakClient | None = None

async def _ensure_connected() -> BleakClient:
    global _client
    if _client and _client.is_connected:
        return _client
    _client = BleakClient(LAMP_ADDR, timeout=15)
    await _client.connect()
    return _client

async def _send(make_access) -> bool:
    """Send a mesh command.  make_access(tid) -> access PDU bytes.
    Retries once with a fresh connection on failure."""
    global _client
    for attempt in range(2):
        try:
            seq    = mc.next_seq()
            access = make_access(seq & 0xff)
            pdu    = mc.build_network_pdu_raw(access, mc.GROUP_ADDR, seq)
            proxy  = mc.proxy_pdu(0x00, pdu)
            client = await _ensure_connected()
            await client.write_gatt_char(mc.PROXY_DATA_IN, proxy, response=False)
            return True
        except (BleakError, Exception):
            _client = None
            if attempt == 0:
                await asyncio.sleep(0.3)
    return False

def _dispatch(make_access) -> bool:
    future = asyncio.run_coroutine_threadsafe(_send(make_access), _loop)
    return future.result(timeout=15)

# ── Routes ────────────────────────────────────────────────────────────────────

@app.post('/on')
def turn_on():
    ok = _dispatch(lambda tid: bytes([0x82, 0x03, 0x01, tid]))
    if ok:
        _state['power'] = 'on'
    return jsonify({'ok': ok, 'state': _state}), (200 if ok else 500)

@app.post('/off')
def turn_off():
    ok = _dispatch(lambda tid: bytes([0x82, 0x03, 0x00, tid]))
    if ok:
        _state['power'] = 'off'
    return jsonify({'ok': ok, 'state': _state}), (200 if ok else 500)

@app.post('/scene/<int:n>')
def set_scene(n):
    if n < 1:
        return jsonify({'error': 'scene must be >= 1'}), 400
    scene_idx = n - 1
    ok = _dispatch(lambda tid: bytes([0xE3, 0x59, 0x00, scene_idx, tid]))
    if ok:
        _state['power'] = 'on'
        _state['scene'] = n
    return jsonify({'ok': ok, 'state': _state}), (200 if ok else 500)

@app.get('/status')
def status():
    return jsonify(_state)

if __name__ == '__main__':
    app.run(host=HOST, port=PORT)
