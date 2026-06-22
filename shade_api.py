#!/usr/bin/env python3
"""
Minimal HTTP REST API for Shadelights ØS1 lamp control.
Runs on the Raspberry Pi; Home Assistant calls it via rest_command.

Endpoints:
  POST /on
  POST /off
  POST /scene/<1-4>
  GET  /status

Start:  python3 shade_api.py
Or via systemd: see shadelights.service
"""

import subprocess, sys, json
from flask import Flask, jsonify

HOST = '0.0.0.0'
PORT = 8765
SCRIPT = '/home/jjn/shadelights/mesh_crypto.py'

app = Flask(__name__)
_state = {'power': 'off', 'scene': None}

def _run(*args):
    result = subprocess.run(
        [sys.executable, SCRIPT, *args],
        capture_output=True, text=True, timeout=20
    )
    return result.returncode == 0

@app.post('/on')
def turn_on():
    ok = _run('on')
    if ok:
        _state['power'] = 'on'
    return jsonify({'ok': ok, 'state': _state}), (200 if ok else 500)

@app.post('/off')
def turn_off():
    ok = _run('off')
    if ok:
        _state['power'] = 'off'
    return jsonify({'ok': ok, 'state': _state}), (200 if ok else 500)

@app.post('/scene/<int:n>')
def set_scene(n):
    if n not in range(1, 5):
        return jsonify({'error': 'scene must be 1-4'}), 400
    ok = _run('scene', str(n))
    if ok:
        _state['power'] = 'on'
        _state['scene'] = n
    return jsonify({'ok': ok, 'state': _state}), (200 if ok else 500)

@app.get('/status')
def status():
    return jsonify(_state)

if __name__ == '__main__':
    app.run(host=HOST, port=PORT)
