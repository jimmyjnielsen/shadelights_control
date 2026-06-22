#!/usr/bin/env python3
"""
Shadelights ØS1 BLE Mesh control over GATT Proxy.

Fill in your own keys and addresses below — see README.md for how to
extract them from the Better Light iOS app using iMazing.

Usage:
    python3 mesh_crypto.py on          # turn all lamps on
    python3 mesh_crypto.py off         # turn all lamps off
    python3 mesh_crypto.py scene <1-4> # activate a saved scene
    python3 mesh_crypto.py on   c001   # explicit group address
    python3 mesh_crypto.py info        # print derived key material
"""

import asyncio, struct, sys
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from bleak import BleakClient

# ── Keys — fill in your own (see README.md) ───────────────────────────────────
# Extract from: iMazing → Better Light app → Container/Documents/shade/
# File: provisionModelData  (JSON, keys are hex strings)
NET_KEY = bytes.fromhex('YOUR_NET_KEY_HEX_HERE')
APP_KEY = bytes.fromhex('YOUR_APP_KEY_HEX_HERE')

# ── Mesh addresses — fill in your own ────────────────────────────────────────
# Run scan_lamps.py to find lamp BLE MACs; mesh addresses are in provisionModelData
LAMP_GATT = {
    0x0021: 'AA:BB:CC:DD:EE:FF',   # Lamp 1 BLE MAC → mesh unicast address
    0x0041: 'AA:BB:CC:DD:EE:FE',   # Lamp 2 BLE MAC → mesh unicast address
}
GROUP_ADDR  = 0xC001   # group address for all lamps (from provisionModelData)
PROV_ADDR   = 0x0001   # provisioner unicast address (from provisionModelData)
IV_INDEX    = 0x00000000   # from provisionModelData ivIndex field
SEQ_FILE    = '/home/pi/.shade_seq'   # persists sequence counter between invocations

def next_seq() -> int:
    """Load, increment, save and return the next 24-bit sequence number."""
    try:
        seq = int(open(SEQ_FILE).read().strip()) + 1
    except Exception:
        seq = 1
    open(SEQ_FILE, 'w').write(str(seq))
    return seq

# ── GATT characteristics ──────────────────────────────────────────────────────
PROXY_DATA_IN  = '00002add-0000-1000-8000-00805f9b34fb'   # write-without-response
PROXY_DATA_OUT = '00002ade-0000-1000-8000-00805f9b34fb'   # notify

# ── BLE Mesh crypto primitives ────────────────────────────────────────────────

def aes_cmac(key: bytes, msg: bytes) -> bytes:
    c = CMAC(algorithms.AES(key)); c.update(msg); return c.finalize()

def aes_ecb(key: bytes, block: bytes) -> bytes:
    return Cipher(algorithms.AES(key), modes.ECB()).encryptor().update(block)

def s1(m: bytes) -> bytes:
    return aes_cmac(b'\x00' * 16, m)

def k1(n: bytes, salt: bytes, p: bytes) -> bytes:
    t = aes_cmac(salt, n)
    return aes_cmac(t, p)

def k2(n: bytes, p: bytes) -> tuple[int, bytes, bytes]:
    """(NID 7-bit, EncryptionKey 16B, PrivacyKey 16B) for master security."""
    salt = s1(b'smk2')
    t    = aes_cmac(salt, n)
    t1   = aes_cmac(t, p + b'\x01')
    t2   = aes_cmac(t, t1 + p + b'\x02')
    t3   = aes_cmac(t, t2 + p + b'\x03')
    return t1[-1] & 0x7f, t2, t3

def k3(n: bytes) -> bytes:
    """Network ID = k3(NetKey) = last 8 bytes (T mod 2^64)."""
    salt = s1(b'nkbk')
    t    = aes_cmac(salt, n)
    return aes_cmac(t, b'id64\x01')[-8:]

def k4(n: bytes) -> int:
    """AID = k4(AppKey) = 6-bit value."""
    salt = s1(b'smk4')
    t    = aes_cmac(salt, n)
    return aes_cmac(t, b'id6\x01')[-1] & 0x3f

# ── Network PDU construction ──────────────────────────────────────────────────

def _aes_ccm(key: bytes, nonce: bytes, plaintext: bytes, mic_len: int) -> bytes:
    """AES-CCM; returns ciphertext + MIC (mic_len bytes appended)."""
    return AESCCM(key, tag_length=mic_len).encrypt(nonce, plaintext, None)

def _app_nonce(aszmic: int, seq: int, src: int, dst: int, iv: int) -> bytes:
    # 0x01 | ASZMIC<<7 | SEQ[0:3] | SRC | DST | IVIndex  (13 bytes total)
    return (bytes([0x01, aszmic << 7])
            + struct.pack('>I', seq)[1:]          # seq as 3 bytes
            + struct.pack('>HHI', src, dst, iv))  # 2+2+4 bytes

def _net_nonce(ctl: int, ttl: int, seq: int, src: int, iv: int) -> bytes:
    # 0x00 | CTL<<7|TTL | SEQ[0:3] | SRC | 0x0000 | IVIndex  (13 bytes total)
    return (bytes([0x00, (ctl << 7) | (ttl & 0x7f)])
            + struct.pack('>I', seq)[1:]          # seq as 3 bytes
            + struct.pack('>H', src)              # 2 bytes
            + b'\x00\x00'                         # padding
            + struct.pack('>I', iv))              # 4 bytes

def build_access_pdu(opcode: bytes, params: bytes) -> bytes:
    return opcode + params

def build_network_pdu_raw(access_pdu: bytes, dst: int, seq: int = 1,
                           ttl: int = 5, src: int = PROV_ADDR,
                           iv: int = IV_INDEX) -> bytes:
    ctl = 0
    aid       = k4(APP_KEY)
    seg_akf   = (0 << 7) | (1 << 6) | (aid & 0x3f)
    app_nonce = _app_nonce(0, seq, src, dst, iv)
    upper_enc = _aes_ccm(APP_KEY, app_nonce, access_pdu, mic_len=4)
    lower_pdu = bytes([seg_akf]) + upper_enc
    nid, enc_key, priv_key = k2(NET_KEY, b'\x00')
    net_nonce  = _net_nonce(ctl, ttl, seq, src, iv)
    plaintext  = struct.pack('>H', dst) + lower_pdu
    enc_out    = _aes_ccm(enc_key, net_nonce, plaintext, mic_len=4)
    enc_dst    = enc_out[:2]
    enc_trans  = enc_out[2:-4]
    net_mic    = enc_out[-4:]
    ivi        = iv & 0x01
    priv_rand  = enc_dst + enc_trans[:5]
    pecb_in    = b'\x00'*5 + struct.pack('>I', iv) + priv_rand
    pecb       = aes_ecb(priv_key, pecb_in[:16])
    plain_hdr  = bytes([(ctl<<7)|(ttl&0x7f)]) + struct.pack('>I',seq)[1:] + struct.pack('>H',src)
    obf_hdr    = bytes(a^b for a,b in zip(plain_hdr, pecb[:6]))
    ivi_nid    = bytes([(ivi<<7)|(nid&0x7f)])
    return ivi_nid + obf_hdr + enc_dst + enc_trans + net_mic

def build_network_pdu(onoff: bool, dst: int, seq: int = 1,
                      ttl: int = 5, src: int = PROV_ADDR,
                      iv: int = IV_INDEX) -> bytes:
    """
    Build a BLE Mesh Network PDU for Generic OnOff Set Unacknowledged (0x8203).
    """
    ctl = 0                          # access message
    tid = seq & 0xff

    # 1. Access PDU: opcode 0x8203, params: OnOff | TID
    access_pdu = bytes([0x82, 0x03, 0x01 if onoff else 0x00, tid])

    # 2. Upper Transport PDU: AES-CCM(AppKey, AppNonce, AccessPDU, MIC=4B)
    app_nonce   = _app_nonce(0, seq, src, dst, iv)
    upper_enc   = _aes_ccm(APP_KEY, app_nonce, access_pdu, mic_len=4)  # 8 bytes

    # 3. Lower Transport PDU (unsegmented, AKF=1, AID from AppKey)
    aid       = k4(APP_KEY)
    seg_akf   = (0 << 7) | (1 << 6) | (aid & 0x3f)   # SEG=0, AKF=1, AID
    lower_pdu = bytes([seg_akf]) + upper_enc            # 1 + 8 = 9 bytes

    # 4. k2 for NID, EncryptionKey, PrivacyKey
    nid, enc_key, priv_key = k2(NET_KEY, b'\x00')

    # 5. Encrypt DST + LowerTransportPDU with EncryptionKey
    net_nonce  = _net_nonce(ctl, ttl, seq, src, iv)
    plaintext  = struct.pack('>H', dst) + lower_pdu    # 2 + 9 = 11 bytes
    enc_out    = _aes_ccm(enc_key, net_nonce, plaintext, mic_len=4)  # 15 bytes
    enc_dst    = enc_out[:2]
    enc_trans  = enc_out[2:11]
    net_mic    = enc_out[11:15]

    # 6. Obfuscate: XOR (CTL|TTL | SEQ | SRC) with PECB[:6]
    ivi         = iv & 0x01
    priv_rand   = enc_dst + enc_trans[:5]              # 7 bytes
    pecb_input  = b'\x00' * 5 + struct.pack('>I', iv) + priv_rand   # 16 bytes
    pecb        = aes_ecb(priv_key, pecb_input)

    plain_hdr  = bytes([(ctl << 7) | (ttl & 0x7f)]) + struct.pack('>I', seq)[1:] + struct.pack('>H', src)
    obf_hdr    = bytes(a ^ b for a, b in zip(plain_hdr, pecb[:6]))

    # 7. Final Network PDU
    ivi_nid = bytes([(ivi << 7) | (nid & 0x7f)])
    return ivi_nid + obf_hdr + enc_dst + enc_trans + net_mic


def proxy_pdu(msg_type: int, data: bytes) -> bytes:
    return bytes([(0b00 << 6) | (msg_type & 0x3f)]) + data


# ── GATT Mesh Proxy sending ───────────────────────────────────────────────────

async def _send_raw(net_pdu: bytes):
    proxy_msg = proxy_pdu(0x00, net_pdu)
    for gatt_addr in list(LAMP_GATT.values()):
        try:
            async with BleakClient(gatt_addr, timeout=15) as client:
                notifications = []
                def on_notify(_, data): notifications.append(data.hex())
                await client.start_notify(PROXY_DATA_OUT, on_notify)
                await client.write_gatt_char(PROXY_DATA_IN, proxy_msg, response=False)
                print(f"  Sent to {gatt_addr}")
                await asyncio.sleep(1)
                for n in notifications: print(f"  [NOTIFY] {n}")
                await client.stop_notify(PROXY_DATA_OUT)
        except Exception as e:
            print(f"  {gatt_addr}: {e}")
        break

async def send(onoff: bool, dst: int, seq: int = 0):
    if seq == 0:
        seq = next_seq()
    net_pdu   = build_network_pdu(onoff, dst, seq)
    proxy_msg = proxy_pdu(0x00, net_pdu)   # type 0 = Network PDU
    print(f"{'ON' if onoff else 'OFF'} → dst=0x{dst:04x}  seq={seq}")
    print(f"  NetPDU  : {net_pdu.hex()}")
    print(f"  ProxyPDU: {proxy_msg.hex()}")

    # Try each lamp's GATT connection
    gatt_targets = list(LAMP_GATT.values())

    for gatt_addr in gatt_targets:
        try:
            async with BleakClient(gatt_addr, timeout=15) as client:
                notifications = []
                def on_notify(_, data):
                    notifications.append(data.hex())
                await client.start_notify(PROXY_DATA_OUT, on_notify)
                await client.write_gatt_char(PROXY_DATA_IN, proxy_msg, response=False)
                print(f"  Sent to {gatt_addr}")
                await asyncio.sleep(1)
                for n in notifications:
                    print(f"  [NOTIFY] {n}")
                await client.stop_notify(PROXY_DATA_OUT)
        except Exception as e:
            print(f"  {gatt_addr}: {e}")
        break   # one connection is enough for a mesh message


def main():
    CMDS = ('on', 'off', 'info', 'brightness', 'ct', 'level', 'scene')
    if len(sys.argv) < 2 or sys.argv[1] not in CMDS:
        print(__doc__)
        sys.exit(1)

    if sys.argv[1] == 'info':
        nid, enc, priv = k2(NET_KEY, b'\x00')
        aid = k4(APP_KEY)
        nid_pub = k3(NET_KEY)
        print(f"NetKey : {NET_KEY.hex()}")
        print(f"AppKey : {APP_KEY.hex()}")
        print(f"NID    : 0x{nid:02x}  (7-bit, goes in Network PDU header)")
        print(f"AID    : 0x{aid:02x}  (6-bit, AppKey ID in Lower Transport PDU)")
        print(f"k3 NID : {nid_pub.hex()}  (from Network ID beacon)")
        print(f"Enc key: {enc.hex()}")
        print(f"Priv   : {priv.hex()}")
        return

    # Extended commands for brightness / color temperature
    if sys.argv[1] == 'brightness':
        # Light Lightness Set Unacknowledged: opcode 0x824C, lightness 0-65535, TID
        if len(sys.argv) < 3:
            print("Usage: brightness <0-100>"); sys.exit(1)
        pct       = int(sys.argv[2])
        lightness = int(pct / 100 * 65535) & 0xFFFF
        seq       = next_seq()
        dst       = int(sys.argv[3], 16) if len(sys.argv) > 3 else GROUP_ADDR
        access    = bytes([0x82, 0x4c]) + struct.pack('<H', lightness) + bytes([seq & 0xff])
        pdu       = build_network_pdu_raw(access, dst, seq)
        print(f"Light Lightness {pct}% ({lightness}) → dst=0x{dst:04x}  seq={seq}")
        print(f"  Access PDU: {access.hex()}")
        asyncio.run(_send_raw(pdu)); return

    if sys.argv[1] == 'ct':
        # Light CTL Set Unacknowledged: opcode 0x825E
        # lightness(2) + temperature(2, 800-20000K) + delta_uv(2) + TID(1)
        if len(sys.argv) < 4:
            print("Usage: ct <brightness_pct> <temp_K>"); sys.exit(1)
        pct       = int(sys.argv[2])
        temp_k    = int(sys.argv[3])
        lightness = int(pct / 100 * 65535) & 0xFFFF
        temp_k    = max(800, min(20000, temp_k))
        seq       = next_seq()
        dst       = int(sys.argv[4], 16) if len(sys.argv) > 4 else GROUP_ADDR
        access    = bytes([0x82, 0x5e]) + struct.pack('<HHh', lightness, temp_k, 0) + bytes([seq & 0xff])
        pdu       = build_network_pdu_raw(access, dst, seq)
        print(f"Light CTL {pct}% @ {temp_k}K → dst=0x{dst:04x}  seq={seq}")
        print(f"  Access PDU: {access.hex()}")
        asyncio.run(_send_raw(pdu)); return

    if sys.argv[1] == 'level':
        # Generic Level Set Unacknowledged: opcode 0x8208, level -32768..32767
        if len(sys.argv) < 3:
            print("Usage: level <-100..100>"); sys.exit(1)
        pct   = int(sys.argv[2])
        level = int(pct / 100 * 32767)
        seq   = next_seq()
        dst   = int(sys.argv[3], 16) if len(sys.argv) > 3 else GROUP_ADDR
        access = bytes([0x82, 0x08]) + struct.pack('<h', level) + bytes([seq & 0xff])
        pdu    = build_network_pdu_raw(access, dst, seq)
        print(f"Generic Level {pct}% ({level}) → dst=0x{dst:04x}  seq={seq}")
        print(f"  Access PDU: {access.hex()}")
        asyncio.run(_send_raw(pdu)); return

    if sys.argv[1] == 'scene':
        # Nordic vendor model scene select (company 0x0059, opcode 0x23).
        # Opcode bytes: 0xE3 0x59 0x00  (0xC0|0x23, company_lo, company_hi)
        # Params: scene_index (0-based) + TID (increments per send).
        # Scene number n maps to index n-1; the number of scenes depends on
        # what the user has configured in the Better Light app.
        if len(sys.argv) < 3:
            print("Usage: scene <n>  [dst_hex]"); sys.exit(1)
        scene_num = int(sys.argv[2])
        if scene_num < 1:
            print("Scene number must be >= 1"); sys.exit(1)
        seq        = next_seq()
        dst        = int(sys.argv[3], 16) if len(sys.argv) > 3 else GROUP_ADDR
        scene_idx  = scene_num - 1          # 0-based
        tid        = seq & 0xff
        access     = bytes([0xE3, 0x59, 0x00, scene_idx, tid])
        pdu        = build_network_pdu_raw(access, dst, seq)
        print(f"Scene {scene_num} (idx={scene_idx} tid=0x{tid:02x}) → dst=0x{dst:04x}  seq={seq}")
        print(f"  Access PDU: {access.hex()}")
        asyncio.run(_send_raw(pdu)); return

    onoff = sys.argv[1] == 'on'
    dst   = int(sys.argv[2], 16) if len(sys.argv) > 2 else GROUP_ADDR
    asyncio.run(send(onoff, dst))


if __name__ == '__main__':
    main()
