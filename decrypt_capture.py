#!/usr/bin/env python3
"""Decrypt BLE Mesh PDUs from pcapng capture using our known keys."""
import sys, struct, subprocess
sys.path.insert(0, '/Users/jjn/repos/shadelights')
from mesh_crypto import k2, k4, NET_KEY, APP_KEY, IV_INDEX, aes_ecb
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

def _ccm_decrypt(key, nonce, ciphertext_with_tag, mic_len):
    return AESCCM(key, tag_length=mic_len).decrypt(nonce, ciphertext_with_tag, None)

TSHARK = '/Applications/Wireshark.app/Contents/MacOS/tshark'
PCAP   = '/Users/jjn/repos/shadelights/betterlight_scene-sweep-twice.pcapng'

nid, enc_key, priv_key = k2(NET_KEY, b'\x00')
aid_expected = k4(APP_KEY)

def _net_nonce(ctl, ttl, seq, src, iv):
    return (b'\x00'
            + bytes([(ctl << 7) | (ttl & 0x7f)])
            + struct.pack('>I', seq)[1:]
            + struct.pack('>H', src)
            + b'\x00\x00'
            + struct.pack('>I', iv))

def _app_nonce(seg, seq, src, dst, iv):
    return (b'\x01'
            + bytes([seg & 0x01])
            + struct.pack('>I', seq)[1:]
            + struct.pack('>H', src)
            + struct.pack('>H', dst)
            + struct.pack('>I', iv))

def parse_opcode(data):
    if not data:
        return "empty", b''
    b0 = data[0]
    if b0 & 0xC0 == 0xC0:        # vendor (3-byte opcode)
        op = data[:3]
        company = struct.unpack_from('<H', data, 1)[0]
        return f"VENDOR op=0x{op.hex()} company=0x{company:04x}", data[3:]
    elif b0 & 0x80:               # 2-byte opcode
        op = data[:2]
        return f"0x{op.hex()}", data[2:]
    else:                         # 1-byte opcode
        return f"0x{b0:02x}", data[1:]

# Extract obfuscated header and encrypted data from verbose tshark output
result = subprocess.run([TSHARK, '-r', PCAP, '-Y', 'btmesh', '-V'],
                        capture_output=True, text=True)

packets = []
cur = {}
for line in result.stdout.splitlines():
    s = line.strip()
    if s.startswith('Frame ') and 'bytes on wire' in s:
        if cur.get('obf') and cur.get('enc'):
            packets.append(cur)
        cur = {}
        cur['frame'] = s.split()[1].rstrip(':')
    elif '= IVI:' in s:
        cur['ivi'] = int(s.split()[-1])
    elif s.startswith('Obfuscated:'):
        cur['obf'] = bytes.fromhex(s.split()[-1])
    elif s.startswith('Encrypted data and NetMIC:'):
        cur['enc'] = bytes.fromhex(s.split()[-1])
    elif 'time_relative' in s.lower() or 'Arrival Time' in s:
        pass
    elif s.startswith('Advertising Address:'):
        cur['adv_addr'] = s.split()[-1]

if cur.get('obf') and cur.get('enc'):
    packets.append(cur)

print(f"Found {len(packets)} mesh PDUs to decrypt\n")
print(f"{'Frame':>6}  {'SRC':>6}  {'DST':>6}  {'SEQ':>8}  {'TTL':>3}  Access PDU / Opcode")
print('-' * 90)

for p in packets:
    obf = p['obf']
    enc = p['enc']
    iv  = IV_INDEX

    # enc = enc_dst(2) + enc_trans(N) + netmic(4)
    enc_dst_bytes  = enc[:2]
    enc_trans      = enc[2:-4]
    netmic         = enc[-4:]

    # Deobfuscate header
    priv_rand = enc_dst_bytes + enc_trans[:5]
    pecb_in   = b'\x00' * 5 + struct.pack('>I', iv) + priv_rand
    pecb      = aes_ecb(priv_key, pecb_in)
    plain_hdr = bytes(a ^ b for a, b in zip(obf, pecb[:6]))

    ctl_ttl = plain_hdr[0]
    ctl     = (ctl_ttl >> 7) & 1
    ttl     = ctl_ttl & 0x7f
    seq     = int.from_bytes(plain_hdr[1:4], 'big')
    src     = int.from_bytes(plain_hdr[4:6], 'big')

    # Decrypt network layer
    net_nonce = _net_nonce(ctl, ttl, seq, src, iv)
    try:
        plain_net = _ccm_decrypt(enc_key, net_nonce, enc, mic_len=4)
    except Exception as e:
        print(f"{p['frame']:>6}  0x{src:04x}  ??      {seq:>8}  {ttl:>3}  [net decrypt failed: {e}]")
        continue

    dst          = int.from_bytes(plain_net[:2], 'big')
    lower_trans  = plain_net[2:]

    # Parse lower transport (unsegmented assumed)
    ltb0  = lower_trans[0]
    seg   = (ltb0 >> 7) & 1
    akf   = (ltb0 >> 6) & 1
    aid   = ltb0 & 0x3f

    if seg:
        print(f"{p['frame']:>6}  0x{src:04x}  0x{dst:04x}  {seq:>8}  {ttl:>3}  [segmented - skipping]")
        continue

    if ctl:
        print(f"{p['frame']:>6}  0x{src:04x}  0x{dst:04x}  {seq:>8}  {ttl:>3}  [control msg, lower={lower_trans.hex()}]")
        continue

    if not akf:
        print(f"{p['frame']:>6}  0x{src:04x}  0x{dst:04x}  {seq:>8}  {ttl:>3}  [device key msg]")
        continue

    # Decrypt upper transport (app key)
    enc_access_mic = lower_trans[1:]
    app_nonce = _app_nonce(0, seq, src, dst, iv)
    try:
        access = _ccm_decrypt(APP_KEY, app_nonce, enc_access_mic, mic_len=4)
    except Exception:
        print(f"{p['frame']:>6}  0x{src:04x}  0x{dst:04x}  {seq:>8}  {ttl:>3}  [app decrypt failed, aid=0x{aid:02x} expected=0x{aid_expected:02x}]")
        continue

    opcode, params = parse_opcode(access)
    print(f"{p['frame']:>6}  0x{src:04x}  0x{dst:04x}  {seq:>8}  {ttl:>3}  opcode={opcode}  params={params.hex()}")
