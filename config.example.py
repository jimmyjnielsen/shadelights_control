# Shadelights ØS1 — instance configuration
#
# Copy this file to config.py and fill in your own values.
# Extract them by running:
#
#   python3 parse_provision_data.py /path/to/shade --write-config
#
# The 'shade' file is exported from the Better Light iOS app via iMazing:
#   App → Files → Container/Documents/shade
#
# config.py is gitignored — never commit it.

# 16-byte mesh keys (hex strings, from provisionModelData)
NET_KEY = 'YOUR_NET_KEY_HEX_HERE'   # 32 hex chars (16 bytes)
APP_KEY = 'YOUR_APP_KEY_HEX_HERE'

# BLE MAC address for each lamp, keyed by mesh unicast address
# Mesh addresses and MACs come from houseData → rooms → orbs
LAMP_GATT = {
    0x0021: 'AA:BB:CC:DD:EE:FF',   # Lamp 1
    # 0x0041: 'AA:BB:CC:DD:EE:FE', # Lamp 2 (add more as needed)
}

# Mesh group address for all lamps (from provisionModelData → currentGroupId)
GROUP_ADDR = 0xC001

# Provisioner unicast address and IV index (defaults if not stored in your shade file)
PROV_ADDR = 0x0001
IV_INDEX  = 0x00000000

# Where to persist the sequence counter between invocations (must be writable)
SEQ_FILE = '/home/pi/shadelights/.shade_seq'
