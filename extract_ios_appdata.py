#!/usr/bin/env python3
"""
Extract Better Light app data from an iTunes/Finder iPhone backup.

Requirements:
  pip install iphone-backup-decrypt   # for encrypted backups

Usage:
  python3 extract_ios_appdata.py [backup_password]

Backup location on macOS: ~/Library/Application Support/MobileSync/Backup/
"""

import os
import sys
import json
import glob
import shutil
import plistlib
import sqlite3
import hashlib
from pathlib import Path

BACKUP_DIR = Path.home() / 'Library' / 'Application Support' / 'MobileSync' / 'Backup'
APP_BUNDLE  = 'one.shade.app'         # Better Light bundle ID
OUT_DIR     = Path('extracted_app_data')

def find_latest_backup() -> Path | None:
    backups = sorted(BACKUP_DIR.glob('*'), key=lambda p: p.stat().st_mtime, reverse=True)
    return backups[0] if backups else None

def is_encrypted(backup: Path) -> bool:
    info = backup / 'Info.plist'
    if not info.exists():
        return False
    with open(info, 'rb') as f:
        d = plistlib.load(f)
    return d.get('IsEncrypted', False)

def extract_unencrypted(backup: Path):
    """Find all files belonging to the app bundle in an unencrypted backup."""
    manifest = backup / 'Manifest.db'
    if not manifest.exists():
        print(f'Manifest.db not found in {backup}')
        return

    OUT_DIR.mkdir(exist_ok=True)
    conn = sqlite3.connect(manifest)
    rows = conn.execute(
        "SELECT fileID, relativePath, domain FROM Files "
        "WHERE domain LIKE ? OR relativePath LIKE ?",
        (f'%{APP_BUNDLE}%', f'%{APP_BUNDLE}%')
    ).fetchall()
    conn.close()

    print(f'Found {len(rows)} files for {APP_BUNDLE}')
    for file_id, rel_path, domain in rows:
        # backup file is at backup/<2-char-prefix>/<file_id>
        src = backup / file_id[:2] / file_id
        if src.exists():
            dest = OUT_DIR / file_id[:8] / rel_path.replace('/', '_')
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest)
            print(f'  {rel_path}  →  {dest}')
        else:
            print(f'  MISSING: {rel_path} ({file_id})')

def scan_for_keys(directory: Path):
    """Scan extracted files for JSON or SQLite with mesh key material."""
    print(f'\n=== Scanning {directory} for mesh key material ===')
    keywords = ['netKey', 'appKey', 'networkKey', 'meshKey', 'provisionKey',
                'net_key', 'app_key', 'network_key', b'netKey', b'appKey']

    for path in directory.rglob('*'):
        if path.is_dir():
            continue
        try:
            # Try JSON
            text = path.read_text(errors='replace')
            if any(k in text for k in keywords[:6]):
                print(f'\n[JSON candidate] {path}')
                try:
                    data = json.loads(text)
                    print(json.dumps(data, indent=2)[:2000])
                except Exception:
                    print(text[:1000])
        except Exception:
            pass

        try:
            # Try SQLite
            raw = path.read_bytes()
            if raw[:6] == b'SQLite':
                print(f'\n[SQLite candidate] {path}')
                conn2 = sqlite3.connect(path)
                for table, in conn2.execute("SELECT name FROM sqlite_master WHERE type='table'"):
                    cols_rows = conn2.execute(f'PRAGMA table_info("{table}")').fetchall()
                    cols = [r[1] for r in cols_rows]
                    print(f'  Table {table}: {cols}')
                    rows = conn2.execute(f'SELECT * FROM "{table}" LIMIT 5').fetchall()
                    for row in rows:
                        print(f'    {row}')
                conn2.close()
        except Exception:
            pass

        try:
            # Look for plist files with key material
            raw = path.read_bytes()
            if raw[:6] in (b'bplist', b'<?xml '):
                try:
                    d = plistlib.loads(raw)
                    text2 = str(d)
                    if any(k in text2 for k in keywords[:6]):
                        print(f'\n[plist candidate] {path}')
                        print(str(d)[:1000])
                except Exception:
                    pass
        except Exception:
            pass


def main():
    password = sys.argv[1] if len(sys.argv) > 1 else None

    backup = find_latest_backup()
    if not backup:
        print(f'No iPhone backup found in {BACKUP_DIR}')
        print('Connect iPhone, open Finder, and click "Back Up Now".')
        sys.exit(1)

    print(f'Latest backup : {backup}')
    print(f'Encrypted     : {is_encrypted(backup)}')

    if is_encrypted(backup):
        if not password:
            print('\nBackup is encrypted. Re-run with the backup password:')
            print(f'  python3 {sys.argv[0]} <your_backup_password>')
            print('\nOr use iMazing (free trial) to browse app data directly.')
            sys.exit(1)
        try:
            from iphone_backup_decrypt import EncryptedBackup, RelativePath
        except ImportError:
            print('Install: pip install iphone-backup-decrypt')
            sys.exit(1)
        eb = EncryptedBackup(backup_directory=str(backup), passphrase=password)
        OUT_DIR.mkdir(exist_ok=True)
        eb.extract_files(relative_paths_to_extract=[
            RelativePath.DOMAIN_APP_GROUPS,
        ], output_folder=str(OUT_DIR))
        # Also extract the specific domain
        try:
            eb.extract_files(
                relative_paths_to_extract=[f'AppDomain-{APP_BUNDLE}'],
                output_folder=str(OUT_DIR))
        except Exception:
            pass
    else:
        extract_unencrypted(backup)

    scan_for_keys(OUT_DIR)

if __name__ == '__main__':
    main()
