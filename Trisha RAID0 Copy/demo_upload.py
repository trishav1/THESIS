#!/usr/bin/env python3
"""Upload a local file into the demo RAID0 storage and show chunk paths/sizes.

Usage (PowerShell):
  python demo_upload.py -f C:\path\to\localfile.txt
  python demo_upload.py -f ./mybin.bin -n /uploads/mybin.bin --storage ./storage_demo_ST1_raid0 --num-devices 3

The script initializes a `StorageModule` with RAID0 and the given `num_devices`, stores
the file, and prints metadata including where each chunk was written.
"""

import argparse
import os
from storage_module import StorageModule


def main():
    p = argparse.ArgumentParser(description="Upload a local file to RAID0 demo storage")
    p.add_argument('-f', '--file', required=True, help='Local file path to upload')
    p.add_argument('-n', '--name', required=False, help='Logical content name (e.g. /files/foo.txt). Defaults to /<basename>')
    p.add_argument('--num-devices', type=int, default=2, help='Number of simulated devices for RAID (RAID0/RAID1)')
    p.add_argument('--raid', type=int, default=0, choices=[0,1,5,6], help='RAID level to use (0,1,5,6)')

    args = p.parse_args()

    local_path = args.file
    if not os.path.exists(local_path):
        print(f"Local file not found: {local_path}")
        return

    logical_name = args.name or ('/' + os.path.basename(local_path))

    # Default device paths (top-level storage nodes)
    device_paths = [os.path.abspath('./storage_ST1'), os.path.abspath('./storage_ST2')]

    # Initialize storage module using explicit device paths so chunks or mirrors
    # are written into `./storage_ST1` and `./storage_ST2` directories.
    sm = StorageModule('DemoUploader', raid_level=args.raid, storage_path='./storage_pool', num_devices=args.num_devices, device_paths=device_paths)

    with open(local_path, 'rb') as f:
        data = f.read()

    print(f"Storing {len(data)} bytes as {logical_name} into {device_paths} (num_devices={args.num_devices}, raid={args.raid})")
    resp = sm.store_file(logical_name, data)
    print('store_file success:', resp.success)
    if not resp.success:
        print('Error:', resp.error)
        return

    meta = sm.stored_files.get(logical_name)
    if not meta:
        print('No metadata found for', logical_name)
        return

    print('\nMetadata:')
    print('  original_size:', meta.original_size)
    print('  stored_size:', meta.stored_size)
    print('  num_devices:', meta.num_devices)
    print('  chunk_size:', meta.chunk_size)
    print('  fragments (1-based index -> path):')
    for idx in sorted(meta.fragments.keys()):
        path = meta.fragments[idx]
        exists = os.path.exists(path)
        size = os.path.getsize(path) if exists else None
        print(f'    {idx}: {path} (exists={exists}, size={size})')

    print('\nTo inspect chunks on disk (PowerShell):')
    print(f"  Get-ChildItem {device_paths[0]} -File | Format-Table Name,Directory,Length -AutoSize")
    print(f"  Get-ChildItem {device_paths[1]} -File | Format-Table Name,Directory,Length -AutoSize")

    # Show retrieval check
    ret = sm.retrieve_file(logical_name)
    print('\nRetrieval success:', ret.success)
    if ret.success:
        print('Retrieved size:', len(ret.content))
    else:
        print('Retrieve error:', ret.error)


if __name__ == '__main__':
    main()
