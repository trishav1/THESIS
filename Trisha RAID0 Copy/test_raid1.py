#!/usr/bin/env python3
import os
import shutil
from storage_module import StorageModule

ST1 = './test_storage_ST1'
ST2 = './test_storage_ST2'
POOL = './test_storage_pool'

# Cleanup from previous runs
for p in [ST1, ST2, POOL]:
    if os.path.exists(p):
        shutil.rmtree(p)

os.makedirs(ST1, exist_ok=True)
os.makedirs(ST2, exist_ok=True)

sm = StorageModule('TestRAID1', raid_level=1, storage_path=POOL, num_devices=2, device_paths=[os.path.abspath(ST1), os.path.abspath(ST2)])

name = '/test/raid1_sample.txt'
content = b'RAID1 test content for mirroring.'

print('Storing file...')
resp = sm.store_file(name, content)
print('Store response:', resp.success, resp.error if resp.error else '')
assert resp.success, 'Store failed when it should succeed'

meta = sm.stored_files.get(name)
assert meta is not None, 'Metadata missing after store'

# Check both mirrors exist
for idx in sorted(meta.fragments.keys()):
    path = meta.fragments[idx]
    print(f'Mirror {idx}:', path, 'exists=', os.path.exists(path))
    assert os.path.exists(path), f'Mirror missing: {path}'

# Delete one mirror and ensure retrieve still succeeds
first_mirror = meta.fragments[1]
print('Deleting first mirror:', first_mirror)
os.remove(first_mirror)
ret = sm.retrieve_file(name)
print('Retrieve after one mirror removed:', ret.success)
assert ret.success and ret.content == content, 'Retrieve failed after one mirror removal'

# Delete remaining mirror and ensure retrieve fails
second_mirror = meta.fragments[2]
print('Deleting second mirror:', second_mirror)
os.remove(second_mirror)
ret2 = sm.retrieve_file(name)
print('Retrieve after both mirrors removed:', ret2.success)
assert not ret2.success, 'Retrieve succeeded but should have failed when both mirrors missing'

print('RAID1 tests passed')
