from storage_module import StorageModule
import os

storage_path = os.path.join('.', 'storage_demo_ST1_raid0')
# ensure clean demo directory
if os.path.exists(storage_path):
    import shutil
    shutil.rmtree(storage_path)

sm = StorageModule('DemoNode', raid_level=0, storage_path=storage_path, num_devices=2)

# Create sample content large enough to produce two chunks
content = ("Demo RAID0 content line\n" * 100).encode('utf-8')
name = '/demo/testfile.txt'

print(f"Storing {len(content)} bytes as {name} into {storage_path} (num_devices=2)")
resp = sm.store_file(name, content)
print('store_file success:', resp.success)

meta = sm.stored_files.get(name)
if not meta:
    print('No metadata found for', name)
    raise SystemExit(1)

print('Metadata:')
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

print('\nStorage directory tree:')
for root, dirs, files in os.walk(storage_path):
    level = root.replace(storage_path, '').count(os.sep)
    indent = ' ' * 2 * level
    print(f"{indent}{os.path.basename(root)}/")
    for f in files:
        fp = os.path.join(root, f)
        print(f"{indent}  - {f} ({os.path.getsize(fp)} bytes)")

# Print reassembled length via retrieval
ret = sm.retrieve_file(name)
print('\nRetrieval success:', ret.success)
if ret.success:
    print('Retrieved size:', len(ret.content))
else:
    print('Retrieve error:', ret.error)
