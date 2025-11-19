import os
import shutil
import tempfile

from storage_module import StorageModule


def test_store_and_retrieve_small_file():
    tmp = tempfile.mkdtemp(prefix="test_storage_")
    try:
        sm = StorageModule("TestNode", raid_level=0, storage_path=tmp, num_devices=3)

        content = b"hello world"
        name = "/test/small.txt"

        resp = sm.store_file(name, content)
        assert resp.success, "store_file should succeed"

        # Metadata recorded
        meta = sm.stored_files.get(name)
        assert meta is not None, "metadata should be present"
        assert meta.num_devices == 3
        assert len(meta.fragments) == 3

        # Retrieve
        ret = sm.retrieve_file(name)
        assert ret.success, f"retrieve should succeed: {ret.error}"
        assert ret.content == content

    finally:
        shutil.rmtree(tmp)


def test_missing_chunk_fails():
    tmp = tempfile.mkdtemp(prefix="test_storage_")
    try:
        sm = StorageModule("TestNode", raid_level=0, storage_path=tmp, num_devices=2)

        # create larger content to ensure both chunks used
        content = b"A" * 1024
        name = "/test/large.bin"

        resp = sm.store_file(name, content)
        assert resp.success

        meta = sm.stored_files.get(name)
        assert meta is not None
        # remove first chunk to simulate disk failure
        first_chunk_path = list(meta.fragments.values())[0]
        if os.path.exists(first_chunk_path):
            os.remove(first_chunk_path)

        # retrieval should fail (RAID0 has no redundancy)
        ret = sm.retrieve_file(name)
        assert not ret.success, "retrieve should fail when a chunk is missing"

    finally:
        shutil.rmtree(tmp)


if __name__ == '__main__':
    test_store_and_retrieve_small_file()
    test_missing_chunk_fails()
    print("RAID0 tests passed")
