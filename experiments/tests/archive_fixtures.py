"""Synthetic archive bytes for offline test fixtures; never benchmark scan output."""

import io
import tarfile


def archive_bytes(files, root="package"):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as bundle:
        for path, data in files.items():
            item = tarfile.TarInfo(f"{root}/{path}")
            item.size = len(data)
            bundle.addfile(item, io.BytesIO(data))
    return buffer.getvalue()
