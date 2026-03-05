import hashlib
from typing import BinaryIO

def sha256_stream(f: BinaryIO, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    while True:
        b = f.read(chunk_size)
        if not b:
            break
        h.update(b)
    return h.hexdigest()
