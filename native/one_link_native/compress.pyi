"""Types for :mod:`one_link_native.compress`."""

from collections.abc import Iterable
from typing import final
from typing_extensions import Buffer

__version__: str
MAX_COMPRESSED_PAYLOAD_BYTES: int
MAX_DECOMPRESSED_BYTES: int

@final
class Compressor:
    def __init__(self) -> None: ...
    def pick(self, kind: str, size: int, precompressed: bool = ...) -> str: ...
    def compress(self, algo: str, payload: Buffer) -> bytes: ...
    def decompress(self, payload: Buffer, max_size: int) -> bytes: ...
    def __repr__(self) -> str: ...

def onemem_sha256_many(chunks: Iterable[bytes]) -> list[bytes]: ...
def onemem_encode_many(
    chunks: Iterable[bytes],
    algorithm: str,
    precompressed: bool = ...,
    compress: bool = ...,
) -> list[bytes]: ...
