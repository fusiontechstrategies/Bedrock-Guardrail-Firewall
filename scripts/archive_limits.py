"""Bound archive structure and decoder work before high-level parsers run."""

from __future__ import annotations

import contextlib
import os
import stat
import struct
import tarfile
import tempfile
import zlib

MAX_COMPRESSED_BYTES = 64 * 1024 * 1024
MAX_RAW_TAR_BYTES = 128 * 1024 * 1024
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_MEMBERS = 10000
MAX_CENTRAL_BYTES = 4 * 1024 * 1024
MAX_METADATA_BYTES = 64 * 1024
MAX_RATIO = 1000
CHUNK_BYTES = 64 * 1024


class ArchiveLimitError(ValueError):
    """An archive is malformed or exceeds a supported resource budget."""


def require(condition, message):
    if not condition:
        raise ArchiveLimitError(message)


def check_zip_structure(value: bytes) -> None:
    """Check the bounded, ordinary ZIP central directory before ZipFile builds it."""
    require(len(value) <= MAX_COMPRESSED_BYTES, "ZIP compressed byte budget exceeded")
    offset = value.rfind(b"PK\x05\x06", max(0, len(value) - 65557))
    require(offset >= 0 and offset + 22 <= len(value), "ZIP end record is missing")
    disk, central_disk, disk_count, count, size, start, comment = struct.unpack_from(
        "<4H2IH", value, offset + 4
    )
    require(
        disk == central_disk == 0
        and disk_count == count
        and count < 0xFFFF
        and size < 0xFFFFFFFF
        and start < 0xFFFFFFFF,
        "Multipart and ZIP64 archives are not supported",
    )
    require(count <= MAX_MEMBERS, "ZIP member count budget exceeded")
    require(size <= MAX_CENTRAL_BYTES, "ZIP central directory budget exceeded")
    require(
        comment == 0 and offset + 22 == len(value) and start + size == offset,
        "ZIP central directory or trailing bytes are invalid",
    )
    cursor, total, entries = start, 0, []
    for _ in range(count):
        require(
            cursor + 46 <= offset and value[cursor : cursor + 4] == b"PK\x01\x02",
            "Invalid ZIP central directory entry",
        )
        flags, method = struct.unpack_from("<HH", value, cursor + 8)
        crc = struct.unpack_from("<I", value, cursor + 16)[0]
        compressed, decoded = struct.unpack_from("<II", value, cursor + 20)
        name, extra, note, volume = struct.unpack_from("<4H", value, cursor + 28)
        local = struct.unpack_from("<I", value, cursor + 42)[0]
        require(
            flags in {0, 0x800} and method in {0, 8},
            "Unsupported ZIP encryption or compression",
        )
        require(volume == 0 and local < start, "Invalid ZIP local entry location")
        require(extra == note == 0, "ZIP extras and entry comments are not approved")
        require(
            struct.unpack_from("<H", value, cursor + 6)[0] == 20,
            "ZIP version or streaming/ZIP64 conventions are not approved",
        )
        require(0 < name <= 4096, "ZIP filename budget exceeded")
        require(decoded <= MAX_MEMBER_BYTES, "ZIP member byte budget exceeded")
        total += decoded
        require(total <= MAX_TOTAL_BYTES, "ZIP total decoded byte budget exceeded")
        require(
            decoded <= max(1, compressed) * MAX_RATIO,
            "ZIP expansion ratio budget exceeded",
        )
        end = cursor + 46 + name
        require(end <= offset, "Truncated ZIP central directory")
        require(
            b"\0" not in value[cursor + 46 : end], "ZIP filename contains a NUL alias"
        )
        require(
            local + 30 <= start and value[local : local + 4] == b"PK\x03\x04",
            "Invalid ZIP local header",
        )
        (
            needed,
            local_flags,
            local_method,
            time,
            date,
            local_crc,
            local_compressed,
            local_decoded,
            local_name,
            local_extra,
        ) = struct.unpack_from("<5H3I2H", value, local + 4)
        require(
            needed == 20
            and local_flags == flags
            and local_method == method
            and local_crc == crc
            and local_compressed == compressed
            and local_decoded == decoded
            and local_name == name
            and local_extra == 0
            and value[local + 30 : local + 30 + name] == value[cursor + 46 : end]
            and (time, date) == struct.unpack_from("<HH", value, cursor + 12),
            "ZIP local and central headers disagree or contain unapproved metadata",
        )
        body = local + 30 + name
        require(body + compressed <= start, "ZIP member overlaps the central directory")
        entries.append((local, body, body + compressed, decoded, method, crc))
        cursor = end
    require(cursor == offset, "ZIP central directory count mismatch")
    end = 0
    for local, body, following, decoded, method, crc in sorted(entries):
        require(local == end, "ZIP contains a preamble, overlap or unreferenced bytes")
        payload = value[body:following]
        if method == 8:
            try:
                decoder = zlib.decompressobj(-15)
                payload = decoder.decompress(payload, decoded + 1)
            except zlib.error as exc:
                raise ArchiveLimitError("Invalid ZIP deflate stream") from exc
            require(
                decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail,
                "ZIP member has trailing data or exceeds its declared size",
            )
        require(
            len(payload) == decoded and zlib.crc32(payload) == crc,
            "ZIP decoded size or CRC mismatch",
        )
        end = following
    require(
        end == start, "ZIP contains unreferenced bytes before the central directory"
    )


@contextlib.contextmanager
def bounded_tar_stream(compressed: bytes):
    """Spool bounded gzip output, then bound physical headers before TAR parsing."""
    require(
        len(compressed) <= MAX_COMPRESSED_BYTES, "TAR compressed byte budget exceeded"
    )
    with tempfile.TemporaryFile() as stream:
        decoder = zlib.decompressobj(31)
        decoded = 0
        try:
            for offset in range(0, len(compressed), CHUNK_BYTES):
                pending = compressed[offset : offset + CHUNK_BYTES]
                while pending:
                    block = decoder.decompress(
                        pending, min(CHUNK_BYTES, MAX_RAW_TAR_BYTES - decoded + 1)
                    )
                    decoded += len(block)
                    require(
                        decoded <= MAX_RAW_TAR_BYTES, "TAR decoded byte budget exceeded"
                    )
                    stream.write(block)
                    pending = decoder.unconsumed_tail
                require(
                    not decoder.unused_data, "TAR gzip has trailing streams or data"
                )
        except zlib.error as exc:
            raise ArchiveLimitError("Invalid TAR gzip stream") from exc
        require(
            decoder.eof and not decoder.unused_data,
            "Truncated or trailing TAR gzip stream",
        )
        stream.seek(0)
        count, total = 0, 0
        while True:
            block = stream.read(512)
            require(len(block) == 512, "TAR end markers are missing")
            if block == b"\0" * 512:
                require(
                    stream.read(512) == b"\0" * 512, "TAR end markers are incomplete"
                )
                require(decoded % 512 == 0, "TAR padding is incomplete")
                for tail in iter(lambda: stream.read(CHUNK_BYTES), b""):
                    require(not any(tail), "TAR has trailing data")
                break
            count += 1
            require(count <= MAX_MEMBERS, "TAR member count budget exceeded")
            try:
                member = tarfile.TarInfo.frombuf(block, "utf-8", "strict")
            except (tarfile.HeaderError, UnicodeError) as exc:
                raise ArchiveLimitError("Invalid TAR physical header") from exc
            require(member.size >= 0, "Negative TAR member size")
            metadata = member.type in {tarfile.XHDTYPE, tarfile.XGLTYPE}
            require(
                metadata
                or member.type in {tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE},
                "TAR contains a link or device",
            )
            require(
                member.size <= (MAX_METADATA_BYTES if metadata else MAX_MEMBER_BYTES),
                "TAR member byte budget exceeded",
            )
            total += member.size
            require(total <= MAX_TOTAL_BYTES, "TAR total member byte budget exceeded")
            rounded = ((member.size + 511) // 512) * 512
            require(stream.tell() + rounded <= decoded, "Truncated TAR member")
            if metadata:
                payload = stream.read(member.size)
                cursor = 0
                while cursor < len(payload):
                    separator = payload.find(b" ", cursor, cursor + 12)
                    require(
                        separator > cursor and payload[cursor:separator].isdigit(),
                        "Invalid TAR extension record",
                    )
                    length = int(payload[cursor:separator])
                    end = cursor + length
                    require(
                        end <= len(payload)
                        and end > separator + 2
                        and payload[end - 1 : end] == b"\n",
                        "Invalid TAR extension length",
                    )
                    key = payload[separator + 1 : end - 1].partition(b"=")[0]
                    require(
                        key
                        in {
                            b"path",
                            b"size",
                            b"mtime",
                            b"atime",
                            b"ctime",
                            b"uid",
                            b"gid",
                            b"uname",
                            b"gname",
                        },
                        "Unsupported TAR extension metadata",
                    )
                    cursor = end
                stream.seek(rounded - member.size, os.SEEK_CUR)
            else:
                stream.seek(rounded, os.SEEK_CUR)
        stream.seek(0)
        yield stream


def regular_snapshot(path) -> bytes:
    """Read a bounded, nonblocking, no-follow regular artifact descriptor."""
    if os.name == "nt":
        import ctypes
        import ctypes.wintypes as wintypes
        import msvcrt

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.CreateFileW(str(path), 0x80000000, 3, None, 3, 0x00200000, None)
        require(handle != wintypes.HANDLE(-1).value, "Unable to open archive")
        try:
            descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
            handle = None
        finally:
            if handle is not None:
                kernel.CloseHandle(handle)
    else:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and not getattr(info, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0),
            "Archive must be one unlinked regular file",
        )
        require(
            info.st_size <= MAX_COMPRESSED_BYTES,
            "Archive compressed byte budget exceeded",
        )
        value = stream.read(MAX_COMPRESSED_BYTES + 1)
        require(
            len(value) <= MAX_COMPRESSED_BYTES,
            "Archive compressed byte budget exceeded",
        )
        return value
