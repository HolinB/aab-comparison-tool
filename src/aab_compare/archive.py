from __future__ import annotations

import os
import stat
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .config import ArchiveLimits


class ArchiveSecurityError(ValueError):
    """Raised when an AAB violates archive safety constraints."""


@dataclass(frozen=True)
class ZipEntry:
    path: str
    size: int
    compressed_size: int
    crc: int


@dataclass(frozen=True)
class ZipInventory:
    path: Path
    modules: list[str]
    counts: dict[str, int]
    entries: list[ZipEntry]


def _validate_member(info: zipfile.ZipInfo, limits: ArchiveLimits) -> None:
    name = info.filename.replace("\\", "/")
    pure = PurePosixPath(name)
    if pure.is_absolute() or ".." in pure.parts or not pure.parts or pure.parts[0] == "":
        raise ArchiveSecurityError(f"unsafe path in archive: {info.filename}")
    mode = info.external_attr >> 16
    if stat.S_ISLNK(mode):
        raise ArchiveSecurityError(f"symbolic link is not allowed: {info.filename}")
    if info.file_size > limits.max_entry_size:
        raise ArchiveSecurityError(f"entry exceeds size limit: {info.filename}")
    if info.file_size and info.compress_size == 0:
        raise ArchiveSecurityError(f"invalid compressed size: {info.filename}")
    if info.compress_size:
        ratio = info.file_size / info.compress_size
        if ratio > limits.max_compression_ratio:
            raise ArchiveSecurityError(f"entry compression ratio is unsafe: {info.filename}")


def _validate_archive(
    archive: zipfile.ZipFile,
    limits: ArchiveLimits,
) -> tuple[zipfile.ZipInfo, ...]:
    infos = archive.infolist()
    if len(infos) > limits.max_entries:
        raise ArchiveSecurityError("archive contains too many entries")
    total_uncompressed = 0
    seen: set[str] = set()
    for info in infos:
        _validate_member(info, limits)
        normalized = info.filename.replace("\\", "/").rstrip("/")
        if not normalized:
            continue
        if normalized in seen:
            raise ArchiveSecurityError(f"duplicate archive entry: {normalized}")
        seen.add(normalized)
        total_uncompressed += info.file_size
        if total_uncompressed > limits.max_uncompressed_size:
            raise ArchiveSecurityError("archive uncompressed size exceeds configured limit")
    return tuple(infos)


@contextmanager
def open_validated_aab(path: Path, limits: ArchiveLimits) -> Iterator[zipfile.ZipFile]:
    resolved = path.resolve()
    if resolved.suffix.lower() != ".aab":
        raise ArchiveSecurityError("input file must use the .aab extension")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(resolved, flags)
    with os.fdopen(descriptor, "rb") as stream:
        file_state = os.fstat(stream.fileno())
        if not stat.S_ISREG(file_state.st_mode):
            raise ArchiveSecurityError("input is not a regular AAB file")
        if file_state.st_size > limits.max_input_size:
            raise ArchiveSecurityError("AAB exceeds configured input size limit")
        with zipfile.ZipFile(stream) as archive:
            _validate_archive(archive, limits)
            yield archive


def validate_aab(path: Path, limits: ArchiveLimits) -> tuple[zipfile.ZipInfo, ...]:
    try:
        with open_validated_aab(path, limits) as archive:
            return tuple(archive.infolist())
    except zipfile.BadZipFile as error:
        raise ArchiveSecurityError("input is not a valid ZIP/AAB archive") from error


def inspect_aab(path: Path, limits: ArchiveLimits) -> ZipInventory:
    path = path.resolve()
    infos = validate_aab(path, limits)

    entries: list[ZipEntry] = []
    modules: set[str] = set()
    counts = {
        "entries": 0,
        "dex": 0,
        "native": 0,
        "assets": 0,
        "resources": 0,
        "manifests": 0,
    }
    for info in infos:
        normalized = info.filename.replace("\\", "/").rstrip("/")
        if not normalized:
            continue
        parts = normalized.split("/")
        if len(parts) >= 3 and parts[1] == "manifest":
            modules.add(parts[0])
            if parts[-1] == "AndroidManifest.xml":
                counts["manifests"] += 1
        if len(parts) >= 3 and parts[1] == "dex" and normalized.endswith(".dex"):
            counts["dex"] += 1
        elif len(parts) >= 4 and parts[1] == "lib" and normalized.endswith(".so"):
            counts["native"] += 1
        elif len(parts) >= 3 and parts[1] == "assets":
            counts["assets"] += 1
        elif len(parts) >= 3 and parts[1] == "res":
            counts["resources"] += 1
        entries.append(ZipEntry(normalized, info.file_size, info.compress_size, info.CRC))
    counts["entries"] = len(entries)
    if "base" not in modules:
        raise ArchiveSecurityError("AAB does not contain a base module manifest")
    return ZipInventory(path, sorted(modules), counts, entries)
