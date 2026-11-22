"""Bounded, symlink-safe file inventory for local scanners."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class InventoryIssue:
    code: str
    path: Path
    message: str


@dataclass(frozen=True)
class FileInventory:
    files: tuple[Path, ...]
    issue: InventoryIssue | None = None


def inventory_files(
    path: str | Path,
    suffixes: set[str],
    *,
    max_files: int,
    max_entries: int,
) -> FileInventory:
    """Find matching regular files without following symlinks or walking without bounds."""
    root = Path(path)
    if root.is_symlink():
        return FileInventory((), InventoryIssue("symlink", root, "Symbolic links are not followed."))
    if root.is_file():
        return FileInventory((root,) if root.suffix.lower() in suffixes else ())
    if not root.exists():
        return FileInventory((), InventoryIssue("missing", root, "Path does not exist."))
    if not root.is_dir():
        return FileInventory((), InventoryIssue("unsupported", root, "Path is not a regular file or directory."))

    pending = [root]
    matched: list[Path] = []
    entry_count = 0
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as iterator:
                entries = []
                for entry in iterator:
                    entry_count += 1
                    if entry_count > max_entries:
                        return FileInventory(
                            (),
                            InventoryIssue(
                                "entry_limit",
                                root,
                                f"Directory tree exceeds the {max_entries:,} entry inventory limit; no files were analyzed.",
                            ),
                        )
                    entries.append(entry)
        except OSError as exc:
            return FileInventory(
                (),
                InventoryIssue(
                    "read_error",
                    directory,
                    f"Could not enumerate directory: {type(exc).__name__}.",
                ),
            )

        entries.sort(key=lambda entry: entry.name)
        child_directories: list[Path] = []
        try:
            for entry in entries:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    child_directories.append(Path(entry.path))
                elif entry.is_file(follow_symlinks=False) and Path(entry.name).suffix.lower() in suffixes:
                    matched.append(Path(entry.path))
                    if len(matched) > max_files:
                        return FileInventory(
                            (),
                            InventoryIssue(
                                "file_limit",
                                root,
                                f"Directory tree contains more than {max_files:,} matching files; no files were analyzed.",
                            ),
                        )
        except OSError as exc:
            return FileInventory(
                (),
                InventoryIssue(
                    "read_error",
                    directory,
                    f"Could not inspect directory entry: {type(exc).__name__}.",
                ),
            )
        pending.extend(reversed(child_directories))

    return FileInventory(tuple(sorted(matched, key=lambda item: item.as_posix())))
