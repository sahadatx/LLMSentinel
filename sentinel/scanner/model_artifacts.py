"""Inspect pickle opcodes without loading or executing the artifact."""

from __future__ import annotations

import os
import pickletools
import zipfile
from pathlib import Path

from sentinel.scanner.filesystem import FileInventory, InventoryIssue, inventory_files
from sentinel.scanner.source import Finding

_DANGEROUS_GLOBALS = {
    ("os", "system"),
    ("posix", "system"),
    ("subprocess", "Popen"),
    ("subprocess", "run"),
    ("subprocess", "call"),
    ("subprocess", "check_output"),
    ("builtins", "eval"),
    ("builtins", "exec"),
    ("__builtin__", "eval"),
    ("__builtin__", "exec"),
}
MAX_MODEL_FILES = 5_000
MAX_DIRECTORY_ENTRIES = 100_000
MAX_TOTAL_MODEL_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_PICKLE_FILES = 64
MAX_ARCHIVE_PICKLE_BYTES = 64 * 1024 * 1024
MAX_MODEL_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 100_000
MAX_PICKLE_OPCODES = 2_000_000


def _dangerous_reference(reference: str) -> bool:
    parts = reference.split()
    return len(parts) == 2 and (parts[0], parts[1]) in _DANGEROUS_GLOBALS


def scan_pickle_bytes(data: bytes, display_path: str) -> list[Finding]:
    findings: list[Finding] = []
    recent_strings: list[str] = []
    try:
        for opcode_count, (opcode, argument, position) in enumerate(pickletools.genops(data), 1):
            if opcode_count > MAX_PICKLE_OPCODES:
                findings.append(Finding("model.opcode-count-limit", "MEDIUM", f"Pickle exceeds the {MAX_PICKLE_OPCODES:,} opcode analysis limit; remaining opcodes were not scanned.", display_path, 1, "CWE-789"))
                break
            if opcode.name == "GLOBAL" and isinstance(argument, str) and _dangerous_reference(argument):
                module, name = argument.split()
                findings.append(Finding("model.pickle-dangerous-global", "HIGH", f"Pickle references risky callable {module}.{name} at byte {position}; this is a static indicator, not proof of execution. Artifact was not loaded.", display_path, 1, "CWE-502", opcode.name))
            elif opcode.name in {"STACK_GLOBAL"} and len(recent_strings) >= 2:
                module, name = recent_strings[-2:]
                if (module, name) in _DANGEROUS_GLOBALS:
                    findings.append(Finding("model.pickle-stack-global-candidate", "HIGH", f"STACK_GLOBAL follows risky-looking strings {module}.{name} near byte {position}; stack association is heuristic. Artifact was not loaded.", display_path, 1, "CWE-502", opcode.name))
            elif opcode.name in {"UNICODE", "BINUNICODE", "SHORT_BINUNICODE", "BINUNICODE8", "STRING", "BINSTRING", "SHORT_BINSTRING"} and isinstance(argument, str):
                recent_strings.append(argument)
                recent_strings = recent_strings[-8:]
    except Exception as exc:
        findings.append(Finding("model.pickle-malformed", "MEDIUM", f"Could not fully parse pickle opcodes ({type(exc).__name__}); artifact was not loaded.", display_path, 1, "CWE-502"))
    return findings


def scan_pickle(path: str | Path) -> list[Finding]:
    artifact = Path(path)
    try:
        if artifact.is_symlink():
            return [Finding("model.symlink-skipped", "INFO", "Symbolic links are not followed by the scanner.", str(artifact), 1, "CWE-59")]
        if artifact.stat().st_size > MAX_ARCHIVE_PICKLE_BYTES:
            return [Finding("model.artifact-too-large", "MEDIUM", "Pickle exceeds the 64 MiB scanner limit and was not loaded.", str(artifact), 1, "CWE-789")]
        descriptor = os.open(artifact, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            data = stream.read(MAX_ARCHIVE_PICKLE_BYTES + 1)
        if len(data) > MAX_ARCHIVE_PICKLE_BYTES:
            return [Finding("model.artifact-too-large", "MEDIUM", "Pickle exceeds the 64 MiB scanner limit and was not loaded.", str(artifact), 1, "CWE-789")]
    except OSError as exc:
        return [Finding("model.read-error", "LOW", str(exc), str(artifact), 1, "CWE-732")]
    return scan_pickle_bytes(data, str(artifact))


def scan_model_path(path: str | Path) -> list[Finding]:
    root = Path(path)
    inventory = inventory_files(
        root,
        {".pkl", ".pickle", ".pt", ".pth"},
        max_files=MAX_MODEL_FILES,
        max_entries=MAX_DIRECTORY_ENTRIES,
    )
    issue = _inventory_finding(inventory, "model")
    if issue:
        return [issue]
    findings: list[Finding] = []
    total_bytes = 0
    for file in inventory.files:
        try:
            size = file.stat().st_size
        except OSError:
            size = 0
        if total_bytes + size > MAX_TOTAL_MODEL_BYTES:
            findings.append(Finding("model.total-byte-limit", "MEDIUM", "Directory tree exceeds the 512 MiB aggregate model analysis limit; remaining artifacts were not analyzed.", str(root), 1, "CWE-789"))
            break
        total_bytes += size
        if file.suffix.lower() in {".pkl", ".pickle"}:
            findings.extend(scan_pickle(file))
        else:
            findings.extend(_scan_torch_archive(file))
    return findings


def _scan_torch_archive(file: Path) -> list[Finding]:
    try:
        if file.is_symlink():
            return [Finding("model.symlink-skipped", "INFO", "Symbolic links are not followed by the scanner.", str(file), 1, "CWE-59")]
        if file.stat().st_size > MAX_MODEL_ARCHIVE_BYTES:
            return [Finding("model.artifact-too-large", "MEDIUM", "PyTorch archive exceeds the 256 MiB scanner limit and was not opened.", str(file), 1, "CWE-789")]
        if not zipfile.is_zipfile(file):
            return [Finding("model.unsupported-container", "INFO", "PyTorch artifact is not a readable ZIP archive; contents were not extracted or executed.", str(file), 1, "CWE-502")]
        with zipfile.ZipFile(file) as archive:
            if len(archive.infolist()) > MAX_ARCHIVE_MEMBERS:
                return [Finding("model.archive-member-limit", "MEDIUM", f"PyTorch archive exceeds the {MAX_ARCHIVE_MEMBERS:,} member limit; no members were scanned.", str(file), 1, "CWE-789")]
            candidates = [item for item in archive.infolist() if item.filename.endswith("data.pkl")]
            if not candidates:
                return [Finding("model.no-pickle-payload", "INFO", "PyTorch archive has no data.pkl member; contents were not extracted to disk.", str(file), 1, "CWE-502")]
            findings = []
            if len(candidates) > MAX_ARCHIVE_PICKLE_FILES:
                findings.append(Finding("model.archive-pickle-limit", "MEDIUM", f"PyTorch archive has more than {MAX_ARCHIVE_PICKLE_FILES} data.pkl members; extra members were not scanned.", str(file), 1, "CWE-789"))
            scanned_bytes = 0
            for item in candidates[:MAX_ARCHIVE_PICKLE_FILES]:
                member_path = f"{file}!{item.filename}"
                member_limit = min(32 * 1024 * 1024, MAX_ARCHIVE_PICKLE_BYTES - scanned_bytes)
                if item.file_size > member_limit:
                    findings.append(Finding("model.embedded-pickle-too-large", "MEDIUM", "Embedded pickle exceeds the per-member or aggregate 64 MiB scan limit.", member_path, 1, "CWE-789"))
                    continue
                with archive.open(item) as stream:
                    data = stream.read(member_limit + 1)
                if len(data) > member_limit:
                    findings.append(Finding("model.embedded-pickle-too-large", "MEDIUM", "Embedded pickle expanded beyond the per-member or aggregate 64 MiB scan limit.", member_path, 1, "CWE-789"))
                    continue
                if len(data) != item.file_size:
                    findings.append(Finding("model.archive-member-size-mismatch", "MEDIUM", "Embedded pickle size differs from archive metadata; member was not analyzed.", member_path, 1, "CWE-502"))
                    continue
                scanned_bytes += len(data)
                findings.extend(scan_pickle_bytes(data, member_path))
            return findings
    except Exception as exc:
        return [Finding("model.archive-error", "MEDIUM", f"Could not safely inspect model archive ({type(exc).__name__}); no artifact code was executed.", str(file), 1, "CWE-502")]


def _inventory_finding(inventory: FileInventory, prefix: str) -> Finding | None:
    issue: InventoryIssue | None = inventory.issue
    if issue is None:
        return None
    if issue.code in {"entry_limit", "file_limit"}:
        severity, cwe = "MEDIUM", "CWE-789"
    elif issue.code == "symlink":
        severity, cwe = "INFO", "CWE-59"
    else:
        severity, cwe = "LOW", "CWE-732"
    return Finding(f"{prefix}.{issue.code.replace('_', '-')}", severity, issue.message, str(issue.path), 1, cwe)
