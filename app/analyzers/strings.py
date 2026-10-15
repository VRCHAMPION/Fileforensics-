"""ASCII and UTF-16LE string extraction with hard caps."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .deadline import Deadline, unlimited

MIN_LEN = 4


@dataclass(frozen=True)
class StringLimits:
    max_scan_bytes: int = 16 * 1024 * 1024
    max_strings: int = 20000
    max_string_len: int = 512
    sample_size: int = 200


_ASCII = re.compile(rb"[\x20-\x7e\t]{%d,}" % MIN_LEN)
_UTF16 = re.compile(rb"(?:[\x20-\x7e\t]\x00){%d,}" % MIN_LEN)

# Strings that show up in droppers, loaders and living-off-the-land tooling.
SUSPICIOUS_TOKENS = {
    "VirtualAlloc": "memory allocation API used by loaders",
    "VirtualProtect": "changes memory protection (shellcode staging)",
    "WriteProcessMemory": "process injection API",
    "CreateRemoteThread": "process injection API",
    "NtUnmapViewOfSection": "process hollowing API",
    "URLDownloadToFile": "downloads a file from the internet",
    "WinExec": "launches a program",
    "ShellExecute": "launches a program",
    "IsDebuggerPresent": "anti-debugging check",
    "GetAsyncKeyState": "keylogging API",
    "SetWindowsHookEx": "keyboard/mouse hooking API",
    "CryptEncrypt": "encryption API (ransomware indicator in context)",
    "powershell -e": "encoded PowerShell command",
    "powershell.exe -nop": "PowerShell with no profile",
    "-encodedcommand": "encoded PowerShell command",
    "FromBase64String": "decodes base64 payload at runtime",
    "WScript.Shell": "Windows Script Host shell object",
    "cmd.exe /c": "runs a shell command",
    "mshta": "HTML Application host (LOLBin)",
    "rundll32": "DLL launcher (LOLBin)",
    "regsvr32": "COM registration tool (LOLBin)",
    "certutil -decode": "certutil used to decode payloads",
    "bitsadmin /transfer": "BITS download (LOLBin)",
    "schtasks /create": "creates a scheduled task (persistence)",
    "CurrentVersion\\Run": "Run key (persistence)",
    "vssadmin delete shadows": "deletes shadow copies (ransomware)",
    "/bin/sh -i": "interactive reverse shell",
    "nc -e": "netcat with command execution",
    "eval(base64_decode": "obfuscated PHP payload",
    "AutoOpen": "Office macro auto-run entry point",
    "Document_Open": "Office macro auto-run entry point",
    "Workbook_Open": "Office macro auto-run entry point",
}


def extract_strings(data: bytes, limits: StringLimits | None = None, deadline: Deadline | None = None) -> dict:
    limits = limits or StringLimits()
    deadline = deadline or unlimited()
    region = data[: limits.max_scan_bytes]

    found: list[tuple[int, str, str]] = []
    capped = False
    for enc, pattern in (("ascii", _ASCII), ("utf16le", _UTF16)):
        for i, m in enumerate(pattern.finditer(region)):
            if len(found) >= limits.max_strings:
                capped = True
                break
            if i % 512 == 0 and deadline.expired():
                capped = True
                break
            raw = m.group()
            text = raw.decode("ascii", "replace") if enc == "ascii" else raw.decode("utf-16-le", "replace")
            if enc == "utf16le" and len(text) < MIN_LEN:
                continue
            found.append((m.start(), enc, text[: limits.max_string_len]))

    ascii_count = sum(1 for f in found if f[1] == "ascii")
    blob = "\n".join(f[2] for f in found)
    lowered = blob.lower()
    suspicious = [{"token": tok, "meaning": why} for tok, why in SUSPICIOUS_TOKENS.items() if tok.lower() in lowered]
    sample = [{"offset": off, "encoding": enc, "value": val[:200]} for off, enc, val in found[: limits.sample_size]]
    return {
        "total": len(found),
        "ascii": ascii_count,
        "utf16le": len(found) - ascii_count,
        "capped": capped,
        "scanned_bytes": len(region),
        "sample": sample,
        "suspicious": suspicious,
        "_blob": blob,  # consumed by the IOC extractor, stripped from the report
    }
