"""First look at a sample: format, hashes and entropy, and for PE files the headers,
sections, imports, claimed identity and packer hints.

Usage: python triage.py FILE [--out imports.txt] [--verify-signature]

Read-only: the sample is parsed as bytes and never executed or loaded.
"""
import argparse
import datetime
import json
import os
import subprocess
import sys
from pathlib import Path

import pefile

from common import UNTRUSTED_NOTICE, ai_directed, decode, emit, entropy, hashes, read_sample, shorten, visible

# Imports that matter in combination. Any one of them alone is weak evidence.
# Names are stored without the A/W suffix of Windows ANSI/Unicode variants.
SUSPICIOUS_APIS = {
    "process_injection": {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "CreateRemoteThreadEx",
                          "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC", "NtQueueApcThread",
                          "SetThreadContext", "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "NtMapViewOfSection"},
    "execution": {"WinExec", "ShellExecute", "ShellExecuteEx", "CreateProcess", "CreateProcessAsUser",
                  "system", "_wsystem"},
    "network": {"InternetOpen", "InternetOpenUrl", "InternetConnect", "InternetReadFile", "HttpOpenRequest",
                "HttpSendRequest", "URLDownloadToFile", "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest",
                "WSAStartup", "socket", "connect", "send", "recv", "gethostbyname", "getaddrinfo", "GetAddrInfo"},
    "persistence": {"RegSetValueEx", "RegCreateKeyEx", "RegCreateKey", "CreateService", "ChangeServiceConfig"},
    "anti_analysis": {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
                      "NtSetInformationThread", "OutputDebugString"},
    "crypto": {"CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptImportKey", "CryptAcquireContext",
               "CryptDeriveKey", "BCryptEncrypt", "BCryptDecrypt", "BCryptGenerateSymmetricKey"},
    "input_capture": {"SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState", "GetClipboardData", "BitBlt"},
    "privileges": {"AdjustTokenPrivileges", "LookupPrivilegeValue", "OpenProcessToken"},
    "process_discovery": {"CreateToolhelp32Snapshot", "Process32First", "Process32Next", "EnumProcesses"},
    "dynamic_loading": {"LoadLibrary", "LoadLibraryEx", "GetProcAddress", "LdrLoadDll", "LdrGetProcedureAddress"},
}

PACKER_SECTIONS = {
    "UPX0": "UPX", "UPX1": "UPX", "UPX2": "UPX", ".aspack": "ASPack", ".adata": "ASPack",
    ".MPRESS1": "MPRESS", ".MPRESS2": "MPRESS", ".petite": "Petite", ".nsp0": "NsPack", ".nsp1": "NsPack",
    ".themida": "Themida", ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect",
    ".enigma1": "Enigma", ".enigma2": "Enigma", "PEC2": "PECompact", "pec1": "PECompact",
}

MACHINES = {0x14C: "x86", 0x8664: "x64", 0xAA64: "ARM64", 0x1C0: "ARM", 0x1C4: "ARMv7"}
SUBSYSTEMS = {1: "native (driver)", 2: "windows_gui", 3: "windows_console", 10: "efi_application",
              11: "efi_boot_driver", 12: "efi_runtime_driver", 16: "boot_application"}
MAGICS = [(b"\x7fELF", "ELF"), (b"\xfe\xed\xfa\xce", "Mach-O"), (b"\xfe\xed\xfa\xcf", "Mach-O"),
          (b"\xce\xfa\xed\xfe", "Mach-O"), (b"\xcf\xfa\xed\xfe", "Mach-O"), (b"\xca\xfe\xba\xbe", "Mach-O fat or Java class"),
          (b"PK\x03\x04", "ZIP (also APK, JAR, Office)"), (b"%PDF", "PDF"), (b"\xd0\xcf\x11\xe0", "OLE (old Office, MSI)")]

HIGH_ENTROPY = 7.2
# A single compressed or encrypted blob sits near the 8.0 maximum; resources that are merely
# partly compressed (images, mixed data) usually stay below this.
PAYLOAD_ENTROPY = 7.9
BIG_EMPTY_SECTION = 1024 * 1024
MAX_NAMES = 50


def capped(names):
    return names if len(names) <= MAX_NAMES else names[:MAX_NAMES] + [f"... +{len(names) - MAX_NAMES} more"]


def permissions(section):
    c = section.Characteristics
    return ("R" if c & 0x40000000 else "-") + ("W" if c & 0x80000000 else "-") + ("X" if c & 0x20000000 else "-")


def directory_present(pe, name):
    d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY[name]]
    return d.VirtualAddress != 0 and d.Size > 0


def imports(pe):
    result = {}
    for attr, suffix in (("DIRECTORY_ENTRY_IMPORT", ""), ("DIRECTORY_ENTRY_DELAY_IMPORT", " (delay-loaded)")):
        for entry in getattr(pe, attr, []):
            names = [imp.name.decode(errors="replace") if imp.name else f"ord_{imp.ordinal}" for imp in entry.imports]
            result.setdefault(entry.dll.decode(errors="replace").lower() + suffix, []).extend(names)
    return result


def exports(pe):
    return [decode(s.name) if s.name else f"ord_{s.ordinal}"
            for s in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", [])]


def suspicious(import_names):
    found = {}
    for name in import_names:
        base = name[:-1] if name[-1:] in ("A", "W") and name[:-1] else name
        for category, apis in SUSPICIOUS_APIS.items():
            if name in apis or base in apis:
                found.setdefault(category, []).append(name)
    return found


def version_info(pe):
    info = {}
    for fileinfo in getattr(pe, "FileInfo", []):
        for entry in fileinfo:
            for table in getattr(entry, "StringTable", []):
                for key, value in table.entries.items():
                    info[decode(key)] = shorten(decode(value))
    return info


def pdb_path(pe):
    for dbg in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
        if pdb := getattr(dbg.entry, "PdbFileName", None):
            return decode(pdb)
    return None


def verify_signature(path):
    """Ask Windows to verify the file's Authenticode or catalog signature. This reads the file, never runs it.

    The path reaches PowerShell through an environment variable, never the command line,
    so a hostile file name can't inject code.
    """
    if sys.platform != "win32":
        return {"status": "not checked: needs Windows"}
    script = (
        "[Console]::OutputEncoding = [Text.Encoding]::UTF8; "
        "$s = Get-AuthenticodeSignature -LiteralPath $env:RE_SKILL_SAMPLE; "
        "[pscustomobject]@{status = [string]$s.Status; type = [string]$s.SignatureType; "
        "signer = $s.SignerCertificate.Subject; issuer = $s.SignerCertificate.Issuer; "
        "message = $s.StatusMessage} | ConvertTo-Json -Compress"
    )
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                           env={**os.environ, "RE_SKILL_SAMPLE": str(path.resolve())},
                           capture_output=True, timeout=60)
        return json.loads(r.stdout.decode("utf-8-sig"))
    except (OSError, subprocess.TimeoutExpired, ValueError) as e:
        return {"status": f"not checked: {e}"}


def analyze_pe(pe, data):
    sections = [{
        "name": decode(s.Name),
        "virtual_address": hex(s.VirtualAddress),
        "virtual_size": s.Misc_VirtualSize,
        "raw_size": s.SizeOfRawData,
        "entropy": entropy(s.get_data()),
        "permissions": permissions(s),
    } for s in pe.sections]

    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    ep_section = pe.get_section_by_rva(ep)
    ep_name = decode(ep_section.Name) if ep_section else None
    imported = imports(pe)
    all_names = [n for names in imported.values() for n in names]
    found = suspicious(all_names)
    overlay = pe.get_overlay_data_start_offset()
    ts = pe.FILE_HEADER.TimeDateStamp

    hints = []
    for s in sections:
        if s["name"] in PACKER_SECTIONS:
            hints.append(f"section {s['name']!r} is typical of {PACKER_SECTIONS[s['name']]}")
        if "X" in s["permissions"] and s["entropy"] > HIGH_ENTROPY:
            hints.append(f"executable section {s['name']!r} has high entropy ({s['entropy']})")
        elif s["entropy"] > PAYLOAD_ENTROPY and s["raw_size"] >= len(data) / 2:
            hints.append(f"section {s['name']!r} holds {s['raw_size'] * 100 // len(data)}% of the file at entropy "
                         f"{s['entropy']}: likely a compressed or encrypted payload")
        if s["raw_size"] == 0 and (s["virtual_size"] >= BIG_EMPTY_SECTION or ("X" in s["permissions"] and s["virtual_size"])):
            hints.append(f"section {s['name']!r} is empty on disk but {s['virtual_size']} bytes in memory: room to unpack into")
        if s["permissions"] == "RWX":
            hints.append(f"section {s['name']!r} is writable and executable")
    # Resource-only DLLs legitimately have no imports, but they also have no entry point.
    if not all_names and ep:
        hints.append("no imports at all: Windows APIs are resolved by hand at runtime, as packers, loaders and shellcode do")
    elif len(all_names) < 10 and "dynamic_loading" in found:
        hints.append(f"only {len(all_names)} imports, including runtime API resolution: real imports are likely hidden")
    # An entry point of 0 just means there is none, as in resource-only DLLs.
    if ep and ep_section is None:
        hints.append("entry point lies outside every section")
    elif len(pe.sections) > 1 and ep_section == pe.sections[-1]:
        hints.append(f"entry point is in the last section ({ep_name!r})")
    if (file_entropy := entropy(data)) > HIGH_ENTROPY:
        hints.append(f"whole file has high entropy ({file_entropy})")

    return {
        "machine": MACHINES.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine)),
        "subsystem": SUBSYSTEMS.get(pe.OPTIONAL_HEADER.Subsystem, pe.OPTIONAL_HEADER.Subsystem),
        "is_dll": pe.is_dll(),
        "is_dotnet": directory_present(pe, "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"),
        "compile_timestamp_claimed": datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).isoformat(),
        "entry_point": hex(ep),
        "entry_point_section": ep_name,
        "imphash": pe.get_imphash() or None,
        "signature_present_unverified": directory_present(pe, "IMAGE_DIRECTORY_ENTRY_SECURITY"),
        "overlay_bytes": len(data) - overlay if overlay is not None else 0,
        "version_info_claimed": version_info(pe),
        "pdb_path": pdb_path(pe),
        "sections": sections,
        "import_count": len(all_names),
        "suspicious_imports": found,
        "packer_hints": hints,
        "imports_per_dll": {dll: len(names) for dll, names in imported.items()},
        "exports": capped(exports(pe)),
        "parser_warnings": pe.get_warnings()[:10],
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("file")
    ap.add_argument("--out", help="write every import and export to this file, one per line, for grep")
    ap.add_argument("--verify-signature", action="store_true",
                    help="ask Windows to verify the signature (it may contact certificate revocation servers)")
    args = ap.parse_args()

    path = Path(args.file)
    data = read_sample(path)
    result = {
        "tool": "triage",
        "notice": UNTRUSTED_NOTICE,
        "file": {"name": visible(path.name), "size": len(data)},
        "hashes": hashes(data),
        "entropy": entropy(data),
        "format": next((fmt for magic, fmt in MAGICS if data.startswith(magic)), "unknown"),
    }

    if data.startswith(b"MZ"):
        try:
            pe = pefile.PE(data=data)
        except pefile.PEFormatError as e:
            result["format"] = f"MZ header but invalid PE ({e})"
        else:
            result["format"] = "PE32+" if pe.OPTIONAL_HEADER.Magic == 0x20B else "PE32"
            result["pe"] = analyze_pe(pe, data)
            if args.out:
                lines = [f"import  {dll}!{name}" for dll, names in imports(pe).items() for name in names]
                lines += [f"export  {name}" for name in exports(pe)]
                with open(args.out, "w", encoding="utf-8") as f:
                    f.write("\n".join(lines) + "\n")
                result["full_import_list"] = args.out
    elif result["format"] != "unknown":
        result["note"] = "Only PE files get in-depth parsing for now; use extract_strings.py for this format."
    if args.verify_signature:
        result["signature"] = verify_signature(path)

    # Author-controlled text the triage itself surfaced: check it for AI-directed content.
    pe_info = result.get("pe", {})
    candidates = [("file name", path.name), ("pdb_path", pe_info.get("pdb_path") or "")]
    candidates += [(f"version_info.{k}", v) for k, v in pe_info.get("version_info_claimed", {}).items()]
    candidates += [("export", name) for name in pe_info.get("exports", [])]
    result["ai_directed_text"] = [{"where": where, "text": shorten(visible(text)), **flag}
                                  for where, text in candidates if (flag := ai_directed(text))]
    emit(result)


if __name__ == "__main__":
    main()
