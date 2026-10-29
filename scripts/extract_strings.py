"""Extract strings from a sample and flag indicators and text aimed at an AI.

Usage: python extract_strings.py FILE [--min-len 5] [--max-other 200] [--out strings.txt]

Read-only: the sample is never executed.
"""
import argparse
import re

import pefile

from common import UNTRUSTED_NOTICE, ai_directed, decode, emit, hashes, hidden_text, read_sample, shorten, visible

# Strictly valid UTF-8 (no overlongs or surrogates), so decoding hostile bytes can never fail.
# It covers plain ASCII too; C1 control characters are excluded to keep binary noise out.
_UTF8 = (rb"(?:[\x20-\x7e]|\xc2[\xa0-\xbf]|[\xc3-\xdf][\x80-\xbf]"
         rb"|\xe0[\xa0-\xbf][\x80-\xbf]|[\xe1-\xec\xee\xef][\x80-\xbf]{2}|\xed[\x80-\x9f][\x80-\xbf]"
         rb"|\xf0[\x90-\xbf][\x80-\xbf]{2}|[\xf1-\xf3][\x80-\xbf]{3}|\xf4[\x80-\x8f][\x80-\xbf]{2}){%d,}")
# UTF-16LE as Windows stores it: ASCII range plus the Arabic block (U+0600-06FF).
_UTF16 = rb"(?:[\x20-\x7e]\x00|[\x00-\xff]\x06){%d,}"

_INDICATORS = {
    "urls": r"\b(?:https?|ftp)://[^\s\"'<>]{3,}",
    "ipv4": r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
    "emails": r"\b[A-Z0-9._%+-]+@[A-Z0-9-]+(?:\.[A-Z0-9-]+)*\.[A-Z]{2,}\b",
    "registry": r"\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU)\\|\bSoftware\\Microsoft\\Windows\\CurrentVersion\\Run"
                r"|\b(?:SOFTWARE|SYSTEM)\\(?:CurrentControlSet|Microsoft|Policies|Classes)\\",
    "paths": r"(?<!\w)[A-Z]:\\[^\s\"*?<>|]{3,}|%[A-Z_]+%\\",
    "commands": r"\b(?:cmd(?:\.exe)?\s+/[ck]|powershell|pwsh|schtasks|vssadmin|bcdedit|wevtutil|wmic|certutil"
                r"|bitsadmin|mshta|rundll32|regsvr32|net\s+(?:user|localgroup|stop)|reg\s+(?:add|delete)"
                r"|taskkill|attrib\s+\+h)\b",
    # Needs a digit, + or / somewhere, so long API names made only of letters don't count,
    # and isn't pure hex, which hex_like covers.
    "base64_like": r"^(?![0-9A-F]+$)(?=[A-Z0-9+/]*[0-9+/])[A-Z0-9+/]{40,}={0,2}$",
    # Hashes, keys and build IDs.
    "hex_like": r"^[0-9A-F]{32,}$",
}
_INDICATOR_REGEXES = {name: re.compile(p, re.IGNORECASE) for name, p in _INDICATORS.items()}
MAX_PER_INDICATOR = 100


def scan(data, min_len):
    """Yield (offset, encoding, text) for every string in data."""
    for m in re.finditer(_UTF8 % min_len, data):
        raw = m.group()
        yield m.start(), "ascii" if raw.isascii() else "utf-8", raw.decode("utf-8")
    for m in re.finditer(_UTF16 % min_len, data):
        yield m.start(), "utf-16le", m.group().decode("utf-16le")


def regions(data):
    """File ranges of PE headers, sections, signature and overlay, so each string can say where it came from."""
    if not data.startswith(b"MZ"):
        return []
    try:
        pe = pefile.PE(data=data, fast_load=True)
    except Exception:  # best effort: a malformed PE still gets its strings, just without regions
        return []
    ranges = [(s.PointerToRawData, s.PointerToRawData + s.SizeOfRawData, decode(s.Name))
              for s in pe.sections if s.SizeOfRawData]
    first = min((start for start, _, _ in ranges), default=len(data))
    last = max((end for _, end, _ in ranges), default=0)
    # The security directory is the one data directory addressed by file offset rather than RVA.
    sig = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
    signature = [(sig.VirtualAddress, sig.VirtualAddress + sig.Size, "signature")] if sig.VirtualAddress and sig.Size else []
    return signature + [(0, first, "headers")] + ranges + [(last, len(data), "overlay")]


def region_of(offset, ranges):
    return next((name for start, end, name in ranges if start <= offset < end), None)


def readable(text):
    """Cheap filter that keeps words and sentences and drops most byte noise."""
    good = sum(c.isalnum() or c in " .,:;_-/\\'\"()[]%@!?" for c in text)
    return len(text) >= 6 and good / len(text) >= 0.85 and any(c.isalpha() for c in text)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("file")
    ap.add_argument("--min-len", type=int, default=5)
    ap.add_argument("--max-other", type=int, default=200, help="readable strings to include besides indicators")
    ap.add_argument("--out", help="write every string with its offset to this file, for grep")
    args = ap.parse_args()

    data = read_sample(args.file)
    strings = sorted(scan(data, args.min_len))
    ranges = regions(data)
    ai_hits, other, signature_strings, dump = [], [], [], []
    indicators = {name: [] for name in _INDICATORS}

    for offset, enc, raw in strings:
        region = region_of(offset, ranges)
        entry = {"offset": hex(offset), "enc": enc, "text": shorten(visible(raw))}
        if region:
            entry["region"] = region
        if hidden := hidden_text(raw):
            entry["hidden_text"] = shorten(hidden)
        dump.append(f"{offset:#010x}  {enc:<8}  {region or '-':<10}  {visible(raw)}"
                    + (f"  [hidden: {hidden}]" if hidden else ""))

        flag = ai_directed(raw)
        if flag:
            ai_hits.append({**entry, **flag})
        if region == "signature":
            # Certificate data: kept apart so it doesn't drown out the program's own strings.
            signature_strings.append(entry)
            continue
        flagged = bool(flag)
        for name, rx in _INDICATOR_REGEXES.items():
            if rx.search(raw):
                indicators[name].append(entry)
                flagged = True
        if not flagged and readable(raw):
            other.append(entry)

    # Longest readable strings carry the most context (messages, configs, scripts).
    sample = sorted(sorted(other, key=lambda e: -len(e["text"]))[:args.max_other], key=lambda e: int(e["offset"], 16))

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write("\n".join(dump) + "\n")

    signature_region = None
    if sig_bytes := next((end - start for start, end, name in ranges if name == "signature"), 0):
        signature_region = {
            "bytes": sig_bytes,
            "strings": len(signature_strings),
            "sample": list({e["text"]: e for e in signature_strings}.values())[:10],
        }

    emit({
        "tool": "extract_strings",
        "notice": UNTRUSTED_NOTICE,
        "sha256": hashes(data)["sha256"],
        "total_strings": len(strings),
        "ai_directed_text": sorted(ai_hits, key=lambda e: e["severity"] != "high"),
        "indicator_counts": {name: len(items) for name, items in indicators.items()},
        "indicators": {name: items[:MAX_PER_INDICATOR] for name, items in indicators.items() if items},
        "other_strings": sample,
        "other_strings_omitted": len(other) - len(sample),
        "signature_region": signature_region,
        "full_dump": args.out,
    })


if __name__ == "__main__":
    main()
