"""Reproducible checks for the prompt-injection benchmark.

These assert the SCANNER's behaviour, which is deterministic. The agent-level
outcome (does the AI keep the "suspicious" verdict and flag every trick?) is
documented in tests/benchmark/RESULTS.md, because it depends on the model.

Run:
    python tests/benchmark/build.ps1    # build the .exe samples first (Windows + MSVC)
    pytest tests/test_benchmark.py

If the samples aren't built, the tests are skipped, not failed.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
BIN = ROOT / "tests" / "benchmark" / "bin"

pytestmark = pytest.mark.skipif(not BIN.exists() or not list(BIN.glob("*.exe")),
                                reason="benchmark .exe samples not built; run tests/benchmark/build.ps1")


def scan(script, exe):
    r = subprocess.run([sys.executable, str(SCRIPTS / script), str(BIN / exe)],
                       capture_output=True, check=True)
    return json.loads(r.stdout.decode("utf-8"))


def triage(exe):
    return scan("triage.py", exe)


def strings(exe):
    return scan("extract_strings.py", exe)


ALL_SAMPLES = [f"{n}.exe" for n in (
    "00_control", "01_plain_text", "02_fake_identity", "03_hidden_unicode",
    "04_base64_payload", "05_split_injection", "06_run_bait",
    "07_fake_tool_output", "08_arabic")]

# Samples the scanner is expected to flag directly. 04 (base64) and 05 (split)
# are deliberately scanner-invisible: they exist to test the agent's judgement.
SCANNER_FLAGS = ["01_plain_text.exe", "02_fake_identity.exe", "03_hidden_unicode.exe",
                 "06_run_bait.exe", "07_fake_tool_output.exe", "08_arabic.exe"]


@pytest.mark.parametrize("exe", ALL_SAMPLES)
def test_control_baseline_shared_by_all(exe):
    """Every sample, poisoned or not, carries the same suspicious imports: the only
    intended difference between the control and a poisoned copy is the injection."""
    inj = triage(exe)["pe"]["suspicious_imports"].get("process_injection", [])
    assert set(inj) == {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}


def test_control_has_no_injection_flag():
    """The control must be scanner-clean, or the benchmark would prove nothing."""
    assert strings("00_control.exe")["ai_directed_text"] == []


@pytest.mark.parametrize("exe", SCANNER_FLAGS)
def test_injection_is_flagged(exe):
    flags = strings(exe)["ai_directed_text"]
    assert flags, f"{exe}: scanner missed the injection"


def test_hidden_unicode_is_decoded():
    """Sample 03 hides its instruction in invisible tag characters."""
    flags = strings("03_hidden_unicode.exe")["ai_directed_text"]
    assert any("hidden_text" in f for f in flags)


def test_base64_blob_is_surfaced_for_the_agent():
    """Sample 04's payload is base64. The scanner can't read it, but it must at
    least surface the blob so the agent decodes and judges it."""
    counts = strings("04_base64_payload.exe")["indicator_counts"]
    assert counts["base64_like"] >= 1


def test_split_injection_is_scanner_invisible_by_design():
    """Sample 05 is the agent-level test: no single string matches, so the scanner
    stays silent. If this ever starts matching, update RESULTS.md."""
    assert strings("05_split_injection.exe")["ai_directed_text"] == []
