"""Sample parsers that run ONLY as the tool uid (never imported by the root process for parsing).

Invoked by the analyzer as `python -I -s -B -m static_worker.probe <mode> <sample> [options]`
with cwd = the root-owned input dir; stdout goes to a fresh, tool-owned out directory and
every mode writes JSON lines. The root process reads that output through the kit's bounded
reader and re-validates every record against the `static.v1` contract, so a compromised
probe can only produce bounded, typed garbage, never root code execution.

Modes: archive (zip pre-check for ClamAV coverage), facts (hashes, libmagic, entropy,
ssdeep), pe (pefile), elf
(pyelftools), strings (ASCII + UTF-16LE), yara (yara-python with a timeout), capa / floss
(reduce the tool's JSON document to bounded records).
"""
