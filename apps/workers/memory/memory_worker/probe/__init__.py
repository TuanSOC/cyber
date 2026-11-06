"""Volatility probe: runs as the tool uid in `python -I -s -B -m memory_worker.probe` (M8
phase 2). Library mode, offline, one plugin per process.

- `plugins`: the allow-list table (fixed configuration per plugin; pure data);
- `guard`: the PEP 578 audit hook (refuses and counts network / process events, RT7);
- `encode`: the row encoder and the streaming TreeGrid visitor (row cap);
- `vol`: the only module that imports Volatility (offline setup, identify, one plugin);
- `main`: the command line (`identify`, `run <plugin>`).
"""
