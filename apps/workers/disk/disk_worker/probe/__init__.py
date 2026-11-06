"""The disk probe: TSK (pytsk3) and libewf (pyewf) in library mode, run as the tool uid in
`python -I -s -B -m disk_worker.probe <stage> <input/<name>.json>` (M9 phase 2). One stage
per process, offline (seccomp AF_UNIX-only + the PEP 578 audit hook).

- `names`: printable names / bounded paths, the mirrored-tree sanitizer (RT13, RT31);
- `magic`: the magic class of a file's first bytes;
- `rows`: bounded JSONL writers, `status.json`, the root-written stage arguments;
- `guard`: the audit hook (refuses and counts network / process / foreign dlopen events);
- `image`: raw / split raw / EWF readers handed to TSK as external images (RT6);
- `tsk`: the thin pytsk3 layer (explicit file-system families only; RT15);
- `verify`, `layout`, `walk`, `collect` (and `extract`), `scan_stage` (phase 5's
  `scan_yara`): the stages;
- `main`: the command line.
"""
