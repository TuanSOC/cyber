# CyberLab M10 `quick` profile: the ONLY radare2 command script (RT9). Root-owned, 0444, run
# once per job as uid 10010 with `radare2 -q -NN -S -2 -i /opt/re/r2/quick.r2 <sample>` under
# the kit sandbox (stdout to a file bounded by RLIMIT_FSIZE; phase 3 reduces it in a probe).
# Never: the debugger (`ood`, `dc`, `-d`), ESIL emulation (`aaaa`, `aae*`, `aez*`), shell
# escapes (`!`), file writes (`wt*`), web server (`=h`), project or plugin loading.
# Field names of the JSON commands are confirmed by the phase-3 engine smoke [I].
e scr.color=0
e scr.interactive=false
e scr.utf8=false
e cfg.fortunes=false
e bin.relocs.apply=true
e bin.demangle=true
e bin.dbginfo=false
e io.cache=true
e anal.jmp.tbl=true
e anal.hasnext=false
aa
aac
aar
aan
?e ===CYBERLAB:info===
ij
?e ===CYBERLAB:functions===
aflj
?e ===CYBERLAB:imports===
iij
?e ===CYBERLAB:strings===
izj
?e ===CYBERLAB:end===
q
