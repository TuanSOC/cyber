"""radare2 `quick` profile (M10 phase 3 owns the body; the signature is frozen in phase 1).

One non-interactive run of the fixed script (`radare2 -q -NN -S -2 -i /opt/re/r2/quick.r2
<sample>`, RT9) as uid 10010 under the kit sandbox, stdout to a file bounded by RLIMIT_FSIZE,
reduced by `probe/r2.py` as the tool uid. No r2pipe, no decompilation, no ESIL, no debugger.
Until phase 3 lands, `run_quick` raises `ProfileUnavailable` (the API refuses `quick` with
`422 profile_unavailable` while `RE_QUICK_ENABLED=false`).
"""

from cyberlab_jobs.reverse import ReJobV1

from re_worker.engines import Budget, EngineOutput, ProfileUnavailable, Workspace


def run_quick(ws: Workspace, job: ReJobV1, budget: Budget) -> EngineOutput:
    del ws, job, budget
    raise ProfileUnavailable()
