#!/usr/bin/env python3
"""`pnpm ops:metrics` (M7 phase 5): replay the M2 dataset and the M3 sample set through the
real workers and write plans/reports/ops-metric-YYMMDD.md. Standard library only.

A HEAVY step: the parent runs it alone, on the host, with the dev stack up (api, postgres,
redis, broker, minio, ingest worker) and nothing else heavy. It is never part of the gate.

  python scripts/ops_metrics.py --manage-workers            # recommended (RAM: one analyzer
                                                             # at a time, pcap then static)
  python scripts/ops_metrics.py --rounds 1 --skip static    # a quick pcap-only replay
  python scripts/ops_metrics.py --org <id> --email <e> --password-file <f>   # existing org

Steps:
1. Generate the datasets into the Docker volume `cyberlab_ops_samples` (never on the host disk:
   host AV quarantines some samples, as for the e2e): the M2 pcap dataset
   (`apps/workers/pcap/dataset`, `python -m dataset.generate` in the pcap-worker image) and the
   M3 sample set (`python -m samples.generate` in the static-worker image).
2. Per analyzer (`--manage-workers` starts that analyzer and stops the other one): run the
   replay driver in a one-off `api-test` container (backend network, the volume mounted
   read-only, no other service started). It registers a throwaway org (or logs in to
   `--org`), uploads every file `--rounds` times through `http://api:8000`, makes sure each
   upload gets its analysis (the automatic one, else a manual request, paced by the
   rate limits' `Retry-After`) and waits for every job to finish.
3. Read `GET /api/v1/orgs/{org}/ops/metrics` (the replay org's own numbers) and
   `/internal/metrics` (platform-wide, read inside the api container with its own token file,
   so the token never leaves it; "off" when no token is configured).
4. Write the report: rounds, jobs per analyzer, failure rate, run and queue latency p50 / p95,
   parse success, failures by class, host notes (RAM, image tags) and the command line.

`--inner` is the driver mode used by step 2 (inside api-test); it is not meant to be run by
hand. `pnpm ops:metrics` currently starts this file inside api-test (phase-1 wiring); there it
only prints these instructions: run it on the host as above.
"""

import argparse
import datetime as dt
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
VOLUME = "cyberlab_ops_samples"
COMPOSE = ["docker", "compose"]
COMPOSE_RUN = [*COMPOSE, "--profile", "test", "run", "--rm", "--no-deps"]
WORKERS = {"pcap": "pcap-worker", "static": "static-worker"}
BEGIN, END = "=== OPS REPLAY BEGIN ===", "=== OPS REPLAY END ==="
API = "http://api:8000"
TERMINAL = {"succeeded", "failed"}

# The api container reads its own token file and asks itself: the token is never printed,
# passed as an argument or stored by this script.
INTERNAL_FETCH = r"""
import os, sys, urllib.error, urllib.request
path = os.environ.get("METRICS_TOKEN_FILE")
token = open(path, encoding="utf-8").read().strip() if path and os.path.isfile(path) else ""
if not token:
    print("OFF"); sys.exit(0)
req = urllib.request.Request("http://127.0.0.1:8000/internal/metrics",
                             headers={"Authorization": "Bearer " + token})
try:
    print(urllib.request.urlopen(req, timeout=30).read().decode())
except urllib.error.HTTPError as e:
    print("HTTP", e.code)
"""


def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argument lists, no shell
        command, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace",
        env={**os.environ, "MSYS_NO_PATHCONV": "1"}, **kwargs,
    )  # fmt: skip


def must(command: list[str], what: str) -> str:
    proc = run(command)
    if proc.returncode:
        sys.stderr.write(f"ops_metrics: {what} failed (exit {proc.returncode})\n")
        sys.stderr.write(proc.stdout[-3000:] + proc.stderr[-3000:])
        raise SystemExit(proc.returncode)
    return proc.stdout


# --- inner driver (api-test, backend network, stdlib HTTP) ----------------------------------


class Client:
    """A minimal cookie-keeping JSON client (the dev cookies are not `Secure`, but every
    cookie is sent back regardless, as the browser on the gateway origin would)."""

    def __init__(self, base: str) -> None:
        self.base = base
        self.cookies: dict[str, str] = {}

    def request(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        data: bytes | None = None,
        params: dict[str, str] | None = None,
    ) -> tuple[int, Any, dict[str, str]]:
        url = self.base + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        headers = {"Accept": "application/json"}
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if method not in ("GET", "HEAD") and "cl_csrf" in self.cookies:
            headers["X-CSRF-Token"] = self.cookies["cl_csrf"]
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        elif data is not None:
            headers["Content-Type"] = "application/octet-stream"
        # A fixed http:// base (the api service on the backend network), never user input.
        req = urllib.request.Request(url, data=data, method=method, headers=headers)  # noqa: S310
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310
                status, raw, got = resp.status, resp.read(), resp.headers
        except urllib.error.HTTPError as exc:
            status, raw, got = exc.code, exc.read(), exc.headers
        for cookie in got.get_all("Set-Cookie") or []:
            name, _, rest = cookie.partition("=")
            self.cookies[name.strip()] = rest.split(";", 1)[0]
        try:
            payload = json.loads(raw) if raw else None
        except ValueError:
            payload = raw.decode(errors="replace")
        return status, payload, dict(got.items())

    def call(self, method: str, path: str, ok: tuple[int, ...] = (200,), **kw: Any) -> Any:
        """Retries on 429 / 409 busy answers after their Retry-After (rate limits, caps)."""
        for _ in range(60):
            status, payload, headers = self.request(method, path, **kw)
            if status in ok:
                return payload
            if status in (429, 409, 503):
                wait = int(headers.get("Retry-After") or 15)
                print(f"  {method} {path}: {status}, retrying in {wait} s", flush=True)
                time.sleep(min(max(wait, 1), 120))
                continue
            raise RuntimeError(f"{method} {path}: {status} {payload}")
        raise RuntimeError(f"{method} {path}: still refused after retries")


def _analyzer_body(name: str) -> dict[str, str]:
    return {"analyzer": "pcap"} if name == "pcap" else {"analyzer": "static", "profile": "full"}


def inner(args: argparse.Namespace) -> int:
    client = Client(API)
    password = os.environ.get("OPS_PASSWORD", "")
    if args.register:
        body = client.call(
            "POST", "/api/v1/auth/register", ok=(201,),
            body={"email": args.email, "password": password, "display_name": "ops-replay",
                  "organization_name": f"Ops replay {dt.date.today().isoformat()}"},
        )  # fmt: skip
        org = body["memberships"][0]["organization_id"]
    else:
        client.call("POST", "/api/v1/auth/login", body={"email": args.email, "password": password})
        org = args.org
    base = f"/api/v1/orgs/{org}"
    case = client.call(
        "POST", f"{base}/investigations", ok=(201,),
        body={"title": f"Ops replay {args.phase}", "severity": "low"},
    )["id"]  # fmt: skip
    files = sorted(
        p for p in Path(args.data, args.phase).iterdir() if p.is_file() and p.suffix != ".json"
    )
    if not files:
        raise RuntimeError(f"no {args.phase} files in {args.data}")
    jobs: list[dict[str, Any]] = []
    for round_ in range(1, args.rounds + 1):
        started = time.monotonic()
        evidence: list[tuple[str, str]] = []
        for path in files:
            out = client.call(
                "POST", f"{base}/investigations/{case}/evidence", ok=(201,),
                params={"filename": path.name}, data=path.read_bytes(),
            )  # fmt: skip
            evidence.append((out["id"], path.name))
        print(f"round {round_}: uploaded {len(evidence)} {args.phase} files", flush=True)
        # The automatic analysis is rate limited per user; request it explicitly if skipped.
        time.sleep(5)
        for evidence_id, _ in evidence:
            page = client.call("GET", f"{base}/evidence/{evidence_id}/analyses")
            if not any(j["analyzer"] == args.phase for j in page["items"]):
                client.call(
                    "POST", f"{base}/evidence/{evidence_id}/analyses", ok=(201,),
                    body=_analyzer_body(args.phase),
                )  # fmt: skip
        deadline = time.monotonic() + args.timeout_s
        pending = dict(evidence)
        while pending and time.monotonic() < deadline:
            time.sleep(10)
            for evidence_id in list(pending):
                page = client.call("GET", f"{base}/evidence/{evidence_id}/analyses")
                mine = [j for j in page["items"] if j["analyzer"] == args.phase]
                if mine and all(j["status"] in TERMINAL for j in mine):
                    for j in mine:
                        jobs.append({"round": round_, "file": pending[evidence_id], **{
                            k: j[k] for k in ("id", "analyzer", "profile", "status",
                                              "error_code", "created_at", "started_at",
                                              "finished_at")}})  # fmt: skip
                    del pending[evidence_id]
        print(
            f"round {round_}: {len(evidence) - len(pending)} finished, {len(pending)} not "
            f"finished after {time.monotonic() - started:.0f} s",
            flush=True,
        )
        for evidence_id, name in pending.items():
            jobs.append({"round": round_, "file": name, "evidence_id": evidence_id,
                         "status": "unfinished", "analyzer": args.phase})  # fmt: skip
    metrics = {w: client.call("GET", f"{base}/ops/metrics", params={"window": w})
               for w in ("1h", "24h")}  # fmt: skip
    print(BEGIN)
    print(json.dumps({"org_id": org, "phase": args.phase, "jobs": jobs, "metrics": metrics}))
    print(END)
    return 0


# --- host orchestrator ------------------------------------------------------------------------


def generate_datasets() -> None:
    must(["docker", "volume", "create", VOLUME], "volume create")
    as_root = ["docker", "run", "--rm", "--user", "0", "-v", f"{VOLUME}:/out"]
    must([*as_root, "--entrypoint", "sh", "cyberlab/static-worker:dev", "-c",
          "rm -rf /out/* && mkdir -p /out/pcap /out/static"], "volume reset")  # fmt: skip
    dataset = str(ROOT / "apps" / "workers" / "pcap" / "dataset")
    must([*as_root, "--entrypoint", "python", "-v", f"{dataset}:/srv/workers/pcap/dataset:ro",
          "cyberlab/pcap-worker:dev", "-m", "dataset.generate", "/out/pcap"],
         "pcap dataset generation")  # fmt: skip
    must([*as_root, "--entrypoint", "sh", "cyberlab/static-worker:dev", "-c",
          "python -m samples.generate /out/static >/dev/null && chmod -R a+rX /out"],
         "static sample generation")  # fmt: skip


def switch_worker(phase: str) -> None:
    other = "static" if phase == "pcap" else "pcap"
    must([*COMPOSE, "stop", WORKERS[other]], f"stop {WORKERS[other]}")
    must([*COMPOSE, "up", "-d", "--no-deps", WORKERS[phase]], f"start {WORKERS[phase]}")


def replay(phase: str, args: argparse.Namespace, email: str, password: str, org: str | None,
           register: bool) -> dict[str, Any]:  # fmt: skip
    command = [
        # `-e OPS_PASSWORD` without a value: docker reads it from its own environment, so the
        # password is never on a command line.
        *COMPOSE_RUN, "-v", f"{VOLUME}:/data:ro", "-e", "OPS_PASSWORD",
        "api-test", "python", "/srv/scripts/ops_metrics.py", "--inner", "--phase", phase,
        "--data", "/data", "--rounds", str(args.rounds), "--timeout-s", str(args.timeout_s),
        "--email", email, *(["--register"] if register else ["--org", org or ""]),
    ]  # fmt: skip
    print(f"replaying {phase} x{args.rounds} ...", flush=True)
    proc = subprocess.run(  # noqa: S603 - fixed argument list
        command, cwd=ROOT, text=True, encoding="utf-8", errors="replace",
        stdout=subprocess.PIPE, stderr=sys.stderr,
        env={**os.environ, "MSYS_NO_PATHCONV": "1", "OPS_PASSWORD": password},
    )  # fmt: skip
    out = proc.stdout
    for line in out[: out.find(BEGIN)].splitlines()[-20:]:
        print("  " + line)
    if proc.returncode or BEGIN not in out:
        sys.stderr.write(out[-4000:])
        raise SystemExit(proc.returncode or 1)
    return json.loads(out[out.index(BEGIN) + len(BEGIN) : out.index(END)])


def internal_metrics() -> str:
    proc = run([*COMPOSE, "exec", "-T", "api", "python", "-c", INTERNAL_FETCH])
    return proc.stdout if proc.returncode == 0 else f"ERROR exit {proc.returncode}"


def host_notes() -> list[str]:
    notes = []
    info = run(["docker", "info", "--format", "{{.MemTotal}} {{.NCPU}} {{.ServerVersion}}"])
    if info.returncode == 0 and info.stdout.strip():
        mem, cpus, version = (info.stdout.split() + ["?", "?", "?"])[:3]
        gib = f"{int(mem) / 2**30:.1f} GiB" if mem.isdigit() else mem
        notes.append(f"Docker engine {version}: {gib} RAM, {cpus} CPUs")
    images = run([*COMPOSE, "images", "--format", "json"])
    if images.returncode == 0 and images.stdout.strip():
        try:
            rows = json.loads(images.stdout)
        except ValueError:
            rows = [json.loads(line) for line in images.stdout.splitlines() if line.strip()]
        for row in rows:
            name = row.get("ContainerName") or row.get("Service") or "?"
            wanted = ("api", "pcap-worker", "static-worker", "ingest", "postgres")
            if any(k in name for k in wanted):
                notes.append(f"{name}: {row.get('Repository')}:{row.get('Tag')} "
                             f"({str(row.get('ID', ''))[:19]})")  # fmt: skip
    stats = run(["docker", "stats", "--no-stream", "--format", "{{.Name}} {{.MemUsage}}"])
    if stats.returncode == 0:
        notes += [f"after the replay: {line}" for line in stats.stdout.splitlines()
                  if "cyberlab" in line]  # fmt: skip
    return notes


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.1%}"


def _ms(value: int | None) -> str:
    return "n/a" if value is None else f"{value / 1000:.2f} s"


def internal_lines(text: str) -> list[str]:
    keep = re.compile(r'^cyberlab_(jobs|job_failure_ratio|parse_success_ratio|'
                      r'job_failures_by_class)\{kind="(pcap|static)".*window="24h"')  # fmt: skip
    return [line for line in text.splitlines() if keep.match(line)]


def write_report(args: argparse.Namespace, results: list[dict[str, Any]], internal: str,
                 notes: list[str], elapsed: float) -> Path:  # fmt: skip
    today = dt.datetime.now(dt.UTC)
    path = Path(args.write) if args.write else (
        ROOT / "plans" / "reports" / f"ops-metric-{today.strftime('%y%m%d')}.md"
    )
    jobs = [j for r in results for j in r["jobs"]]
    lines = [
        "# Runtime job metrics over a real replay (M7 phase 5)",
        "",
        f"Generated {today.strftime('%Y-%m-%d %H:%M UTC')} by "
        f"`python scripts/ops_metrics.py {' '.join(sys.argv[1:])}` in {elapsed / 60:.1f} min.",
        f"Rounds: {args.rounds}. Phases: {', '.join(r['phase'] for r in results)} "
        f"(one analyzer at a time: {'yes' if args.manage_workers else 'no'}). "
        "Datasets: the M2 synthetic pcap set and the M3 static sample set, generated into a "
        "Docker volume and uploaded through the API (`http://api:8000`) by a throwaway org.",
        "",
        "## Per analyzer (the replay org, `GET /ops/metrics?window=24h`)",
        "",
        "| Analyzer | Profile | Jobs | Succeeded | Failed | Failure rate | Parse success "
        "| Queue p50 / p95 | Run p50 / p95 | Failures by class |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for result in results:
        for item in result["metrics"]["24h"]["items"]:
            if item["kind"] != result["phase"]:
                continue
            classes = ", ".join(f"{k} {v}" for k, v in sorted(item["error_classes"].items()))
            lines.append(
                f"| {item['kind']} | {item['subkind'] or '-'} | {item['total']} | "
                f"{item['succeeded']} | {item['failed']} | {_pct(item['failure_ratio'])} | "
                f"{_pct(item['parse_success_ratio'])} | {_ms(item['queue_p50_ms'])} / "
                f"{_ms(item['queue_p95_ms'])} | {_ms(item['run_p50_ms'])} / "
                f"{_ms(item['run_p95_ms'])} | {classes or '-'} |"
            )
    lines += ["", "## Jobs per round", "", "| Analyzer | Round | Jobs | Failed | Unfinished |",
              "|---|---|---|---|---|"]  # fmt: skip
    for phase in sorted({j["analyzer"] for j in jobs}):
        for round_ in range(1, args.rounds + 1):
            mine = [j for j in jobs if j["analyzer"] == phase and j["round"] == round_]
            failed = sum(j["status"] == "failed" for j in mine)
            unfinished = sum(j["status"] == "unfinished" for j in mine)
            lines.append(f"| {phase} | {round_} | {len(mine)} | {failed} | {unfinished} |")
    failures = sorted({(j["analyzer"], j["file"], j.get("error_code")) for j in jobs
                       if j["status"] == "failed"})  # fmt: skip
    lines += ["", "## Failed jobs (file and error code)", ""]
    lines += [f"- {a} `{f}`: `{c}`" for a, f, c in failures] or ["- none"]
    lines += ["", "## Platform view (`/internal/metrics`, 24h, pcap and static)", ""]
    if internal.strip() == "OFF":
        lines.append("Not read: no `METRICS_TOKEN_FILE` is configured on the api (route off).")
    elif internal.startswith(("HTTP", "ERROR")):
        lines.append(f"Not read: {internal.strip()}.")
    else:
        lines += ["```", *internal_lines(internal), "```"]
    lines += ["", "## Host", "", *([f"- {n}" for n in notes] or ["- n/a"])]
    lines += ["", "The gate's own e2e jobs are recorded separately (phase 11).", ""]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    return path


def host(args: argparse.Namespace) -> int:
    if Path("/srv/api").is_dir() or shutil.which("docker") is None:
        sys.stderr.write(__doc__ or "")
        sys.stderr.write("\nops_metrics: run this on the host (python scripts/ops_metrics.py), "
                         "not inside a container\n")  # fmt: skip
        return 2
    started = time.monotonic()
    phases = [p for p in ("pcap", "static") if p not in args.skip]
    password = (
        Path(args.password_file).read_text(encoding="utf-8").strip()
        if args.password_file else secrets.token_urlsafe(24)
    )  # fmt: skip
    if args.org and not (args.email and args.password_file):
        sys.stderr.write("ops_metrics: --org needs --email and --password-file\n")
        return 2
    email = args.email or f"ops-replay-{secrets.token_hex(4)}@example.com"
    print("generating the datasets into the volume ...", flush=True)
    generate_datasets()
    results, org = [], args.org
    for phase in phases:
        if args.manage_workers:
            switch_worker(phase)
        result = replay(phase, args, email, password, org, register=org is None)
        org = result["org_id"]
        results.append(result)
    internal = internal_metrics()
    path = write_report(args, results, internal, host_notes(), time.monotonic() - started)
    print(f"written: {path.relative_to(ROOT) if path.is_relative_to(ROOT) else path}")
    unfinished = sum(j["status"] == "unfinished" for r in results for j in r["jobs"])
    return 1 if unfinished else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--org", default=None, help="an existing org (else a throwaway one)")
    parser.add_argument("--email", default=None)
    parser.add_argument("--password-file", default=None)
    parser.add_argument("--manage-workers", action="store_true",
                        help="start one analyzer at a time (stops the other)")  # fmt: skip
    parser.add_argument("--skip", choices=["pcap", "static"], action="append", default=[])
    parser.add_argument("--timeout-s", type=int, default=1800, help="per round")
    parser.add_argument("--write", default=None, metavar="PATH")
    # Driver mode (inside api-test).
    parser.add_argument("--inner", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--phase", choices=["pcap", "static"], help=argparse.SUPPRESS)
    parser.add_argument("--data", default="/data", help=argparse.SUPPRESS)
    parser.add_argument("--register", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.rounds < 1:
        parser.error("--rounds must be >= 1")
    if args.inner:
        if not args.phase or not args.email:
            parser.error("--inner needs --phase and --email")
        return inner(args)
    return host(args)


if __name__ == "__main__":
    sys.exit(main())
