"""`heuristic:disk_remote_logon@1`.

- low: successful remote logons, one finding per (source address, account, logon kind) with
  count, first and last time: EVTX Security 4624 logon types 3 (network) and 10 (remote
  interactive) from a non-loopback address; `sshd` "Accepted ..." lines (Plaso's
  `syslog:ssh:login`, or a plain syslog line).
- medium: a burst of failures from one source: >= `BURST` EVTX 4625 records, or `sshd`
  "Failed ..." lines, within 10 minutes. Failures are counted in per-minute buckets per source,
  so the input does not need to be in time order and memory stays bounded by the number of
  (source, minute) pairs (budgeted). One finding per source and family, for its densest window.

A source address of `-`, empty, loopback or unspecified is not a remote logon. The source IP of
every finding becomes an IOC.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address

from cyberlab_jobs.disk import DiskEventRecord

from disk_worker.detections import events as ev
from disk_worker.detections import evtx_fields
from disk_worker.detections.base import CitedEvent, Context, Finding, Rule, iso, joined, quoted

BURST = 20
BURST_MINUTES = 10  # buckets m .. m + 9: every event within 10 minutes of the first
MAX_BUCKET_ORDINALS = 3
MAX_ACCOUNTS = 8
REMOTE_TYPES = {"3": "type 3, network", "10": "type 10, remote interactive"}
ACCEPTED = re.compile(
    r"^Accepted (?P<method>\S{1,64}) for (?P<account>\S{1,128}) from (?P<address>\S{1,64})"
    r" port \d{1,5}"
)
FAILED = re.compile(
    r"^Failed (?:\S{1,64}) for (?:invalid user )?(?P<account>\S{1,128}) from "
    r"(?P<address>\S{1,64}) port \d{1,5}"
)
CONFIDENCE_LOGON = 0.5
CONFIDENCE_BURST = 0.7


@dataclass
class _Bucket:
    count: int
    first: datetime
    last: datetime
    events: list[CitedEvent] = field(default_factory=list)


@dataclass
class _Failures:
    ip: IPv4Address | IPv6Address
    family: str
    buckets: dict[int, _Bucket] = field(default_factory=dict)
    accounts: list[str] = field(default_factory=list)


@dataclass
class RemoteLogon(Rule):
    logons: dict[str, Finding] = field(default_factory=dict)
    counts: dict[str, tuple[int, datetime, datetime]] = field(default_factory=dict)
    failures: dict[tuple[str, str], _Failures] = field(default_factory=dict)

    def observe(self, event: DiskEventRecord, ctx: Context) -> None:
        record = ctx.evtx(event)
        if record is not None:
            if record.provider != evtx_fields.SECURITY or record.event_id not in (4624, 4625):
                return
            if record.fields is None:
                ctx.counts["evtx_layout_unknown"] += 1
                return
            ip = ev.address(record.get("IpAddress"))
            account = record.get("TargetUserName") or "unknown"
            if ip is None:
                return
            if record.event_id == 4624:
                kind = REMOTE_TYPES.get((record.get("LogonType") or "").strip())
                if kind is not None:
                    self._success(event, ctx, ip, account, kind, "EVTX 4624")
            else:
                self._failure(event, ctx, ip, account, "EVTX 4625")
            return
        if event.data_type == "syslog:ssh:login":
            ip = ev.address(ev.text(event, "address"))
            if ip is not None:
                method = ev.text(event, "authentication_method") or "unknown method"
                account = ev.text(event, "username") or "unknown"
                self._success(event, ctx, ip, account, f"SSH, {method}", "sshd")
            return
        line = ev.syslog(event)
        if line is None or line[0].casefold() != "sshd":
            return
        accepted = ACCEPTED.match(line[1])
        if accepted:
            ip = ev.address(accepted.group("address"))
            if ip is not None:
                kind = f"SSH, {accepted.group('method')}"
                self._success(event, ctx, ip, accepted.group("account"), kind, "sshd")
            return
        failed = FAILED.match(line[1])
        if failed:
            ip = ev.address(failed.group("address"))
            if ip is not None:
                self._failure(event, ctx, ip, failed.group("account"), "sshd")

    def _success(
        self,
        event: DiskEventRecord,
        ctx: Context,
        ip: IPv4Address | IPv6Address,
        account: str,
        kind: str,
        source: str,
    ) -> None:
        key = f"{source}|{ip}|{account.casefold()}|{kind}"
        finding = self.logons.get(key)
        if finding is None:
            if not ctx.budget.take():
                return
            finding = Finding(
                type="disk_remote_logon",
                severity="low",
                confidence=CONFIDENCE_LOGON,
                values={
                    "address": str(ip),
                    "account": quoted(account, 128),
                    "logon_kind": quoted(kind, 64),
                    "source": source,
                },
                subject=str(ip),
                key=key,
                ts=event.ts,
                src_ip=ip,
                attributes={
                    "subject": str(ip),
                    "account": quoted(account, 128),
                    "logon_kind": quoted(kind, 64),
                },
            )
            self.logons[key] = finding
            self.counts[key] = (0, event.ts, event.ts)
        count, first, last = self.counts[key]
        self.counts[key] = (count + 1, min(first, event.ts), max(last, event.ts))
        title = f"Remote logon ({kind}) of {account} from {ip}"
        finding.cite(ev.cited(event, "logon", title, str(ip)))

    def _failure(
        self,
        event: DiskEventRecord,
        ctx: Context,
        ip: IPv4Address | IPv6Address,
        account: str,
        family: str,
    ) -> None:
        key = (family, str(ip))
        source = self.failures.get(key)
        if source is None:
            if not ctx.budget.take():
                return
            source = self.failures[key] = _Failures(ip, family)
        bucket_key = ev.minute(event.ts)
        bucket = source.buckets.get(bucket_key)
        if bucket is None:
            if not ctx.budget.take():
                return
            bucket = source.buckets[bucket_key] = _Bucket(0, event.ts, event.ts)
        bucket.count += 1
        bucket.first = min(bucket.first, event.ts)
        bucket.last = max(bucket.last, event.ts)
        if len(bucket.events) < MAX_BUCKET_ORDINALS:
            title = f"Failed logon of {account} from {ip}"
            bucket.events.append(ev.cited(event, "logon", title, str(ip)))
        if account not in source.accounts and len(source.accounts) < MAX_ACCOUNTS:
            source.accounts.append(account)

    def finish(self, ctx: Context) -> list[Finding]:
        out: list[Finding] = []
        for key, finding in self.logons.items():
            count, first, last = self.counts[key]
            finding.ts = first
            finding.values.update(count=count, first=iso(first), last=iso(last))
            finding.attributes["count"] = count
            out.append(finding)
        for (family, address), source in sorted(self.failures.items()):
            window = _densest(source.buckets)
            if window is None:
                continue
            total, buckets = window
            found = Finding(
                type="disk_logon_failure_burst",
                severity="medium",
                confidence=CONFIDENCE_BURST,
                values={
                    "count": total,
                    "address": address,
                    "source": family,
                    "first": iso(buckets[0].first),
                    "last": iso(buckets[-1].last),
                    "accounts": quoted(joined(source.accounts), 255),
                },
                subject=address,
                key=f"{family}|{address}",
                ts=buckets[0].first,
                src_ip=source.ip,
                attributes={"subject": address, "count": total, "source": family},
            )
            for bucket in buckets:
                for cited in bucket.events:
                    found.cite(cited)
            out.append(found)
        return out


def _densest(buckets: dict[int, _Bucket]) -> tuple[int, list[_Bucket]] | None:
    """The 10-minute window with the most failures, if it reaches `BURST`."""
    keys = sorted(buckets)
    best: tuple[int, int, int] | None = None  # (total, start index, end index)
    total = 0
    start = 0
    for end, minute in enumerate(keys):
        total += buckets[minute].count
        while minute - keys[start] >= BURST_MINUTES:
            total -= buckets[keys[start]].count
            start += 1
        if total >= BURST and (best is None or total > best[0]):
            best = (total, start, end)
    if best is None:
        return None
    return best[0], [buckets[k] for k in keys[best[1] : best[2] + 1]]
