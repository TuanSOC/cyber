"""`heuristic:disk_account_change@1` (low): account creation and privilege changes.

- EVTX Security 4720 (created), 4722 (enabled), 4728 / 4732 (member added to a global / local
  group), fields by position (an unknown layout skips the event, counted);
- auth logs: `useradd` creating an account with UID 0 or >= 1000 (packages create their system
  accounts with UIDs 1..999 at install time, which is not a finding), and `usermod` / `gpasswd`
  adding an account to a privileged group (`sudo`, `wheel`, `admin`, `root`, `adm`, `docker`,
  `lxd`). `sudo` usage itself is not an account change.

Events about the same change (one `usermod -aG` writes two lines) are one finding.
"""

import re
from dataclasses import dataclass, field

from cyberlab_jobs.disk import DiskEventRecord

from disk_worker.detections import events as ev
from disk_worker.detections import evtx_fields
from disk_worker.detections.base import Context, Finding, Rule, iso, quoted

USERADD = re.compile(r"new user: name=(?P<account>[^,\s]{1,64}), UID=(?P<uid>\d{1,10})")
USERMOD = re.compile(r"add '(?P<account>[^']{1,64})' to (?:shadow )?group '(?P<group>[^']{1,64})'")
GPASSWD = re.compile(r"user (?P<account>\S{1,64}) added by \S{1,64} to group (?P<group>\S{1,64})")
PRIVILEGED_GROUPS = frozenset({"sudo", "wheel", "admin", "root", "adm", "docker", "lxd"})
SYSTEM_UID_MAX = 999
EVTX_KINDS = {
    4720: "disk_account_created",
    4722: "disk_account_enabled",
    4728: "disk_group_member_added",
    4732: "disk_group_member_added",
}
CONFIDENCE = 0.6


@dataclass
class AccountChange(Rule):
    pending: dict[str, Finding] = field(default_factory=dict)

    def observe(self, event: DiskEventRecord, ctx: Context) -> None:
        record = ctx.evtx(event)
        if record is not None:
            kind = EVTX_KINDS.get(record.event_id)
            if kind is None or record.provider != evtx_fields.SECURITY:
                return
            if record.fields is None:
                ctx.counts["evtx_layout_unknown"] += 1
                return
            if kind == "disk_group_member_added":
                member = record.get("MemberName")
                account = member if member and member != "-" else record.get("MemberSid")
                group = record.get("TargetUserName") or "unknown"
            else:
                account, group = record.get("TargetUserName"), ""
                domain = record.get("TargetDomainName")
                if account and domain and domain != "-":
                    account = f"{domain}\\{account}"
            self._add(event, ctx, kind, account or "unknown", group, f"EVTX {record.event_id}", "")
            return
        line = ev.syslog(event)
        if line is None:
            return
        reporter, body = line[0].casefold(), line[1]
        if reporter == "useradd":
            found = USERADD.search(body)
            if found is None:
                return
            uid = int(found.group("uid"))
            if 0 < uid <= SYSTEM_UID_MAX:
                ctx.counts["system_account_created"] += 1
                return
            account = found.group("account")
            self._add(
                event, ctx, "disk_account_created", account, "", "useradd", f" with UID {uid}"
            )
        elif reporter in ("usermod", "gpasswd"):
            found = (USERMOD if reporter == "usermod" else GPASSWD).search(body)
            if found is None or found.group("group") not in PRIVILEGED_GROUPS:
                return
            self._add(
                event,
                ctx,
                "disk_group_member_added",
                found.group("account"),
                found.group("group"),
                reporter,
                "",
            )

    def _add(
        self,
        event: DiskEventRecord,
        ctx: Context,
        kind: str,
        account: str,
        group: str,
        source: str,
        detail: str,
    ) -> None:
        key = f"{kind}|{account.casefold()}|{group.casefold()}"
        finding = self.pending.get(key)
        if finding is None:
            if not ctx.budget.take():
                return
            finding = Finding(
                type=kind,
                severity="low",
                confidence=CONFIDENCE,
                values={
                    "account": quoted(account, 128),
                    "group": quoted(group, 128),
                    "source": source,
                    "when": iso(event.ts),
                    "detail": detail,
                },
                subject=account,
                key=key,
                ts=event.ts,
                attributes={"subject": quoted(account, 255), "group": quoted(group, 128)},
            )
            self.pending[key] = finding
        action = {
            "disk_account_created": "created",
            "disk_account_enabled": "enabled",
            "disk_group_member_added": f"added to {group}",
        }[kind]
        finding.cite(ev.cited(event, "account_change", f"Account {account} {action}"))

    def finish(self, ctx: Context) -> list[Finding]:
        return list(self.pending.values())
