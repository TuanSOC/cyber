"""Labels, budget and stats: raw selections -> `FrozenContext` (M5 phase 4).

Selection order is the output order (documented in `builder.py`): items are transformed and
labelled one by one (`F1`, `F2` … per kind, in that order) and added while the running
canonical size stays within the token budget. The first item that does not fit ends the
fill (every later item is omitted too), so a `T` item never refers to an omitted `I`, and
its pseudonyms are rolled back (numbering has no gaps).
"""

from collections import Counter
from dataclasses import dataclass, field

from app.modules.ai.context.encode import (
    canonical,
    empty_context_json,
    fields_sha256,
    item_json,
)
from app.modules.ai.context.estimate import chars_for_tokens, estimate_tokens
from app.modules.ai.context.fields import RawItem
from app.modules.ai.context.pseudonymize import Pseudonymizer, category_counts, used_pseudonyms
from app.modules.ai.context.transform import MAX_CODE_CHARS, Totals, Transformer
from app.modules.ai.contracts import (
    CONTEXT_VERSION,
    AiTask,
    ContextBuildError,
    ContextItem,
    ContextRef,
    ContextStats,
    FrozenContext,
    KindStats,
    RefKind,
    RunScope,
)
from app.modules.ai.labels import format_label


@dataclass
class Selection:
    """Candidate rows of one kind, in priority order; `total` counts every row of the kind in
    scope (not only the capped candidates)."""

    kind: RefKind
    items: list[RawItem]
    total: int


@dataclass
class Assembled:
    items: list[ContextItem] = field(default_factory=list)
    refs: list[ContextRef] = field(default_factory=list)
    included: Counter[RefKind] = field(default_factory=Counter)
    totals: Totals = field(default_factory=Totals)


def assemble(
    task: AiTask,
    scope: RunScope,
    selections: list[Selection],
    pseudonymizer: Pseudonymizer,
    *,
    budget_tokens: int,
    jobs_omitted: int = 0,
    max_code_chars: int = MAX_CODE_CHARS,
) -> FrozenContext:
    transformer = Transformer(pseudonymizer, max_code_chars=max_code_chars)
    out = Assembled()
    budget_chars = chars_for_tokens(budget_tokens)
    size = len(empty_context_json(task))
    counters: Counter[RefKind] = Counter()
    full = False
    for selection in selections:
        if full:
            break
        for raw in selection.items:
            snapshot = pseudonymizer.snapshot()
            fields, counts = transformer.fields(raw)
            label = format_label(raw.kind, counters[raw.kind] + 1)
            item = ContextItem(label=label, kind=raw.kind, fields=fields)
            added = len(item_json(item)) + (1 if out.items else 0)
            if size + added > budget_chars:
                pseudonymizer.restore(snapshot)
                full = True
                break
            size += added
            counters[raw.kind] += 1
            out.items.append(item)
            out.included[raw.kind] += 1
            out.totals.add(raw.kind, raw, counts)
            out.refs.append(
                ContextRef(
                    label=label,
                    kind=raw.kind,
                    ref_table=raw.ref_table,
                    ref_id=raw.ref_id,
                    job_id=raw.job_id,
                    fields_sha256=fields_sha256(fields),
                )
            )
    return finish(task, scope, out, selections, pseudonymizer.mapping, jobs_omitted=jobs_omitted)


def finish(
    task: AiTask,
    scope: RunScope,
    out: Assembled,
    selections: list[Selection],
    tree_map: dict[str, str],
    *,
    jobs_omitted: int = 0,
) -> FrozenContext:
    if not out.items:
        raise ContextBuildError("context_empty")
    totals: Counter[RefKind] = Counter()
    for selection in selections:
        totals[selection.kind] += selection.total
    per_kind: dict[RefKind, KindStats] = {}
    omitted = 0
    for kind in RefKind:
        included = out.included.get(kind, 0)
        total = max(totals.get(kind, 0), included)
        if total or included:
            per_kind[kind] = KindStats(included=included, total=total)
            omitted += total - included
    text = canonical(
        {
            "version": CONTEXT_VERSION,
            "task": task.value,
            "items": [i.model_dump(mode="json") for i in out.items],
        }
    )
    used = used_pseudonyms(text)
    pseudonym_map = {name: tree_map[name] for name in used if name in tree_map}
    t = out.totals
    stats = ContextStats(
        per_kind=per_kind,
        omitted=omitted,
        est_tokens=estimate_tokens(text),
        truncated=bool(omitted or jobs_omitted or t.truncated_fields or t.dropped_keys),
        truncated_fields={k: n for k, n in sorted(t.truncated_fields.items()) if n},
        dropped_keys=t.dropped_keys,
        pseudonymized=category_counts(pseudonym_map),
        neutralized=t.neutralized,
        stripped={k: v for k, v in t.stripped.as_dict().items() if v},
        jobs_omitted=jobs_omitted,
        code_literals_truncated=t.code_literals,
        code_identifiers_truncated=t.code_identifiers,
    )
    return FrozenContext(
        task=task,
        scope=scope,
        items=tuple(out.items),
        refs=tuple(out.refs),
        stats=stats,
        pseudonym_map=pseudonym_map,
    )
