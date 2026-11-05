"""Incident reduce context (signature FROZEN in phase 1; body M5 phase 4).

Pure (no DB): the base (root) context plus, per child digest in the given order:
- `J{n}:D{k}` digest-claim items: only the child's **supported** observed / interpretation
  claims and its hypotheses, each marked `kind: digest_claim`, `untrusted: model_output`,
  with the child's flags (RT23) and its verified citations rewritten to `J{n}:<label>`.
  `D` labels are never valid as evidence (the verifier enforces it);
- then the cited child items, copied as `J{n}:F3` … with their original field values (so
  the verifier can check quotes against exactly what the child saw).

All D items come before all copied items; the same budget, estimate and hash rules apply
(the first item that does not fit ends the fill). The pseudonym map is the union of the base
and child maps, restricted to the pseudonyms present.
"""

from collections import Counter
from dataclasses import dataclass

from app.core.config import get_settings
from app.modules.ai.context.encode import canonical, fields_sha256, item_json
from app.modules.ai.context.estimate import chars_for_tokens, context_budget, estimate_tokens
from app.modules.ai.context.fields import RawItem, digest_fields
from app.modules.ai.context.pseudonymize import Pseudonymizer, category_counts, used_pseudonyms
from app.modules.ai.context.transform import ItemCounts, Transformer
from app.modules.ai.contracts import (
    CONTEXT_VERSION,
    CitationStatus,
    ClaimStatus,
    ContextItem,
    ContextRef,
    ContextStats,
    DigestInput,
    FrozenContext,
    KindStats,
    RefKind,
)
from app.modules.ai.labels import format_label, parse_label, qualify


@dataclass
class _Candidate:
    item: ContextItem
    ref: ContextRef
    counts: ItemCounts


def _verified_labels(digest: DigestInput, claim_id: str) -> list[str]:
    labels = [
        c.label
        for c in digest.citations
        if c.claim_id == claim_id and c.status is CitationStatus.VERIFIED
    ]
    out: list[str] = []
    for label in labels:
        parsed = parse_label(label)
        if parsed is None or parsed.job is not None or parsed.kind is RefKind.DIGEST_CLAIM:
            continue
        if digest.context.item(label) is not None and label not in out:
            out.append(label)
    return out


def _claims(digest: DigestInput) -> list[tuple[str, str, str, str]]:
    """(section, claim id, text, confidence) of the supported claims and the hypotheses."""
    out: list[tuple[str, str, str, str]] = []
    body = digest.body
    for section, entries in (("observed", body.observed), ("interpretation", body.interpretation)):
        for claim in entries:
            verdict = digest.claims.get(claim.id)
            if verdict is not None and verdict.status is ClaimStatus.SUPPORTED:
                out.append((section, claim.id, claim.text, str(claim.confidence)))
    for hypothesis in body.hypotheses:
        verdict = digest.claims.get(hypothesis.id)
        if verdict is None or verdict.status is ClaimStatus.HYPOTHESIS:
            out.append(("hypothesis", hypothesis.id, hypothesis.text, str(hypothesis.confidence)))
    return out


def _digest_candidates(
    digest: DigestInput, transformer: Transformer
) -> tuple[list[_Candidate], list[_Candidate]]:
    job = int(digest.job_label[1:])
    flags = [f.value for f in digest.flags]
    claims: list[_Candidate] = []
    cited: list[str] = []
    for k, (section, claim_id, text, confidence) in enumerate(_claims(digest), start=1):
        labels = _verified_labels(digest, claim_id)
        cited.extend(label for label in labels if label not in cited)
        raw = RawItem(
            RefKind.DIGEST_CLAIM,
            "ai_runs",
            str(digest.run_id),
            digest.job_id,
            digest_fields(
                section=section,
                text=text,
                confidence=confidence,
                citations=[qualify(label, job) for label in labels],
                flags=flags,
            ),
        )
        fields, counts = transformer.fields(raw, trusted=True)
        label = format_label(RefKind.DIGEST_CLAIM, k, job)
        claims.append(
            _Candidate(
                ContextItem(label=label, kind=RefKind.DIGEST_CLAIM, fields=fields),
                ContextRef(
                    label=label,
                    kind=RefKind.DIGEST_CLAIM,
                    ref_table=raw.ref_table,
                    ref_id=raw.ref_id,
                    job_id=digest.job_id,
                    fields_sha256=fields_sha256(fields),
                    stage="reduce",
                ),
                counts,
            )
        )
    refs = {r.label: r for r in digest.context.refs}
    copies: list[_Candidate] = []
    for label in cited:
        child = digest.context.item(label)
        ref = refs.get(label)
        if child is None or ref is None:
            continue
        qualified = qualify(label, job)
        copies.append(
            _Candidate(
                child.model_copy(update={"label": qualified}),
                ref.model_copy(update={"label": qualified, "stage": "reduce"}),
                ItemCounts(),
            )
        )
    return claims, copies


def build_reduce_context(base: FrozenContext, digests: list[DigestInput]) -> FrozenContext:
    budget_chars = chars_for_tokens(context_budget(get_settings().ai_max_input_tokens))
    transformer = Transformer(Pseudonymizer(enabled=False))
    claims: list[_Candidate] = []
    copies: list[_Candidate] = []
    for digest in digests:
        c, k = _digest_candidates(digest, transformer)
        claims += c
        copies += k
    items = list(base.items)
    refs = list(base.refs)
    size = len(canonical({"version": base.version, "task": base.task.value, "items": []}))
    size += sum(len(item_json(i)) for i in items) + max(len(items) - 1, 0)
    included: Counter[RefKind] = Counter()
    candidates: Counter[RefKind] = Counter()
    stripped = dict(base.stats.stripped)
    truncated_fields = dict(base.stats.truncated_fields)
    full = False
    for candidate in [*claims, *copies]:
        kind = candidate.item.kind
        candidates[kind] += 1
        if full:
            continue
        added = len(item_json(candidate.item)) + (1 if items else 0)
        if size + added > budget_chars:
            full = True
            continue
        size += added
        items.append(candidate.item)
        refs.append(candidate.ref)
        included[kind] += 1
        for name, n in candidate.counts.stripped.as_dict().items():
            if n:
                stripped[name] = stripped.get(name, 0) + n
        if candidate.counts.truncated:
            truncated_fields[kind] = truncated_fields.get(kind, 0) + candidate.counts.truncated

    per_kind = dict(base.stats.per_kind)
    omitted = base.stats.omitted
    for kind, total in candidates.items():
        previous = per_kind.get(kind, KindStats(included=0, total=0))
        per_kind[kind] = KindStats(
            included=previous.included + included[kind], total=previous.total + total
        )
        omitted += total - included[kind]
    text = canonical(
        {
            "version": CONTEXT_VERSION,
            "task": base.task.value,
            "items": [i.model_dump(mode="json") for i in items],
        }
    )
    tree_map: dict[str, str] = {}
    for digest in digests:
        tree_map.update(digest.context.pseudonym_map)
    tree_map.update(base.pseudonym_map)
    pseudonym_map = {name: tree_map[name] for name in used_pseudonyms(text) if name in tree_map}
    stats = ContextStats(
        per_kind={k: per_kind[k] for k in RefKind if k in per_kind},
        omitted=omitted,
        est_tokens=estimate_tokens(text),
        truncated=bool(base.stats.truncated or omitted > base.stats.omitted or truncated_fields),
        truncated_fields={k: truncated_fields[k] for k in RefKind if truncated_fields.get(k)},
        dropped_keys=base.stats.dropped_keys,
        pseudonymized=category_counts(pseudonym_map),
        neutralized=base.stats.neutralized,
        stripped=stripped,
        jobs_omitted=base.stats.jobs_omitted,
    )
    return FrozenContext(
        task=base.task,
        scope=base.scope,
        items=tuple(items),
        refs=tuple(refs),
        stats=stats,
        pseudonym_map=pseudonym_map,
    )
