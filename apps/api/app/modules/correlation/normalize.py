"""The correlation key of one observable (M7; frozen signature, phase 4 implements it).

It delegates to M6's `ioc_collections.normalize.normalize_item` (RT8), which runs the M4 TI
normalizer, keeps private values and internal names, and keys the pcap-only types with
`opaque_key`, so `key` is byte-identical to `ti_results.ioc_key` and
`ioc_collection_items.ioc_key`. Never reinvent a normalizer here.
"""


def correlation_key(ioc_type: str, raw: str) -> tuple[str, str, str] | None:
    """`(kind, key, value_norm)`, or None when the type is not indexed or the value does not
    normalize (phase 4)."""
    raise NotImplementedError("correlation.normalize.correlation_key is implemented in M7 phase 4")
