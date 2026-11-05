"""Pseudonymization and the value transforms of the context builder (M5 phase 4)."""

import ipaddress

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from app.modules.ai.context.fields import HostList, RawItem
from app.modules.ai.context.pseudonymize import (
    Pseudonymizer,
    category_counts,
    neutralize,
    used_pseudonyms,
)
from app.modules.ai.context.transform import ItemCounts, Transformer, redact_url
from app.modules.ai.contracts import RefKind


def pz(**kwargs: object) -> Pseudonymizer:
    return Pseudonymizer(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "address",
    [
        "10.1.2.3",
        "172.16.0.9",
        "172.31.255.1",
        "192.168.1.20",
        "100.64.3.4",
        "127.0.0.1",
        "169.254.10.10",
        "::1",
        "fe80::1",
        "fd12:3456::7",
        "::ffff:10.0.0.1",
    ],
)
def test_internal_addresses_are_replaced(address: str) -> None:
    p = pz()
    out = p.text(f"connection from {address} port 445")
    assert address not in out
    assert "INT_IP_1" in out
    assert p.mapping == {"INT_IP_1": address}


@pytest.mark.parametrize("address", ["192.0.2.1", "8.8.8.8", "203.0.113.50", "2001:db8::1"])
def test_public_and_documentation_addresses_stay(address: str) -> None:
    p = pz()
    assert p.text(f"to {address}:443") == f"to {address}:443"
    assert p.mapping == {}


def test_ipv4_mapped_form_shares_the_pseudonym() -> None:
    p = pz()
    assert p.text("10.0.0.1 and ::ffff:10.0.0.1") == "INT_IP_1 and INT_IP_1"


def test_org_cidrs_are_internal_and_garbage_is_ignored() -> None:
    p = pz(internal_cidrs=["203.0.113.0/24", "not a cidr", 7])
    assert p.text("203.0.113.9 and 198.51.100.1") == "INT_IP_1 and 198.51.100.1"


def test_numbering_is_stable_in_first_appearance_order() -> None:
    p = pz()
    out = p.text("10.0.0.2 -> 10.0.0.1 -> 10.0.0.2 / host.corp")
    assert out == "INT_IP_1 -> INT_IP_2 -> INT_IP_1 / INT_HOST_1"
    assert p.mapping == {"INT_IP_1": "10.0.0.2", "INT_IP_2": "10.0.0.1", "INT_HOST_1": "host.corp"}


@pytest.mark.parametrize(
    "name",
    [
        "fileserver.corp",
        "printer.local",
        "nas.lan",
        "db.internal",
        "router.home.arpa",
        "pc1.localdomain",
        "wiki.intranet",
        "x.private",
        "tv.home",
        "1.0.168.192.in-addr.arpa",
    ],
)
def test_special_use_hostnames_are_replaced(name: str) -> None:
    p = pz()
    assert p.text(f"query {name} failed") == "query INT_HOST_1 failed"
    assert p.mapping["INT_HOST_1"] == name


def test_ptr_name_of_an_internal_address_maps_to_the_real_name() -> None:
    p = pz()
    assert p.text("ptr 5.0.0.10.in-addr.arpa") == "ptr INT_HOST_1"
    assert p.mapping["INT_HOST_1"] == "5.0.0.10.in-addr.arpa"


def test_org_suffixes_and_public_names() -> None:
    p = pz(internal_suffixes=[".Acme.Example", ""])
    assert p.text("srv1.acme.example vs example.com") == "INT_HOST_1 vs example.com"


def test_single_label_names_only_in_hostname_fields() -> None:
    p = pz()
    assert p.text("wpad") == "wpad"
    assert p.host_field("wpad") == "INT_HOST_1"
    assert p.host_field("fileserver:445") == "INT_HOST_2:445"
    assert p.host_field("12345") == "12345"
    assert p.host_field("example.com") == "example.com"


@pytest.mark.parametrize(
    ("raw", "user"),
    [
        ("C:\\Users\\alice\\AppData\\Local\\Temp\\x.exe", "alice"),
        ("c:\\users\\Bob Smith\\Desktop", "Bob Smith"),
        ("C:\\Documents and Settings\\carol\\x", "carol"),
        ("/home/dave/.ssh/id_rsa", "dave"),
        ("/Users/erin/Library", "erin"),
        ("C:\\Users\\frank\\source\\repos\\tool\\Release\\tool.pdb", "frank"),
    ],
)
def test_usernames_in_paths(raw: str, user: str) -> None:
    p = pz()
    out = p.text(raw)
    assert user not in out
    assert "USER_1" in out
    assert p.mapping["USER_1"] == user


def test_profile_directories_that_are_not_people_stay() -> None:
    p = pz()
    assert p.text("C:\\Users\\Public\\run.bat") == "C:\\Users\\Public\\run.bat"


def test_internal_email_local_part() -> None:
    p = pz()
    assert p.text("mail jane@corp.internal and ops@example.test") == (
        "mail USER_1@INT_HOST_1 and ops@example.test"
    )
    assert p.mapping == {"USER_1": "jane", "INT_HOST_1": "corp.internal"}
    assert p.text("ask jane@corp.internal.") == "ask USER_1@INT_HOST_1."


def test_disabled_changes_nothing() -> None:
    p = pz(enabled=False)
    assert (
        p.text("10.0.0.1 host.corp C:\\Users\\alice\\x") == "10.0.0.1 host.corp C:\\Users\\alice\\x"
    )
    assert p.host_field("wpad") == "wpad"


def test_snapshot_restore_rolls_back_numbering() -> None:
    p = pz()
    p.text("10.0.0.1")
    snap = p.snapshot()
    p.text("10.0.0.2")
    p.restore(snap)
    assert p.text("10.0.0.3") == "INT_IP_2"


def test_planted_pseudonyms_are_neutralized() -> None:
    text, n = neutralize("INT_IP_7 then user_2, Int_Host_3 and MY_USER_9")
    assert text == "INT-IP-7 then user-2, Int-Host-3 and MY_USER-9"
    assert n == 4
    assert used_pseudonyms(text) == []


def test_used_pseudonyms_and_counts() -> None:
    names = used_pseudonyms('{"a":"INT_IP_1:80","b":"USER_2 INT_IP_1","c":"INT_HOST_3"}')
    assert names == ["INT_IP_1", "USER_2", "INT_HOST_3"]
    assert category_counts(names) == {"host": 1, "ip": 1, "user": 1}


# --- transforms -----------------------------------------------------------------------------


def transform(value: str, *, host: bool = False, p: Pseudonymizer | None = None) -> str:
    t = Transformer(p or pz(), max_chars=10_000)
    out = t.value(value, ItemCounts(), host=host)
    assert isinstance(out, str)
    return out


def test_url_query_values_and_fragments_never_leave() -> None:
    assert redact_url("https://x.example/a?token=s3cret&b=2&flag#frag") == (
        "https://x.example/a?token=…&b=…&…"
    )
    out = transform("GET https://cdn.example.com/p.js?key=abc123#x then 10.0.0.1")
    assert "abc123" not in out and "#x" not in out
    assert out == "GET hxxps[:]//cdn[.]example[.]com/p[.]js?key=… then INT_IP_1"


def test_transform_order_planted_tokens_cannot_collide() -> None:
    p = pz()
    out = transform("INT_IP_1 talks to 10.0.0.5", p=p)
    assert out == "INT-IP-1 talks to INT_IP_1"
    assert p.mapping == {"INT_IP_1": "10.0.0.5"}


def test_truncation_is_counted_and_marked() -> None:
    t = Transformer(pz())
    counts = ItemCounts()
    out = t.value("a" * 300, counts)
    assert out == "a" * 256 + "…[truncated 44]"
    assert counts.truncated == 1


def test_host_list_aggregates_go_through_the_hostname_pipeline() -> None:
    t = Transformer(pz(), max_chars=10_000)
    out = t.value(HostList((("wpad", 3), ("example.com", 1))), ItemCounts())
    assert out == "INT_HOST_1 (3), example[.]com (1)"


def test_non_strings_pass_through() -> None:
    t = Transformer(pz())
    for value in (1, 2.5, True, None):
        assert t.value(value, ItemCounts()) == value


def test_item_fields_use_host_fields() -> None:
    t = Transformer(pz())
    item = RawItem(
        RefKind.RECORD,
        "network_records",
        "r",
        None,
        {"qname": "wpad", "kind": "dns"},
        host_fields=frozenset({"qname"}),
    )
    fields, _ = t.fields(item)
    assert fields == {"kind": "dns", "qname": "INT_HOST_1"}


# --- properties ------------------------------------------------------------------------------

PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
SEPARATORS = st.sampled_from([" ", ", ", "/", "=", "\t", "(", ")", "; ", " -> ", '"'])
WORDS = st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=8)


@st.composite
def private_ip(draw: st.DrawFn) -> str:
    net = draw(st.sampled_from(PRIVATE))
    offset = draw(st.integers(min_value=0, max_value=net.num_addresses - 1))
    address = net.network_address + offset
    if draw(st.booleans()):
        return str(address)
    return f"::ffff:{address}"


@st.composite
def internal_host(draw: st.DrawFn) -> str:
    label = draw(st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=10))
    suffix = draw(st.sampled_from(["corp", "local", "lan", "internal", "acme.example"]))
    return f"h{label}.{suffix}"


@st.composite
def mixed_text(draw: st.DrawFn) -> tuple[str, list[str]]:
    secrets = draw(st.lists(st.one_of(private_ip(), internal_host()), min_size=1, max_size=6))
    words = draw(st.lists(WORDS, max_size=6))
    tokens = draw(st.permutations(secrets + words))
    seps = draw(st.lists(SEPARATORS, min_size=len(tokens), max_size=len(tokens)))
    return "".join(t + s for t, s in zip(tokens, seps, strict=True)), secrets


@settings(max_examples=200, deadline=None)
@given(mixed_text())
def test_no_internal_value_survives(case: tuple[str, list[str]]) -> None:
    text, secrets = case
    p = pz(internal_suffixes=["acme.example"])
    out = transform(text, p=p)
    for secret in secrets:
        assert secret not in out
        bare = secret.removeprefix("::ffff:")
        assert bare not in out.replace("[.]", ".")


@settings(max_examples=100, deadline=None)
@given(mixed_text())
def test_numbering_is_deterministic(case: tuple[str, list[str]]) -> None:
    text, _ = case
    a, b = pz(internal_suffixes=["acme.example"]), pz(internal_suffixes=["acme.example"])
    assert transform(text, p=a) == transform(text, p=b)
    assert a.mapping == b.mapping
    for category in ("INT_IP", "INT_HOST"):
        numbers = [int(n.rsplit("_", 1)[1]) for n in a.mapping if n.startswith(category + "_")]
        assert numbers == list(range(1, len(numbers) + 1))


STRIPPED = (
    [chr(c) for c in range(0x00, 0x20) if c not in (0x09, 0x0A)]
    + [chr(0x7F)]
    + [chr(c) for c in range(0x80, 0xA0)]
    + [chr(c) for c in range(0x200B, 0x2010)]
    + [chr(c) for c in range(0x202A, 0x202F)]
    + [chr(c) for c in range(0x2066, 0x206A)]
    + ["\ufeff"]
    + [chr(c) for c in range(0xE0000, 0xE0080)]
)


@settings(max_examples=200, deadline=None)
@given(st.lists(st.one_of(st.sampled_from(STRIPPED), WORDS), max_size=30))
def test_sanitize_removes_every_listed_code_point(parts: list[str]) -> None:
    counts = ItemCounts()
    out = Transformer(pz(), max_chars=10_000).value("".join(parts), counts)
    assert isinstance(out, str)
    assert not set(out) & set(STRIPPED)
    assert counts.stripped.total == sum(1 for p in parts if p in STRIPPED)


# --- regressions: structural values are not identities ---------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "heuristic:dns_anomaly@1",
        "heuristic:beaconing@12",
        "x@1",
        "a@1.2",
        "pkg@2.0.1",
        "user@fileserver",
    ],
)
def test_not_an_email(value: str) -> None:
    p = pz()
    assert p.text(value) == value
    assert p.mapping == {}


def test_structural_fields_are_never_pseudonymized() -> None:
    t = Transformer(pz(internal_suffixes=["corp"]))
    item = RawItem(
        RefKind.FINDING,
        "analysis_findings",
        "f",
        None,
        {
            "detection_method": "heuristic:dns_anomaly@1",
            "type": "dns_anomaly",
            "severity": "high",
            "title": "Lookups from 10.0.0.5 for jane@corp.internal",
            "attributes.peer": "10.0.0.5",
        },
    )
    fields, _ = t.fields(item)
    assert fields["detection_method"] == "heuristic:dns_anomaly@1"
    assert fields["type"] == "dns_anomaly" and fields["severity"] == "high"
    assert fields["title"] == "Lookups from INT_IP_1 for USER_1@INT_HOST_1"
    assert fields["attributes.peer"] == "INT_IP_1"


def test_structural_registry_covers_known_kinds() -> None:
    from app.modules.ai.context import fields as F

    for kind, names in F.STRUCTURAL.items():
        assert names <= F.ALLOWED[kind], kind
    assert F.is_structural(RefKind.FINDING, "detection_method")
    assert F.is_structural(RefKind.JOB, "count.flows")
    assert not F.is_structural(RefKind.FINDING, "title")
    assert not F.is_structural(RefKind.FLOW, "src")
    assert not F.is_structural(RefKind.FINDING, "attributes.x")


# --- regressions: schemeless queries and attribute roles (security review) -------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (
            "GET /login.php?user=alice&session=abcd1234secret seen",
            "GET /login[.]php?user=…&session=… seen",
        ),
        ("?a=1&b=2#frag", "?a=…&b=…"),
        ("path /x?k=v&flag", "path /x?k=…&…"),
        ("why? because x=1", "why? because x=1"),
    ],
)
def test_schemeless_query_values_never_leave(raw: str, expected: str) -> None:
    assert transform(raw) == expected


def test_uri_and_host_attributes() -> None:
    from app.modules.ai.context import fields as F

    flat, _, _ = F.flatten_attributes(
        {
            "uri": "/login.php?abcd1234secret#frag",
            "http": {"url": "/a?session=s3cr3t"},
            "host": "intranet01",
            "tls": {"sni": "fileserver"},
            "note": "intranet01",
        }
    )
    hosts, urls = F.attribute_roles(flat)
    assert hosts == {"attributes.host", "attributes.tls.sni"}
    assert urls == {"attributes.uri", "attributes.http.url"}
    item = RawItem(
        RefKind.FINDING, "analysis_findings", "f", None, flat, host_fields=hosts, url_fields=urls
    )
    fields, _ = Transformer(pz()).fields(item)
    text = str(fields)
    assert "abcd1234secret" not in text and "s3cr3t" not in text and "frag" not in text
    assert fields["attributes.uri"] == "/login[.]php?…"
    assert fields["attributes.host"] == "INT_HOST_1"
    assert fields["attributes.tls.sni"] == "INT_HOST_2"
    assert fields["attributes.note"] == "intranet01"  # free text: a single word is not a name
