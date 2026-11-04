"""ATT&CK labels route: authenticated, validated, carries the MITRE notice."""

from tests.factories import new_client, register


async def test_labels_and_meta_for_authenticated_users() -> None:
    reg = await register()
    resp = await reg.client.get("/api/v1/attack/techniques", params={"ids": "T1055,t1059.001"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert {label["id"] for label in body["techniques"]} >= {"T1055", "T1059.001"}
    assert "MITRE" in body["meta"]["notice"]


async def test_bad_ids_are_rejected() -> None:
    reg = await register()
    resp = await reg.client.get("/api/v1/attack/techniques", params={"ids": "T1055,<script>"})
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "invalid_attack_ids"


async def test_anonymous_is_refused() -> None:
    resp = await new_client().get("/api/v1/attack/techniques", params={"ids": "T1055"})
    assert resp.status_code == 401
