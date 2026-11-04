"""The generated contracts stay clean (M4 phase 7, frontend report): stable component names
(no module-path names from two enums called `IocType`, no `-Input`/`-Output` splits), an
optional `acknowledge_terms`, and a declared 204 on the key removal."""

from typing import Any

from app.main import create_app

SCHEMA: dict[str, Any] = create_app().openapi()
COMPONENTS: dict[str, Any] = SCHEMA["components"]["schemas"]


def test_component_names_are_plain() -> None:
    odd = [n for n in COMPONENTS if "__" in n or n.endswith(("-Input", "-Output"))]
    assert odd == []


def test_both_ioc_type_enums_have_their_own_names() -> None:
    assert "IocType" not in COMPONENTS
    assert "ip" in COMPONENTS["AnalysisIocType"]["enum"]
    assert "ipv4" in COMPONENTS["TiIocType"]["enum"]
    iocs = SCHEMA["paths"]["/api/v1/orgs/{org_id}/analyses/{job_id}/iocs"]["get"]
    [param] = [p for p in iocs["parameters"] if p["name"] == "type"]
    assert {"$ref": "#/components/schemas/AnalysisIocType"} in param["schema"]["anyOf"]


def test_acknowledge_terms_is_optional() -> None:
    update = COMPONENTS["IntegrationUpdate"]
    assert "acknowledge_terms" not in update.get("required", [])
    # No `default` either: openapi-typescript turns a defaulted property into a required one.
    assert "default" not in update["properties"]["acknowledge_terms"]


def test_key_removal_declares_an_empty_204() -> None:
    delete = SCHEMA["paths"]["/api/v1/orgs/{org_id}/integrations/{provider}/key"]["delete"]
    assert "204" in delete["responses"]
    assert "content" not in delete["responses"]["204"]
    assert "200" not in delete["responses"]
