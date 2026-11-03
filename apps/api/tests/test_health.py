from httpx import ASGITransport, AsyncClient

from app.main import app


async def test_health_reports_all_dependencies_ok() -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json() == {"db": "ok", "redis": "ok", "minio": "ok"}
