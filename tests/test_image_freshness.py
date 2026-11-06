"""
Images d'éditeurs déjà à jour : leurs failles « corrigeables » attendent une nouvelle
image de l'éditeur et ne pèsent plus comme une action oubliée.
"""
import asyncio

import httpx
import pytest

from app import score
from app.vuln import freshness as F

LOCAL_DIGEST = "sha256:" + "a" * 64
NEW_DIGEST = "sha256:" + "b" * 64


# ---------------------------------------------------------------------------
# Références d'images
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("ref, expected", [
    ("nginx:1.30-alpine", (F.DOCKER_HUB, "library/nginx", "1.30-alpine")),
    ("redis", (F.DOCKER_HUB, "library/redis", "latest")),
    ("mcuadros/ofelia:latest", (F.DOCKER_HUB, "mcuadros/ofelia", "latest")),
    ("docker.io/certbot/certbot", (F.DOCKER_HUB, "certbot/certbot", "latest")),
    ("ghcr.io/mailcow/postfix:3.10.12-1", ("ghcr.io", "mailcow/postfix", "3.10.12-1")),
    ("registry.local:5000/app/web:2", ("registry.local:5000", "app/web", "2")),
    ("localhost/app", ("localhost", "app", "latest")),
])
def test_parse_ref(ref, expected):
    assert F.parse_ref(ref) == expected


def test_digest_reference_is_not_checked():
    assert F.parse_ref("nginx@sha256:" + "c" * 64) is None


# ---------------------------------------------------------------------------
# Registre (simulé)
# ---------------------------------------------------------------------------
def registry(digest=NEW_DIGEST, needs_token=True, status=200):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.host, request.url.path))
        if request.url.path == "/token":
            assert request.url.params["scope"] == "repository:mailcow/postfix:pull"
            return httpx.Response(200, json={"token": "anonyme"})
        assert request.method == "HEAD"  # jamais de téléchargement de l'image
        assert "manifest" in request.headers["accept"]
        if needs_token and request.headers.get("authorization") != "Bearer anonyme":
            return httpx.Response(401, headers={"www-authenticate":
                'Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:mailcow/postfix:pull"'})
        return httpx.Response(status, headers={"docker-content-digest": digest} if status == 200 else {})

    return httpx.MockTransport(handler), calls


def status_of(transport, ref="ghcr.io/mailcow/postfix:3.10.12-1", repo_digests=None):
    if repo_digests is None:
        repo_digests = [f"ghcr.io/mailcow/postfix@{LOCAL_DIGEST}"]

    async def run():
        async with httpx.AsyncClient(transport=transport) as client:
            return await F.image_status(client, ref, repo_digests)

    return asyncio.run(run())


def test_latest_image_with_anonymous_token():
    transport, calls = registry(digest=LOCAL_DIGEST)
    assert status_of(transport) == F.LATEST
    assert calls[0] == ("HEAD", "ghcr.io", "/v2/mailcow/postfix/manifests/3.10.12-1")


def test_newer_image_on_registry_is_outdated():
    transport, _ = registry(digest=NEW_DIGEST)
    assert status_of(transport) == F.OUTDATED


def test_image_built_here_is_local_without_network():
    transport, calls = registry()
    assert status_of(transport, ref="tikipay-web", repo_digests=[]) == F.LOCAL
    assert calls == []


def test_compose_built_image_with_containerd_digest_is_local():
    # Stockage containerd : une image construite ici a aussi un RepoDigest
    transport, calls = registry()

    async def run():
        async with httpx.AsyncClient(transport=transport) as client:
            return await F.image_status(client, "tikipay-web", [f"tikipay-web@{LOCAL_DIGEST}"],
                                        {"com.docker.compose.project": "tikipay", "com.docker.compose.service": "web"})

    assert asyncio.run(run()) == F.LOCAL
    assert calls == []


def test_registry_error_is_unknown():
    transport, _ = registry(status=404)
    assert status_of(transport) == F.UNKNOWN


def test_network_error_is_unknown():
    def boom(request):
        raise httpx.ConnectError("hors ligne")
    assert status_of(httpx.MockTransport(boom)) == F.UNKNOWN


def test_unknown_and_outdated_stay_actionable():
    assert F.ACTIONABLE == {F.LOCAL, F.OUTDATED, F.UNKNOWN}


# ---------------------------------------------------------------------------
# Score
# ---------------------------------------------------------------------------
def _score(summary):
    return score.compute(summary, [], {}, [])


def test_vendor_wait_weighs_like_unfixable():
    base = {"vulns_by_severity": {"critical": 53, "high": 0, "medium": 0}}
    before = _score({**base, "fixable_by_severity": {"critical": 53, "high": 0, "medium": 0}})
    after = _score({**base, "fixable_by_severity": {"critical": 0, "high": 0, "medium": 0},
                    "vendor_wait_by_severity": {"critical": 53, "high": 0, "medium": 0}})
    assert before["score"] == 75
    assert after["score"] == 95  # plafond des failles qui n'attendent aucune action : 5 points
    assert any("en attente d'une nouvelle image" in p["label"] for p in after["penalties"])
    assert not any("corrigeable" in p["label"] for p in after["penalties"])


def test_vendor_wait_and_unfixable_share_the_same_small_cap():
    s = _score({"vulns_by_severity": {"critical": 100, "high": 0, "medium": 0},
                "fixable_by_severity": {"critical": 0, "high": 0, "medium": 0},
                "vendor_wait_by_severity": {"critical": 60, "high": 0, "medium": 0}})
    assert s["score"] == 95


def test_actionable_fixes_still_weigh_heavily():
    s = _score({"vulns_by_severity": {"critical": 20, "high": 0, "medium": 0},
                "fixable_by_severity": {"critical": 4, "high": 0, "medium": 0},
                "vendor_wait_by_severity": {"critical": 16, "high": 0, "medium": 0}})
    assert s["score"] == 100 - 10 - 4
