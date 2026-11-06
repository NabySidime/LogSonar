"""
Fraîcheur des images : qui peut corriger une faille « corrigeable » ?

Une faille a un correctif quand Debian, Alpine, Ubuntu… ont publié une version
corrigée du paquet. Encore faut-il pouvoir l'installer :
- serveur, ou image construite ici (étiquettes de docker compose build, ou pas de
  RepoDigests) : oui, mise à jour ou reconstruction de l'image. Avec le stockage
  d'images containerd, une image construite localement a aussi des RepoDigests :
  ils ne suffisent pas à la reconnaître ;
- image d'un éditeur (mailcow, nginx…) dont le registre propose une version plus
  récente pour le même tag : oui, en tirant la nouvelle image ;
- image d'un éditeur déjà à jour : non, seul l'éditeur peut publier une image
  reconstruite. La faille est « en attente de l'éditeur » et ne doit pas peser
  comme une action oubliée.

Le registre est interrogé en lecture seule (requête HEAD sur le manifeste, jeton
anonyme si nécessaire). Une erreur réseau ou un registre privé donne « unknown » :
la faille reste alors comptée comme corrigeable, comme avant.
"""
from __future__ import annotations

import asyncio
import re
from typing import Optional

import httpx

LOCAL, LATEST, OUTDATED, UNKNOWN = "local", "latest", "outdated", "unknown"
# Statuts pour lesquels l'utilisateur peut appliquer lui-même les correctifs
ACTIONABLE = {LOCAL, OUTDATED, UNKNOWN}

DOCKER_HUB = "registry-1.docker.io"
MANIFEST_TYPES = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])
_AUTH_PARAM = re.compile(r'(\w+)="([^"]*)"')


def parse_ref(ref: str) -> Optional[tuple[str, str, str]]:
    """« ghcr.io/mailcow/postfix:3.10 » -> (registre, dépôt, tag). None pour une référence par digest."""
    if not ref or "@" in ref:
        return None
    name, tag = ref, "latest"
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        name, tag = ref.rsplit(":", 1)
    first = name.split("/", 1)[0]
    if "/" in name and ("." in first or ":" in first or first == "localhost"):
        registry, repo = first, name.split("/", 1)[1]
    else:
        registry, repo = DOCKER_HUB, name if "/" in name else f"library/{name}"
    if registry in ("docker.io", "index.docker.io"):
        registry = DOCKER_HUB
    return registry, repo, tag


def local_digests(repo_digests: list[str]) -> set[str]:
    """Digests (sha256:…) sous lesquels l'image a été tirée."""
    return {d.split("@", 1)[1] for d in repo_digests or [] if "@" in d}


async def _token(client: httpx.AsyncClient, challenge: str) -> Optional[str]:
    if not challenge.lower().startswith("bearer "):
        return None
    params = dict(_AUTH_PARAM.findall(challenge))
    realm = params.pop("realm", "")
    if not realm.startswith("https://"):
        return None
    r = await client.get(realm, params=params)
    if r.status_code != 200:
        return None
    data = r.json()
    return data.get("token") or data.get("access_token")


async def remote_digest(client: httpx.AsyncClient, registry: str, repo: str, tag: str) -> Optional[str]:
    """Digest actuel du tag sur le registre, ou None si indisponible."""
    url = f"https://{registry}/v2/{repo}/manifests/{tag}"
    headers = {"Accept": MANIFEST_TYPES}
    r = await client.head(url, headers=headers)
    if r.status_code == 401:
        token = await _token(client, r.headers.get("www-authenticate", ""))
        if not token:
            return None
        r = await client.head(url, headers={**headers, "Authorization": f"Bearer {token}"})
    if r.status_code != 200:
        return None
    return r.headers.get("docker-content-digest")


BUILT_HERE_LABEL = "com.docker.compose.project"  # posé par docker compose build, jamais sur une image tirée


async def image_status(client: httpx.AsyncClient, ref: str, repo_digests: list[str],
                       labels: Optional[dict] = None) -> str:
    digests = local_digests(repo_digests)
    if not digests or BUILT_HERE_LABEL in (labels or {}):
        return LOCAL  # construite sur ce serveur : une reconstruction applique les correctifs
    parsed = parse_ref(ref)
    if parsed is None:
        return UNKNOWN
    try:
        remote = await remote_digest(client, *parsed)
    except (httpx.HTTPError, ValueError):
        return UNKNOWN
    if not remote:
        return UNKNOWN
    return LATEST if remote in digests else OUTDATED


async def statuses(images: dict[str, tuple[str, list[str], dict]]) -> dict[str, str]:
    """{id d'image: (référence, RepoDigests, étiquettes)} -> {id d'image: statut}. Une requête par image."""
    if not images:
        return {}
    sem = asyncio.Semaphore(4)
    async with httpx.AsyncClient(timeout=httpx.Timeout(15.0), follow_redirects=True,
                                 headers={"User-Agent": "LogSonar/2 (+https://github.com/NabySidime/LogSonar)"}) as client:
        async def one(image_id: str, ref: str, repo_digests: list[str], labels: dict) -> tuple[str, str]:
            async with sem:
                return image_id, await image_status(client, ref, repo_digests, labels)
        return dict(await asyncio.gather(*(one(i, r, d, lb) for i, (r, d, lb) in images.items())))
