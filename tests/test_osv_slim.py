"""
Fiches OSV : on ne garde que ce qui sert, sinon les milliers de failles du
noyau (fiches Ubuntu de ~340 Ko) font dépasser la mémoire du conteneur.
"""
from app.vuln.osv import fixed_version, only_packages, severity_of, slim_vuln


def kernel_record() -> dict:
    variant = lambda name: {  # noqa: E731
        "package": {"name": name, "ecosystem": "Ubuntu:22.04:LTS"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.15.0-100.110"}]}],
        "versions": [f"5.15.0-{i}.{i}" for i in range(100)],
        "ecosystem_specific": {"binaries": [{f"{name}-image-{i}": "5.15.0-100.110"} for i in range(50)], "severity": "medium"},
    }
    return {
        "id": "UBUNTU-CVE-2024-0001", "summary": "faille noyau",
        "severity": [{"type": "Ubuntu", "score": "medium"}],
        "affected": [variant("linux")] + [variant(f"linux-aws-{i}") for i in range(135)],
    }


def test_slim_drops_binaries_and_versions():
    slim = slim_vuln(kernel_record())
    aff = slim["affected"][0]
    assert "versions" not in aff
    assert aff["ecosystem_specific"] == {"severity": "medium"}  # la gravité reste


def test_only_packages_keeps_installed_ones():
    v = only_packages(slim_vuln(kernel_record()), {"linux"})
    assert [a["package"]["name"] for a in v["affected"]] == ["linux"]


def test_same_severity_and_fix():
    raw = kernel_record()
    small = only_packages(slim_vuln(raw), {"linux"})
    eco = "Ubuntu:22.04:LTS"
    assert severity_of(small, "linux", eco) == severity_of(raw, "linux", eco) == ("medium", None)
    assert fixed_version(small, "linux", "5.15.0-25.25", eco) == fixed_version(raw, "linux", "5.15.0-25.25", eco) == "5.15.0-100.110"
