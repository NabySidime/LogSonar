"""
Anciens noyaux ignorés sur l'hôte, et score fondé sur les failles corrigeables.
"""
from app import score
from app.vuln.inventory import drop_old_kernels, kernel_abi


def pkg(binary, source="linux", version="6.8.0-147.147"):
    return {"name": source, "version": version, "binary": binary}


HOST = [
    pkg("linux-image-6.8.0-147-generic"),
    pkg("linux-modules-6.8.0-147-generic"),
    pkg("linux-image-6.8.0-137-generic", version="6.8.0-137.137"),
    pkg("linux-modules-6.8.0-137-generic", version="6.8.0-137.137"),
    pkg("linux-headers-6.8.0-137", version="6.8.0-137.137"),
    pkg("linux-generic", "linux-meta", "6.8.0.147.147"),          # méta-paquet : gardé
    pkg("linux-firmware", "linux-firmware", "20240318.git3b128b60"),
    pkg("openssl", "openssl", "3.0.13-0ubuntu3.5"),
]


def test_kernel_abi():
    assert kernel_abi("6.8.0-147-generic") == "6.8.0-147"
    assert kernel_abi("") is None


def test_old_kernels_dropped():
    kept, dropped = drop_old_kernels(HOST, "6.8.0-147")
    assert dropped == 3
    assert not any("137" in p["binary"] for p in kept)
    assert {p["binary"] for p in kept} >= {"linux-image-6.8.0-147-generic", "linux-generic", "linux-firmware", "openssl"}


def test_nothing_dropped_if_running_kernel_unknown():
    assert drop_old_kernels(HOST, None) == (HOST, 0)
    assert drop_old_kernels(HOST, "6.8.0-999") == (HOST, 0)  # noyau actif absent des paquets


def _score(summary):
    return score.compute(summary, [], {}, [], {})


def test_unfixable_vulns_weigh_little():
    base = {"vulns_by_severity": {"critical": 237, "high": 1931, "medium": 6264}}
    all_fixable = _score({**base, "fixable_by_severity": {"critical": 237, "high": 1931, "medium": 6264}})
    none_fixable = _score({**base, "fixable_by_severity": {"critical": 0, "high": 0, "medium": 0}})
    assert all_fixable["score"] == 100 - 25 - 15 - 5
    assert none_fixable["score"] == 100 - 5 - 3
    assert any("sans correctif" in p["label"] for p in none_fixable["penalties"])


def test_never_lower_than_before():
    # Assez de failles critiques corrigeables pour le plafond : celles sans
    # correctif n'ajoutent rien (avant : 100 - 25 - 15 - 5 = 55)
    s = _score({"vulns_by_severity": {"critical": 216, "high": 1400, "medium": 1000},
                "fixable_by_severity": {"critical": 153, "high": 817, "medium": 713}})
    assert s["score"] == 55
    assert not any("sans correctif" in p["label"] for p in s["penalties"])


def test_old_scan_summary_counts_everything():
    old = _score({"vulns_by_severity": {"critical": 10, "high": 0, "medium": 0}})
    assert old["score"] == 75
