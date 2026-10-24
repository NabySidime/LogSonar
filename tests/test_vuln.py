from app.vuln.inventory import os_ecosystem, parse_apk_installed, parse_dpkg_status, parse_package_lock, parse_python_dirs
from app.vuln.osv import cvss3_score, fixed_version, severity_of


def test_cvss3_reference_scores():
    assert cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1
    assert cvss3_score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N") == 5.5
    assert cvss3_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0
    assert cvss3_score("not a vector") is None


def test_severity_sources():
    assert severity_of({"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]})[0] == "critical"
    assert severity_of({"database_specific": {"severity": "MODERATE"}})[0] == "medium"
    assert severity_of({"severity": [{"type": "Ubuntu", "score": "negligible"}]})[0] == "low"
    assert severity_of({})[0] == "unknown"


def test_fixed_version_picks_next_fix():
    vuln = {"affected": [{"package": {"name": "django"}, "ranges": [{"events": [
        {"introduced": "4.2"}, {"fixed": "4.2.16"}, {"introduced": "5.0"}, {"fixed": "5.0.9"}]}]}]}
    assert fixed_version(vuln, "Django", "4.2.10") == "4.2.16"
    assert fixed_version(vuln, "django", "5.0.1") == "5.0.9"
    assert fixed_version(vuln, "flask", "1.0") == ""


def test_distro_specific_fix_and_urgency():
    vuln = {
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [
            {"package": {"name": "glibc", "ecosystem": "Debian:13"}, "ranges": [{"events": [{"introduced": "0"}]}],
             "ecosystem_specific": {"urgency": "unimportant"}},
            {"package": {"name": "glibc", "ecosystem": "Debian:14"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.42-1"}]}],
             "ecosystem_specific": {"urgency": "high"}},
        ],
    }
    # Le correctif de Debian 14 ne doit pas être proposé à Debian 13
    assert fixed_version(vuln, "glibc", "2.41-12", "Debian:13") == ""
    assert fixed_version(vuln, "glibc", "2.41-12", "Debian:14") == "2.42-1"
    # Debian juge la faille sans importance pour Debian 13 : on suit son avis
    assert severity_of(vuln, "glibc", "Debian:13")[0] == "low"
    assert severity_of(vuln, "glibc", "Debian:14")[0] == "critical"


def test_os_ecosystems():
    assert os_ecosystem({"ID": "debian", "VERSION_ID": "12"}) == "Debian:12"
    assert os_ecosystem({"ID": "alpine", "VERSION_ID": "3.20.3"}) == "Alpine:v3.20"
    assert os_ecosystem({"ID": "ubuntu", "VERSION_ID": "24.04", "VERSION": "24.04.1 LTS (Noble Numbat)"}) == "Ubuntu:24.04:LTS"
    assert os_ecosystem({"ID": "arch"}) is None


def test_dpkg_uses_source_package():
    text = (
        "Package: libssl3\nStatus: install ok installed\nSource: openssl (3.0.14-1~deb12u2)\nVersion: 3.0.14-1~deb12u2\n\n"
        "Package: bash\nStatus: install ok installed\nVersion: 5.2.15-2+b7\nSource: bash (5.2.15-2)\n\n"
        "Package: removed\nStatus: deinstall ok config-files\nVersion: 1.0\n"
    )
    pkgs = parse_dpkg_status(text)
    assert {(p["name"], p["version"]) for p in pkgs} == {("openssl", "3.0.14-1~deb12u2"), ("bash", "5.2.15-2")}


def test_apk_uses_origin():
    text = "P:libcrypto3\nV:3.3.2-r0\no:openssl\n\nP:musl\nV:1.2.5-r0\no:musl\n"
    assert parse_apk_installed(text) == [
        {"name": "openssl", "version": "3.3.2-r0", "binary": "libcrypto3"},
        {"name": "musl", "version": "1.2.5-r0", "binary": "musl"},
    ]


def test_python_dist_info():
    names = ["Django-4.2.1.dist-info", "django", "PyYAML-6.0.1.dist-info", "zope.interface-6.0-py3.11.egg-info", "README"]
    assert parse_python_dirs(names) == [
        {"name": "django", "version": "4.2.1"},
        {"name": "pyyaml", "version": "6.0.1"},
        {"name": "zope-interface", "version": "6.0"},
    ]


def test_package_lock_v3():
    text = '{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/lodash":{"version":"4.17.20"},"node_modules/a/node_modules/@scope/b":{"version":"1.0.0"}}}'
    assert parse_package_lock(text) == [{"name": "lodash", "version": "4.17.20"}, {"name": "@scope/b", "version": "1.0.0"}]
