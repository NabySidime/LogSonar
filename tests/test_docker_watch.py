"""
Liste des conteneurs : un conteneur aux données incomplètes ne doit pas faire
échouer toute la liste (LogSonar se croirait coupé de Docker).
"""
from app.collectors import docker_watch as D


class FakeApi:
    def __init__(self, raw):
        self.raw = raw

    def containers(self, all=False):
        return self.raw


class FakeClient:
    def __init__(self, raw):
        self.api = FakeApi(raw)


def run_with(monkeypatch, raw):
    monkeypatch.setattr(D.state, "client", lambda: FakeClient(raw))
    return D.list_containers(True)


def test_container_without_ports(monkeypatch):
    # Docker renvoie "Ports": null pour un conteneur sans port publié
    raw = [
        {"Id": "a" * 64, "Names": ["/web"], "State": "running", "Ports": [{"PublicPort": 80, "PrivatePort": 8000}], "Labels": {}},
        {"Id": "b" * 64, "Names": ["/job"], "State": "running", "Ports": None, "Labels": None},
    ]
    out = run_with(monkeypatch, raw)
    assert [c["name"] for c in out] == ["web", "job"]
    assert out[1]["ports"] == [] and out[1]["labels"] == {}


def test_finished_reader_is_alive(monkeypatch):
    # Un flux de logs coupé termine le thread ; is_alive() ne doit pas planter
    # (Thread a sa propre méthode _stop : ne pas la masquer par un attribut).
    class FailingApi:
        def logs(self, *a, **k):
            raise ConnectionError("coupé")

    class FailingClient:
        api = FailingApi()

    monkeypatch.setattr(D.state, "client", lambda: FailingClient())
    reader = D.LogReader("d" * 64, "web", None, lambda *a: None)
    reader.start()
    reader.join(5)
    assert reader.is_alive() is False

    watcher = D.LogWatcher(lambda *a: None)
    watcher.readers[reader.cid] = reader
    monkeypatch.setattr(D.LogReader, "start", lambda self: None)
    watcher.sync([{"id": reader.cid, "name": "web", "state": "running"}])  # relance le lecteur mort
    assert watcher.readers[reader.cid] is not reader


def test_broken_container_is_skipped(monkeypatch):
    raw = [
        {"Names": ["/sans-id"]},  # pas d'Id : ignoré
        {"Id": "c" * 64, "Names": ["/ok"], "State": "running", "Ports": [], "Labels": {}},
    ]
    assert [c["name"] for c in run_with(monkeypatch, raw)] == ["ok"]
