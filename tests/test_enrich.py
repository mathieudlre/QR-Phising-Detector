import base64

import pytest

httpx = pytest.importorskip("httpx")

from qrguard import enrich  # noqa: E402
from qrguard.analyzer import DANGEROUS, analyze_content  # noqa: E402

URL = "https://evil.example/login"


@pytest.fixture(autouse=True)
def activer(monkeypatch):
    monkeypatch.setenv("ENABLE_EXTERNAL_LOOKUPS", "true")
    for variable, _, _ in enrich.SOURCES:
        monkeypatch.delenv(variable, raising=False)
    enrich._cache.clear()


def client_factice(gestionnaire):
    return httpx.Client(transport=httpx.MockTransport(gestionnaire))


def test_desactive_par_defaut(monkeypatch):
    monkeypatch.setenv("ENABLE_EXTERNAL_LOOKUPS", "false")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "cle")

    def jamais(_requete):
        raise AssertionError("aucun appel attendu")

    assert enrich.check_reputation(URL, client_factice(jamais)) == []


def test_google_safe_browsing(monkeypatch):
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "cle")
    client = client_factice(
        lambda _r: httpx.Response(200, json={"matches": [{"threatType": "MALWARE"}]})
    )
    assert enrich.check_reputation(URL, client) == [
        enrich.Reputation("Google Safe Browsing", enrich.MALICIOUS, "MALWARE")
    ]


@pytest.mark.parametrize(
    ("malveillants", "attendu"),
    [(0, enrich.CLEAN), (1, enrich.SUSPICIOUS), (3, enrich.MALICIOUS)],
)
def test_virustotal_seuils(monkeypatch, malveillants, attendu):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "cle")

    def gestionnaire(requete):
        identifiant = base64.urlsafe_b64encode(URL.encode()).decode().rstrip("=")
        assert requete.url.path.endswith(identifiant)
        stats = {"malicious": malveillants, "suspicious": 0, "harmless": 60}
        return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": stats}}})

    assert enrich.check_reputation(URL, client_factice(gestionnaire))[0].status == attendu


def test_virustotal_url_inconnue(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "cle")
    client = client_factice(lambda _r: httpx.Response(404))
    assert enrich.check_reputation(URL, client)[0].status == enrich.UNKNOWN


def test_urlhaus(monkeypatch):
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "cle")
    client = client_factice(
        lambda _r: httpx.Response(200, json={"query_status": "ok", "threat": "malware_download"})
    )
    assert enrich.check_reputation(URL, client)[0].status == enrich.MALICIOUS


def test_urlscan_ne_soumet_jamais_de_scan(monkeypatch):
    monkeypatch.setenv("URLSCAN_API_KEY", "cle")

    def gestionnaire(requete):
        assert requete.method == "GET"
        if "search" in requete.url.path:
            return httpx.Response(200, json={"results": [{"_id": "abc"}]})
        return httpx.Response(200, json={"verdicts": {"overall": {"malicious": True}}})

    assert enrich.check_reputation(URL, client_factice(gestionnaire))[0].status == enrich.MALICIOUS


def test_panne_isolee_sans_fuite_de_cle_et_non_cachee(monkeypatch):
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "cle-secrete")

    def panne(requete):
        raise httpx.ConnectError(f"echec {requete.url}")

    resultat = enrich.check_reputation(URL, client_factice(panne))
    assert resultat[0].status == enrich.ERROR
    assert "cle-secrete" not in resultat[0].detail
    assert URL not in enrich._cache


def test_cache(monkeypatch):
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "cle")
    appels = []

    def gestionnaire(requete):
        appels.append(requete)
        return httpx.Response(200, json={"query_status": "no_results"})

    client = client_factice(gestionnaire)
    enrich.check_reputation(URL, client)
    enrich.check_reputation(URL, client)
    assert len(appels) == 1


def test_reputation_malveillante_decide_le_verdict(monkeypatch):
    monkeypatch.setattr(
        "qrguard.analyzer.check_reputation",
        lambda _u: [enrich.Reputation("URLhaus", enrich.MALICIOUS, "malware_download")],
    )
    analyse = analyze_content("https://example.com/menu")
    assert analyse.verdict == DANGEROUS
    assert "URLhaus" in analyse.findings[0].reason
