"""Enrichissement par des sources de réputation externes (extra `web`).

Désactivé par défaut : activer ENABLE_EXTERNAL_LOOKUPS envoie l'URL à ces services tiers.
Toutes ces requêtes sont des consultations : aucune ne demande de visiter l'URL.
"""

import base64
import os
import time
from dataclasses import dataclass

CLEAN = "clean"
SUSPICIOUS = "suspicious"
MALICIOUS = "malicious"
UNKNOWN = "unknown"
ERROR = "error"

VT_SEUIL_MALVEILLANT = 3  # moteurs en accord : un seul moteur est souvent un faux positif

_cache: dict[str, tuple[float, list["Reputation"]]] = {}


@dataclass(frozen=True)
class Reputation:
    """La réponse d'une source de réputation."""

    source: str
    status: str
    detail: str = ""


def _google_safe_browsing(client, url: str, cle: str) -> Reputation:
    reponse = client.post(
        "https://safebrowsing.googleapis.com/v4/threatMatches:find",
        params={"key": cle},
        json={
            "client": {"clientId": "qr-phishing-detector", "clientVersion": "0.1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        },
    )
    reponse.raise_for_status()
    menaces = {m["threatType"] for m in reponse.json().get("matches", [])}
    if menaces:
        return Reputation("Google Safe Browsing", MALICIOUS, ", ".join(sorted(menaces)))
    return Reputation("Google Safe Browsing", CLEAN)


def _virustotal(client, url: str, cle: str) -> Reputation:
    identifiant = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    reponse = client.get(
        f"https://www.virustotal.com/api/v3/urls/{identifiant}",
        headers={"x-apikey": cle},
    )
    if reponse.status_code == 404:
        return Reputation("VirusTotal", UNKNOWN)
    reponse.raise_for_status()
    stats = reponse.json()["data"]["attributes"]["last_analysis_stats"]
    detections = stats.get("malicious", 0)
    detail = f"{detections} moteur(s) sur {sum(stats.values())}"
    if detections >= VT_SEUIL_MALVEILLANT:
        return Reputation("VirusTotal", MALICIOUS, detail)
    if detections or stats.get("suspicious", 0):
        return Reputation("VirusTotal", SUSPICIOUS, detail)
    return Reputation("VirusTotal", CLEAN, detail)


def _urlhaus(client, url: str, cle: str) -> Reputation:
    reponse = client.post(
        "https://urlhaus-api.abuse.ch/v1/url/",
        data={"url": url},
        headers={"Auth-Key": cle},
    )
    reponse.raise_for_status()
    donnees = reponse.json()
    if donnees.get("query_status") == "ok":
        return Reputation("URLhaus", MALICIOUS, str(donnees.get("threat", "malware")))
    return Reputation("URLhaus", UNKNOWN)


def _urlscan(client, url: str, cle: str) -> Reputation:
    entetes = {"API-Key": cle}
    # Recherche seule : soumettre un scan ferait visiter l'URL par urlscan.io
    echappee = url.replace("\\", "\\\\").replace('"', '\\"')
    reponse = client.get(
        "https://urlscan.io/api/v1/search/",
        params={"q": f'task.url:"{echappee}"', "size": 1},
        headers=entetes,
    )
    reponse.raise_for_status()
    resultats = reponse.json().get("results", [])
    if not resultats:
        return Reputation("urlscan.io", UNKNOWN)
    detail = client.get(f"https://urlscan.io/api/v1/result/{resultats[0]['_id']}/", headers=entetes)
    detail.raise_for_status()
    if detail.json().get("verdicts", {}).get("overall", {}).get("malicious"):
        return Reputation("urlscan.io", MALICIOUS)
    return Reputation("urlscan.io", CLEAN)


SOURCES = (
    ("GOOGLE_SAFE_BROWSING_API_KEY", "Google Safe Browsing", _google_safe_browsing),
    ("VIRUSTOTAL_API_KEY", "VirusTotal", _virustotal),
    ("URLHAUS_AUTH_KEY", "URLhaus", _urlhaus),
    ("URLSCAN_API_KEY", "urlscan.io", _urlscan),
)


def lookups_enabled() -> bool:
    """Vrai seulement si l'utilisateur a explicitement activé les appels externes."""
    return os.getenv("ENABLE_EXTERNAL_LOOKUPS", "false").strip().lower() == "true"


def check_reputation(url: str, client=None) -> list[Reputation]:
    """Interroge chaque source configurée. Une source en panne n'interrompt pas l'analyse."""
    if not lookups_enabled():
        return []

    duree_cache = float(os.getenv("CACHE_TTL_HOURS", "24")) * 3600
    en_cache = _cache.get(url)
    if en_cache and time.monotonic() - en_cache[0] < duree_cache:
        return en_cache[1]

    try:
        import httpx
    except ImportError:
        return [Reputation("réputation", ERROR, 'pip install -e ".[web]" requis')]

    actives = [(env, nom, f) for env, nom, f in SOURCES if os.getenv(env)]
    # follow_redirects=False : on ne suit rien, seule l'API du service est contactée
    delai = float(os.getenv("REQUEST_TIMEOUT_SECONDS", "5"))
    proprietaire = client is None
    client = client or httpx.Client(timeout=delai, follow_redirects=False)
    reponses = []
    try:
        for env, nom, fonction in actives:
            try:
                reponses.append(fonction(client, url, os.environ[env]))
            except (httpx.HTTPError, KeyError, ValueError) as erreur:
                # Le type seul : le message httpx peut contenir l'URL de l'API et donc la clé
                reponses.append(Reputation(nom, ERROR, type(erreur).__name__))
    finally:
        if proprietaire:
            client.close()

    # Les erreurs ne sont pas mises en cache : la prochaine analyse retentera ces sources
    if not any(r.status == ERROR for r in reponses):
        _cache[url] = (time.monotonic(), reponses)
    return reponses
