"""Découpage d'une URL et calcul de ses caractéristiques lexicales. Aucun accès réseau."""

import ipaddress
import math
from collections import Counter
from dataclasses import dataclass
from urllib.parse import urlsplit

import tldextract

# suffix_list_urls vide : on utilise la liste de suffixes embarquée, sans aucun appel réseau
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())

MOTS_SENSIBLES = (
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "confirm",
    "password",
    "banking",
    "payment",
    "paiement",
    "amende",
    "contravention",
    "connexion",
    "wallet",
)

# Ordre figé : le modèle entraîné dépend de cet ordre
FEATURE_NAMES = (
    "longueur_url",
    "longueur_hote",
    "longueur_chemin",
    "longueur_requete",
    "nb_points",
    "nb_tirets",
    "nb_chiffres",
    "nb_arobases",
    "nb_pourcent",
    "nb_parametres",
    "nb_sous_domaines",
    "profondeur_chemin",
    "ratio_chiffres",
    "entropie_hote",
    "est_https",
    "hote_est_ip",
    "a_punycode",
    "port_explicite",
    "nb_mots_sensibles",
)


@dataclass(frozen=True)
class ParsedURL:
    """Une URL découpée en morceaux utiles à l'analyse."""

    url: str
    scheme: str
    host: str
    port: int | None
    userinfo: str
    path: str
    query: str
    subdomain: str
    domain: str
    suffix: str

    @property
    def registered_domain(self) -> str:
        """Le domaine réellement possédé : "paypal.com" dans "login.paypal.com"."""
        return f"{self.domain}.{self.suffix}" if self.suffix else self.domain


def parse_url(url: str) -> ParsedURL:
    """Découpe une URL. Sans schéma, https est supposé, comme le font les téléphones."""
    url = url.strip()
    if "://" not in url:
        url = f"https://{url}"
    try:
        parts = urlsplit(url)
    except ValueError:  # URL volontairement malformée (crochets IPv6 invalides...)
        parts = urlsplit("")
    try:
        port = parts.port
    except ValueError:  # port hors limites : l'URL reste analysable sans lui
        port = None
    host = (parts.hostname or "").lower().rstrip(".")
    userinfo = parts.netloc.rpartition("@")[0] if "@" in parts.netloc else ""
    extrait = _EXTRACT(host)
    return ParsedURL(
        url=url,
        scheme=parts.scheme.lower(),
        host=host,
        port=port,
        userinfo=userinfo,
        path=parts.path,
        query=parts.query,
        subdomain=extrait.subdomain,
        domain=extrait.domain,
        suffix=extrait.suffix,
    )


def host_is_ip(host: str) -> bool:
    """Vrai si l'hôte est une IP, y compris en décimal ou hexa (http://3232235777/)."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    if host.isdigit():
        return True
    return host.startswith("0x") and all(c in "0123456789abcdefx." for c in host)


def entropy(text: str) -> float:
    """Entropie de Shannon : élevée pour les noms générés au hasard ("xk2q9zv7")."""
    if not text:
        return 0.0
    total = len(text)
    return -sum(n / total * math.log2(n / total) for n in Counter(text).values())


def count_sensitive_words(url: str) -> int:
    """Compte les mots typiques du phishing présents dans l'URL."""
    url = url.lower()
    return sum(mot in url for mot in MOTS_SENSIBLES)


def extract_features(url: str) -> list[float]:
    """Transforme une URL en vecteur numérique, dans l'ordre de FEATURE_NAMES."""
    p = parse_url(url)
    chiffres = sum(c.isdigit() for c in p.url)
    return [
        len(p.url),
        len(p.host),
        len(p.path),
        len(p.query),
        p.url.count("."),
        p.url.count("-"),
        chiffres,
        p.url.count("@"),
        p.url.count("%"),
        p.query.count("=") if p.query else 0,
        len(p.subdomain.split(".")) if p.subdomain else 0,
        p.path.count("/"),
        chiffres / len(p.url) if p.url else 0.0,
        entropy(p.host),
        float(p.scheme == "https"),
        float(host_is_ip(p.host)),
        float("xn--" in p.host),
        float(p.port is not None),
        count_sensitive_words(p.url),
    ]
