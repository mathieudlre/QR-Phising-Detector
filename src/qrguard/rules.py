"""Moteur de règles : repère les signaux de danger dans le contenu d'un QR code."""

import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from urllib.parse import parse_qs, unquote

from qrguard.features import ParsedURL, count_sensitive_words, host_is_ip, parse_url

RACCOURCISSEURS = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "rebrand.ly",
        "cutt.ly",
        "shorturl.at",
        "tiny.cc",
        "rb.gy",
        "t.ly",
        "qrco.de",
        "s.id",
        "lnkd.in",
    }
)

TLD_A_RISQUE = frozenset(
    {"zip", "mov", "top", "xyz", "click", "link", "icu", "tk", "ml", "ga", "cf", "gq", "buzz"}
)

# Marque -> domaines officiels. Tout autre domaine qui utilise la marque est une imitation.
MARQUES = {
    "paypal": ("paypal.com", "paypal.fr"),
    "google": ("google.com", "google.fr", "googleapis.com", "googleusercontent.com"),
    "microsoft": ("microsoft.com", "microsoftonline.com", "live.com", "office.com"),
    "apple": ("apple.com", "icloud.com"),
    "amazon": ("amazon.com", "amazon.fr", "amazonaws.com"),
    "netflix": ("netflix.com",),
    "facebook": ("facebook.com", "fb.com"),
    "instagram": ("instagram.com",),
    "whatsapp": ("whatsapp.com",),
    "ameli": ("ameli.fr",),
    "impots": ("impots.gouv.fr",),
    "franceconnect": ("franceconnect.gouv.fr",),
    "antai": ("antai.gouv.fr",),
    "laposte": ("laposte.fr", "laposte.net"),
    "colissimo": ("laposte.fr",),
    "chronopost": ("chronopost.fr",),
    "creditagricole": ("credit-agricole.fr",),
    "bnpparibas": ("bnpparibas.com", "mabanque.bnpparibas"),
    "societegenerale": ("societegenerale.fr",),
    "edf": ("edf.fr",),
    "sncf": ("sncf.com", "sncf-connect.com"),
}

# En dessous de cette longueur, une marque se retrouve par hasard dans d'autres mots
# (apple dans pineapple, ameli dans amelie) : on exige alors une correspondance exacte.
LONGUEUR_MARQUE_DISTINCTIVE = 6

EXTENSIONS_DANGEREUSES = frozenset(
    {
        ".apk",
        ".exe",
        ".msi",
        ".bat",
        ".cmd",
        ".scr",
        ".ps1",
        ".vbs",
        ".js",
        ".jar",
        ".dmg",
        ".pkg",
        ".iso",
        ".mobileconfig",
        ".ipa",
    }
)
EXTENSIONS_ARCHIVES = frozenset({".zip", ".rar", ".7z"})

URL_DANS_TEXTE = re.compile(r"(?:https?://|www\.)[^\s\"'<>;]+", re.IGNORECASE)
LONGUEUR_URL_SUSPECTE = 120
SOUS_DOMAINES_SUSPECTS = 3
PORTS_WEB = (80, 443)

# Numéros français surtaxés : 081, 082, 089 et numéros courts SMS à 5 chiffres
NUMERO_SURTAXE = re.compile(r"^(\+33|0033|0)8[129]")
NUMERO_COURT = re.compile(r"^\d{4,6}$")


@dataclass(frozen=True)
class Finding:
    """Un signal détecté, avec son poids dans le score de risque (0 à 100)."""

    code: str
    score: int
    reason: str


def _desarme(domaine: str) -> str:
    """Un domaine cité dans une raison ne doit jamais devenir un lien cliquable."""
    return domaine.replace(".", "[.]")


def _levenshtein(a: str, b: str) -> int:
    """Nombre minimal de caractères à modifier pour passer de `a` à `b`."""
    precedente = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        courante = [i]
        for j, cb in enumerate(b, start=1):
            courante.append(
                min(precedente[j] + 1, courante[-1] + 1, precedente[j - 1] + (ca != cb))
            )
        precedente = courante
    return precedente[-1]


def _normaliser_marque(texte: str) -> str:
    """Retire les séparateurs et annule les substitutions classiques (paypa1 -> paypal)."""
    return texte.replace("-", "").translate(str.maketrans("013457", "oieast"))


def _check_brand(p: ParsedURL) -> list[Finding]:
    """Détecte l'usage d'une marque ailleurs que sur ses domaines officiels."""
    officiels = {d for domaines in MARQUES.values() for d in domaines}
    if p.registered_domain in officiels or p.host in officiels:
        return []

    domaine = p.domain.replace("-", "")
    normalise = _normaliser_marque(p.domain)
    sous_domaine = p.subdomain.replace("-", "").replace(".", " ")
    chemin = (p.path + " " + p.query).lower()
    mots_domaine = p.domain.split("-")
    for marque, domaines in MARQUES.items():
        distinctive = len(marque) >= LONGUEUR_MARQUE_DISTINCTIVE
        if p.domain == marque and len(p.suffix) == 2:
            # amazon.de est sans doute légitime, paypal.ru non : on signale sans condamner
            return [
                Finding(
                    "marque_autre_extension",
                    25,
                    f"« {marque} » avec l'extension .{p.suffix} : le site habituel est "
                    f"{domaines[0]}.",
                )
            ]
        trouve = (
            (marque in domaine or marque in normalise) if distinctive else (marque in mots_domaine)
        )
        if trouve:
            return [
                Finding(
                    "marque_imitee",
                    60,
                    f"Le domaine contient « {marque} » sans être un domaine officiel "
                    f"({domaines[0]}).",
                )
            ]
        if distinctive and _levenshtein(normalise, marque) == 1:
            return [
                Finding(
                    "typosquatting",
                    65,
                    f"Le domaine « {p.domain} » ressemble fortement à « {marque} » "
                    f"({domaines[0]}).",
                )
            ]
        if marque in sous_domaine.split():
            return [
                Finding(
                    "marque_en_sous_domaine",
                    55,
                    f"« {marque} » apparaît en sous-domaine, mais le vrai domaine est "
                    f"{_desarme(p.registered_domain)}.",
                )
            ]
        if distinctive and marque in chemin:
            return [
                Finding(
                    "marque_dans_chemin",
                    25,
                    f"« {marque} » apparaît dans le chemin d'un site tiers "
                    f"({_desarme(p.registered_domain)}).",
                )
            ]
    return []


def check_url(url: str) -> list[Finding]:
    """Applique toutes les règles à une URL, sans jamais l'ouvrir."""
    p = parse_url(url)
    findings: list[Finding] = []

    if p.scheme == "http":
        findings.append(Finding("http", 10, "La connexion n'est pas chiffrée (http)."))
    if not p.host:
        findings.append(Finding("hote_absent", 40, "L'URL ne contient pas de nom de domaine."))
        return findings

    if host_is_ip(p.host):
        findings.append(
            Finding("ip", 45, "L'URL pointe vers une adresse IP au lieu d'un nom de domaine.")
        )
    if p.userinfo:
        findings.append(
            Finding(
                "arobase",
                60,
                f"Le texte avant « @ » est trompeur : la vraie destination est {_desarme(p.host)}.",
            )
        )
    if "xn--" in p.host:
        findings.append(
            Finding("punycode", 50, "Le domaine utilise du punycode, qui peut imiter un vrai nom.")
        )
    elif not p.host.isascii():
        findings.append(
            Finding(
                "unicode",
                50,
                "Le domaine contient des caractères non latins, qui peuvent imiter un vrai nom.",
            )
        )
    if p.registered_domain in RACCOURCISSEURS:
        findings.append(
            Finding(
                "raccourcisseur",
                30,
                f"{p.registered_domain} est un raccourcisseur : il masque la vraie destination.",
            )
        )
    if p.suffix.rpartition(".")[2] in TLD_A_RISQUE:
        findings.append(
            Finding("tld_risque", 20, f"L'extension .{p.suffix} est très utilisée par les fraudes.")
        )
    if p.subdomain.count(".") + 1 >= SOUS_DOMAINES_SUSPECTS and p.subdomain:
        findings.append(Finding("sous_domaines", 20, "L'URL a un nombre anormal de sous-domaines."))
    if p.port is not None and p.port not in PORTS_WEB:
        findings.append(Finding("port", 20, f"L'URL utilise un port inhabituel ({p.port})."))
    if len(p.url) > LONGUEUR_URL_SUSPECTE:
        findings.append(Finding("longueur", 10, "L'URL est anormalement longue."))

    mots = count_sensitive_words(p.path + "?" + p.query + " " + p.subdomain)
    if mots:
        findings.append(
            Finding(
                "mots_sensibles",
                min(10 * mots, 25),
                "L'URL contient des mots typiques du phishing (connexion, paiement...).",
            )
        )

    extension = PurePosixPath(unquote(p.path)).suffix.lower()
    if extension in EXTENSIONS_DANGEREUSES:
        findings.append(
            Finding(
                "telechargement",
                70,
                f"Le lien télécharge directement un fichier exécutable ({extension}) : "
                "risque de malware.",
            )
        )
    elif extension in EXTENSIONS_ARCHIVES:
        findings.append(
            Finding(
                "archive",
                35,
                f"Le lien télécharge une archive ({extension}), qui peut cacher un malware.",
            )
        )

    for valeurs in parse_qs(p.query).values():
        if any(URL_DANS_TEXTE.match(unquote(v)) for v in valeurs):
            findings.append(
                Finding("redirection", 30, "L'URL contient une autre URL : possible redirection.")
            )
            break

    findings.extend(_check_brand(p))
    return findings


def _check_wifi(raw: str) -> list[Finding]:
    champs = dict(re.findall(r"([TSPH]):((?:\\.|[^;])*);", raw[5:], re.IGNORECASE))
    champs = {k.upper(): v for k, v in champs.items()}
    securite = champs.get("T", "").upper()
    findings = []
    if securite in ("", "NOPASS"):
        findings.append(
            Finding("wifi_ouvert", 40, "Ce réseau Wi-Fi n'a pas de mot de passe : trafic exposé.")
        )
    elif securite == "WEP":
        findings.append(Finding("wifi_wep", 40, "Ce réseau utilise WEP, un chiffrement cassé."))
    if champs.get("H", "").lower() == "true":
        findings.append(Finding("wifi_cache", 15, "Ce QR code connecte à un réseau Wi-Fi caché."))
    return findings


def _check_phone(numero: str) -> list[Finding]:
    numero = unquote(numero).strip().replace(" ", "").replace(".", "")
    if any(c in numero for c in "*#"):
        return [
            Finding(
                "code_ussd",
                75,
                "Le numéro contient un code USSD (* ou #), qui peut déclencher une action "
                "sur le téléphone.",
            )
        ]
    if NUMERO_SURTAXE.match(numero):
        return [Finding("numero_surtaxe", 50, "Ce numéro est probablement surtaxé.")]
    if NUMERO_COURT.match(numero):
        return [Finding("numero_court", 40, "Ce numéro court peut être un service payant.")]
    return []


def check_content(raw: str, kind: str) -> list[Finding]:
    """Applique les règles propres au type de contenu du QR code."""
    raw = raw.strip()
    if kind == "url":
        return check_url(raw)
    if kind == "script":
        return [
            Finding(
                "schema_dangereux",
                80,
                f"Le QR code utilise le schéma « {raw.split(':')[0].lower()}: », qui peut "
                "exécuter du code ou lancer une application.",
            )
        ]

    findings: list[Finding] = []
    if kind == "wifi":
        findings.extend(_check_wifi(raw))
    elif kind == "tel":
        findings.extend(_check_phone(raw[4:]))
    elif kind == "sms":
        findings.extend(_check_phone(raw.split(":")[1].split("?")[0] if ":" in raw else ""))
    elif kind == "crypto":
        findings.append(
            Finding(
                "crypto",
                40,
                "Ce QR code prépare un paiement en cryptomonnaie : il est irréversible, "
                "vérifie l'adresse.",
            )
        )
    elif kind == "otp":
        findings.append(
            Finding(
                "otp",
                30,
                "Ce QR code ajoute un compte de double authentification : n'accepte que si "
                "tu en es à l'origine.",
            )
        )

    # Une URL cachée dans un SMS, un e-mail ou un texte est analysée comme les autres
    for url in URL_DANS_TEXTE.findall(raw):
        findings.append(Finding("url_integree", 10, "Le contenu contient un lien."))
        findings.extend(check_url(url))
    return findings
