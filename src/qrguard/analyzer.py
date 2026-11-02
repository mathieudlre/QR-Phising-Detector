"""Combine règles, modèle et réputation pour produire un verdict expliqué."""

import re
from dataclasses import asdict, dataclass, field

from qrguard.enrich import MALICIOUS, SUSPICIOUS, Reputation, check_reputation
from qrguard.extractor import DecodedQR, detect_kind
from qrguard.features import parse_url
from qrguard.model import predict_proba
from qrguard.rules import URL_DANS_TEXTE, Finding, check_content

SAFE = "sûr"
SUSPECT = "suspect"
DANGEROUS = "malveillant"

SEUIL_SUSPECT = 30
SEUIL_MALVEILLANT = 70

ML_SEUIL_FORT = 0.9
ML_SEUIL_MOYEN = 0.7


@dataclass(frozen=True)
class Analysis:
    """Le résultat complet de l'analyse d'un QR code."""

    content: str  # contenu désarmé : affichable sans risque de clic
    kind: str
    verdict: str
    score: int
    findings: list[Finding] = field(default_factory=list)
    ml_probability: float | None = None
    reputation: list[Reputation] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def defang(texte: str) -> str:
    """Désarme un contenu pour qu'il ne soit jamais cliquable (hxxps://exemple[.]com)."""
    texte = re.sub(r"\bhttp", "hxxp", texte, flags=re.IGNORECASE)

    def _desarmer_url(m: re.Match) -> str:
        return m.group(0).replace(".", "[.]")

    return re.sub(r"(?:hxxps?://|www\.)[^\s\"'<>;]+", _desarmer_url, texte, flags=re.IGNORECASE)


def _urls_of(raw: str, kind: str) -> list[str]:
    """Renvoie les URLs à soumettre au modèle et aux sources de réputation."""
    if kind == "url":
        return [raw.strip()]
    if kind == "script":
        return []
    return URL_DANS_TEXTE.findall(raw)


def analyze_content(raw: str, kind: str | None = None) -> Analysis:
    """Analyse le contenu d'un QR code. Le contenu n'est jamais ouvert ni exécuté."""
    kind = kind or detect_kind(raw)
    findings = check_content(raw, kind)
    urls = [parse_url(url).url for url in _urls_of(raw, kind)]

    ml_probability = None
    reputation: list[Reputation] = []
    for url in urls:
        proba = predict_proba(url)
        if proba is not None:
            ml_probability = max(proba, ml_probability or 0.0)
        reputation.extend(check_reputation(url))

    if ml_probability is not None:
        pourcentage = f"{ml_probability:.0%}"
        if ml_probability >= ML_SEUIL_FORT:
            raison = f"Le modèle estime le risque de phishing à {pourcentage}."
            findings.append(Finding("ml_fort", 40, raison))
        elif ml_probability >= ML_SEUIL_MOYEN:
            raison = f"Le modèle estime le risque de phishing à {pourcentage}."
            findings.append(Finding("ml_moyen", 20, raison))

    for r in reputation:
        precision = f" ({r.detail})" if r.detail else ""
        if r.status == MALICIOUS:
            raison = f"{r.source} signale ce lien comme malveillant{precision}."
            findings.append(Finding("reputation_malveillante", 100, raison))
        elif r.status == SUSPICIOUS:
            raison = f"{r.source} signale ce lien comme suspect{precision}."
            findings.append(Finding("reputation_suspecte", 35, raison))

    score = min(sum(f.score for f in findings), 100)
    if score >= SEUIL_MALVEILLANT:
        verdict = DANGEROUS
    elif score >= SEUIL_SUSPECT:
        verdict = SUSPECT
    else:
        verdict = SAFE

    contenu = defang(raw.strip())
    if kind == "url":  # une URL peut ne pas avoir de schéma : tous ses points sont désarmés
        contenu = contenu.replace("[.]", ".").replace(".", "[.]")

    return Analysis(
        content=contenu,
        kind=kind,
        verdict=verdict,
        score=score,
        findings=findings,
        ml_probability=ml_probability,
        reputation=reputation,
    )


def analyze_qr(qr: DecodedQR) -> Analysis:
    """Analyse un QR code déjà extrait d'une image."""
    return analyze_content(qr.raw, qr.kind)
