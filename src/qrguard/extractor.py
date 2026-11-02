"""Extraction des QR codes contenus dans une image ou un PDF."""

import re
from dataclasses import dataclass
from pathlib import Path

import zxingcpp
from PIL import Image

KIND_PREFIXES = {
    "url": ("http://", "https://"),
    "wifi": ("wifi:",),
    "sms": ("smsto:", "sms:"),
    "tel": ("tel:",),
    "email": ("mailto:", "matmsg:"),
    "contact": ("begin:vcard", "mecard:"),
    "event": ("begin:vevent",),
    "geo": ("geo:",),
    "crypto": ("bitcoin:", "ethereum:", "litecoin:"),
    "otp": ("otpauth://",),
    # Schémas exécutés directement par le navigateur ou le téléphone
    "script": (
        "javascript:",
        "data:text/",
        "data:application/",
        "vbscript:",
        "file:",
        "intent:",
    ),
}

# Les téléphones ouvrent aussi "www.exemple.com" et "exemple.com/page" comme des liens
URL_SANS_SCHEMA = re.compile(r"^(www\.\S+|[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}(:\d+)?/\S*)$")

PDF_ZOOM = 3  # rendu des pages à ~216 DPI : assez net pour les petits QR codes
PDF_MAX_PAGES = 50
PDF_MAX_PIXELS_PAGE = 25_000_000  # une page géante ne doit pas saturer la mémoire


@dataclass(frozen=True)
class DecodedQR:
    """Un QR code trouvé dans une image."""

    raw: str  # contenu brut, tel que décodé
    kind: str  # type : "url", "wifi", "sms", "tel"...
    position: tuple[tuple[int, int], ...]  # 4 coins (x, y) dans l'image


def detect_kind(raw: str) -> str:
    """Renvoie le type de contenu d'un QR code à partir de son texte brut."""
    raw = raw.strip().lower()
    for kind, prefixes in KIND_PREFIXES.items():
        if raw.startswith(prefixes):
            return kind
    if URL_SANS_SCHEMA.match(raw):
        return "url"
    return "text"


def extract_from_image(image: Image.Image) -> list[DecodedQR]:
    """Trouve et décode tous les QR codes d'une image. N'ouvre jamais leur contenu."""
    gris = image.convert("L")
    resultats = zxingcpp.read_barcodes(gris, formats=zxingcpp.BarcodeFormat.QRCode)
    trouves = []
    for r in resultats:
        p = r.position
        coins = tuple(
            (point.x, point.y) for point in (p.top_left, p.top_right, p.bottom_right, p.bottom_left)
        )
        trouves.append(DecodedQR(raw=r.text, kind=detect_kind(r.text), position=coins))
    return trouves


def extract_from_pdf_bytes(contenu: bytes) -> list[DecodedQR]:
    """Extrait les QR codes de toutes les pages d'un PDF (nécessite l'extra `pdf`)."""
    try:
        import pymupdf
    except ImportError as erreur:
        raise ImportError('Lecture des PDF indisponible : pip install -e ".[pdf]"') from erreur

    trouves = []
    with pymupdf.open(stream=contenu, filetype="pdf") as document:
        if document.page_count > PDF_MAX_PAGES:
            raise ValueError(f"PDF trop long (limite : {PDF_MAX_PAGES} pages).")
        for page in document:
            surface = max(page.rect.width * page.rect.height, 1)
            zoom = min(PDF_ZOOM, (PDF_MAX_PIXELS_PAGE / surface) ** 0.5)
            rendu = page.get_pixmap(matrix=pymupdf.Matrix(zoom, zoom), alpha=False)
            image = Image.frombytes("RGB", (rendu.width, rendu.height), rendu.samples)
            trouves.extend(extract_from_image(image))
    return trouves


def extract_from_file(chemin: str | Path) -> list[DecodedQR]:
    """Ouvre une image ou un PDF depuis le disque et en extrait les QR codes."""
    chemin = Path(chemin)
    if chemin.suffix.lower() == ".pdf":
        return extract_from_pdf_bytes(chemin.read_bytes())
    with Image.open(chemin) as image:
        return extract_from_image(image)
