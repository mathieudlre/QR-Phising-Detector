"""Extraction des QR codes contenus dans une image."""

from dataclasses import dataclass
from pathlib import Path

import zxingcpp
from PIL import Image

@dataclass(frozen=True)
class DecodedQR:
    """Un QR code trouvé dans une image."""

    raw: str  # contenu brut, tel que décodé
    kind: str  # type : "url", "wifi", "sms", "tel"...
    position: tuple[tuple[int, int], ...]  # 4 coins (x, y) dans l'image

    def detect_kind(raw: str) -> str:
        """Renvoie le type de contenu d'un QR code à partir de son texte brut."""
        # TODO : à toi de jouer (voir plus bas)
        return "text"

    def extract_from_image(image: Image.Image) -> list[DecodedQR]:
        """Trouve et décode tous les QR codes d'une image. N'ouvre jamais leur contenu."""
        gris = image.convert("L")
        resultats = zxingcpp.read_barcodes(gris, formats=zxingcpp.BarcodeFormat.QRCode)

        trouves = []
        for r in resultats:
            p = r.position
            coins = tuple(
                (point.x, point.y)
                for point in (p.top_left, p.top_right, p.bottom_right, p.bottom_left)
            )
            trouves.append(DecodedQR(raw=r.text, kind=detect_kind(r.text), position=coins))
        return trouves

    def extract_from_file(chemin: str | Path) -> list[DecodedQR]:
        """Ouvre une image depuis le disque et en extrait les QR codes."""
        with Image.open(chemin) as image:
            return extract_from_image(image)