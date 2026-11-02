"""API REST de l'analyseur. Lancement : uvicorn qrguard.api:app"""

import io
import os

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, UploadFile
from PIL import Image, UnidentifiedImageError
from pydantic import BaseModel, Field

from qrguard import __version__
from qrguard.analyzer import analyze_content, analyze_qr
from qrguard.extractor import extract_from_image, extract_from_pdf_bytes

load_dotenv()

MAX_CONTENU_TEXTE = 8192  # un QR code contient au plus ~7 000 caractères
MAX_PIXELS = 50_000_000  # protège contre les images "bombes de décompression"
TAILLE_BLOC = 1024 * 1024

app = FastAPI(title="QR Phishing Detector", version=__version__)


class ContentRequest(BaseModel):
    content: str = Field(min_length=1, max_length=MAX_CONTENU_TEXTE)


def _lire_avec_limite(fichier: UploadFile) -> bytes:
    limite = int(os.getenv("MAX_UPLOAD_MB", "10")) * 1024 * 1024
    contenu = bytearray()
    while bloc := fichier.file.read(TAILLE_BLOC):
        contenu += bloc
        if len(contenu) > limite:
            raise HTTPException(413, f"Fichier trop volumineux (limite : {limite // 1048576} Mo).")
    return bytes(contenu)


def _extraire(contenu: bytes):
    if contenu.startswith(b"%PDF"):
        try:
            return extract_from_pdf_bytes(contenu)
        except ImportError as erreur:
            raise HTTPException(415, str(erreur)) from erreur
        except Exception as erreur:  # pymupdf lève plusieurs types sur un PDF corrompu
            raise HTTPException(400, "PDF illisible.") from erreur
    try:
        with Image.open(io.BytesIO(contenu)) as image:
            if image.width * image.height > MAX_PIXELS:
                raise HTTPException(413, "Image trop grande.")
            return extract_from_image(image)
    except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError) as erreur:
        raise HTTPException(400, "Le fichier n'est pas une image lisible.") from erreur


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": __version__}


@app.post("/analyze")
def analyze_file(file: UploadFile) -> dict:
    """Analyse tous les QR codes d'une image ou d'un PDF."""
    qrs = _extraire(_lire_avec_limite(file))
    return {"count": len(qrs), "results": [analyze_qr(qr).to_dict() for qr in qrs]}


@app.post("/analyze/content")
def analyze_text(requete: ContentRequest) -> dict:
    """Analyse un contenu déjà décodé."""
    return analyze_content(requete.content).to_dict()
