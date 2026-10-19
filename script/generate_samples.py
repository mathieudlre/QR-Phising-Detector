"""Génère des QR codes de test bénins dans data/samples/."""

import qrcode
from pathlib import Path

# Chemins construits à partir de l'emplacement de CE fichier,
RACINE = Path(__file__).resolve().parent.parent # __file__ = scripts/generate_samples.py ici
DOSSIER_SORTIE = RACINE / "data" / "samples"

SAMPLES = {
    "01_url.png" : "https://example.com/menu",
    "02_wifi.png" : "WIFI:T:WPA;S:Reseau-Test;P:motdepasse-test;;",
    "03_sms.png" : "SMSTO:+33639980000:Bonjour",
    "04_tel.png" : "tel:+33199000000",
    "05_texte.png" : "QR code de test du projet QR Phishing Detector"
}

def generer(contenu: str, chemin: Path) -> int:
    """Crée un QR code pour `contenu`, l'enregistre dans `chemin` et renvoie sa version."""
    qr = qrcode.QRCode(
        version=None,  # taille choisie automatiquement par make(fit=True)
        error_correction=qrcode.constants.ERROR_CORRECT_M,  # ~15 % récupérable
        box_size=10,  # 1 module = 10 x 10 pixels
        border=4,  # zone de silence de 4 modules
    )
    qr.add_data(contenu)
    qr.make(fit=True)  # calcule la plus petite version qui contient les données
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(chemin)
    return qr.version


def main() -> None:
    DOSSIER_SORTIE.mkdir(parents=True, exist_ok=True)

    for fichier, contenu in SAMPLES.items():
        chemin = DOSSIER_SORTIE / fichier
        version = generer(contenu, chemin)
        print(f"{fichier:<14} version {version:>2}  ({len(contenu)} caractères)")

    print(f"\n{len(SAMPLES)} QR codes générés dans {DOSSIER_SORTIE.relative_to(RACINE)}/")

if __name__ == "__main__":
    main()