import io

import pytest
import qrcode
from PIL import Image

from qrguard.extractor import detect_kind, extract_from_file, extract_from_image


@pytest.mark.parametrize(
    ("fichier", "kind", "contenu"),
    [
        ("01_url.png", "url", "https://example.com/menu"),
        ("02_wifi.png", "wifi", "WIFI:T:WPA;S:Reseau-Test;P:motdepasse-test;;"),
        ("03_sms.png", "sms", "SMSTO:+33639980000:Bonjour"),
        ("04_tel.png", "tel", "tel:+33199000000"),
        ("05_texte.png", "text", "QR code de test du projet QR Phishing Detector"),
    ],
)
def test_extrait_les_echantillons(samples, fichier, kind, contenu):
    resultats = extract_from_file(samples / fichier)
    assert [(r.kind, r.raw) for r in resultats] == [(kind, contenu)]
    assert len(resultats[0].position) == 4


@pytest.mark.parametrize(
    ("contenu", "kind"),
    [
        ("HTTPS://EXEMPLE.COM", "url"),
        ("www.exemple.com", "url"),
        ("exemple.com/page", "url"),
        ("bitcoin:bc1qxyz", "crypto"),
        ("otpauth://totp/x", "otp"),
        ("javascript:alert(1)", "script"),
        ("data:text/html,<script>", "script"),
        ("data: un simple texte", "text"),
        ("Bonjour tout le monde", "text"),
    ],
)
def test_detect_kind(contenu, kind):
    assert detect_kind(contenu) == kind


def test_image_sans_qr():
    assert extract_from_image(Image.new("RGB", (200, 200), "white")) == []


def test_plusieurs_qr_dans_une_image():
    a = qrcode.make("https://a.example.com").get_image().convert("RGB")
    b = qrcode.make("https://b.example.com").get_image().convert("RGB")
    planche = Image.new("RGB", (a.width + b.width, max(a.height, b.height)), "white")
    planche.paste(a, (0, 0))
    planche.paste(b, (a.width, 0))
    assert {r.raw for r in extract_from_image(planche)} == {
        "https://a.example.com",
        "https://b.example.com",
    }


def test_extrait_depuis_un_pdf(tmp_path):
    pytest.importorskip("pymupdf")
    tampon = io.BytesIO()
    qrcode.make("https://pdf.example.com").get_image().convert("RGB").save(tampon, "PDF")
    chemin = tmp_path / "document.pdf"
    chemin.write_bytes(tampon.getvalue())
    assert [r.raw for r in extract_from_file(chemin)] == ["https://pdf.example.com"]
