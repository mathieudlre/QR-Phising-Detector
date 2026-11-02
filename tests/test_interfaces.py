import io
import json

import pytest
import qrcode

from qrguard.cli import main


def test_cli_scan(samples, capsys):
    assert main(["scan", str(samples / "01_url.png")]) == 0
    assert "hxxps://example[.]com/menu" in capsys.readouterr().out


def test_cli_codes_de_sortie(capsys):
    assert main(["check", "https://example.com/menu"]) == 0
    assert main(["check", "bitcoin:bc1qxyz"]) == 1
    assert main(["check", "javascript:alert(1)"]) == 2
    capsys.readouterr()


def test_cli_json(capsys):
    main(["check", "javascript:alert(1)", "--json"])
    assert json.loads(capsys.readouterr().out)[0]["verdict"] == "malveillant"


def test_cli_fichier_absent_ou_invalide(tmp_path, capsys):
    assert main(["scan", str(tmp_path / "absent.png")]) == 3
    faux = tmp_path / "faux.png"
    faux.write_text("pas une image")
    assert main(["scan", str(faux)]) == 3
    capsys.readouterr()


def test_cli_image_sans_qr(tmp_path, capsys):
    from PIL import Image

    vide = tmp_path / "vide.png"
    Image.new("RGB", (50, 50), "white").save(vide)
    assert main(["scan", str(vide)]) == 3
    capsys.readouterr()


@pytest.fixture
def client():
    pytest.importorskip("fastapi")
    pytest.importorskip("multipart")
    from fastapi.testclient import TestClient

    from qrguard.api import app

    return TestClient(app)


def test_api_health(client):
    assert client.get("/health").json()["status"] == "ok"


def test_api_image(client, samples):
    contenu = (samples / "01_url.png").read_bytes()
    reponse = client.post("/analyze", files={"file": ("a.png", contenu)})
    assert reponse.status_code == 200
    assert reponse.json()["count"] == 1
    assert reponse.json()["results"][0]["verdict"] == "sûr"


def test_api_pdf(client):
    pytest.importorskip("pymupdf")
    tampon = io.BytesIO()
    qrcode.make("javascript:alert(1)").get_image().convert("RGB").save(tampon, "PDF")
    reponse = client.post("/analyze", files={"file": ("a.pdf", tampon.getvalue())})
    assert reponse.json()["results"][0]["verdict"] == "malveillant"


@pytest.mark.parametrize("contenu", [b"pas une image", b"%PDF-corrompu"])
def test_api_fichier_invalide(client, contenu):
    assert client.post("/analyze", files={"file": ("x", contenu)}).status_code == 400


def test_api_fichier_trop_gros(client, samples, monkeypatch):
    monkeypatch.setenv("MAX_UPLOAD_MB", "0")
    contenu = (samples / "01_url.png").read_bytes()
    assert client.post("/analyze", files={"file": ("a.png", contenu)}).status_code == 413


def test_api_contenu(client):
    reponse = client.post("/analyze/content", json={"content": "https://example.com/app.apk"})
    assert reponse.json()["verdict"] == "malveillant"
    assert client.post("/analyze/content", json={"content": ""}).status_code == 422
