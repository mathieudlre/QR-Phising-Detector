import pytest

pytest.importorskip("sklearn")
pytest.importorskip("joblib")

from qrguard.analyzer import analyze_content  # noqa: E402
from qrguard.cli import main  # noqa: E402
from qrguard.model import (  # noqa: E402
    canonicalize,
    deduplicate_hosts,
    load_dataset,
    predict_proba,
    train,
)


def jeu_factice(n=150):
    """Données synthétiques : elles vérifient le pipeline, pas la qualité du modèle."""
    urls, labels = [], []
    for i in range(n):
        urls.append(f"https://site{i}.example.com/page/{i}")
        labels.append(0)
        urls.append(f"http://login-verify{i}.secure-account.example.xyz/update/{i}?id={i}%20")
        labels.append(1)
    return urls, labels


def test_canonicalize_ne_garde_que_l_hote():
    assert canonicalize("http://www.Exemple.com/a/b?c=1") == "https://exemple.com"


def test_deduplication_retire_doublons_et_conflits():
    urls = ["https://a.com/1", "http://www.a.com/2", "https://b.com", "https://b.com/x"]
    assert deduplicate_hosts(urls, [1, 1, 0, 1]) == (["https://a.com"], [1])


def test_le_chemin_ne_change_pas_la_prediction(tmp_path, monkeypatch):
    chemin = tmp_path / "modele.joblib"
    train(*jeu_factice(), chemin)
    monkeypatch.setenv("MODEL_PATH", str(chemin))
    assert predict_proba("https://site7.example.com") == predict_proba(
        "http://site7.example.com/un/long/chemin?x=1"
    )


def test_sans_modele_renvoie_none():
    assert predict_proba("https://example.com") is None


def test_entrainement_puis_prediction(tmp_path, monkeypatch):
    chemin = tmp_path / "modele.joblib"
    scores = train(*jeu_factice(), chemin)
    assert scores["exemples_test"] == 60
    assert chemin.exists()

    monkeypatch.setenv("MODEL_PATH", str(chemin))
    url = "http://login-verify7.secure-account.example.xyz/update/7?id=7%20"
    assert predict_proba(url) > 0.9
    assert predict_proba("https://site7.example.com/page/7") < 0.1
    assert analyze_content(url).ml_probability > 0.9


def test_commande_train_et_labels(tmp_path):
    urls, labels = jeu_factice()
    csv = tmp_path / "urls.csv"
    lignes = ["url,label", "https://ignoree.example.com,inconnu"]
    lignes += [f"{u},{'phishing' if v else 'benign'}" for u, v in zip(urls, labels, strict=True)]
    csv.write_text("\n".join(lignes), encoding="utf-8")

    assert load_dataset(csv) == (urls, labels)
    assert main(["train", str(csv), "--sortie", str(tmp_path / "m.joblib")]) == 0
