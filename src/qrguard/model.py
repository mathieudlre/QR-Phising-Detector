"""Modèle de machine learning : entraînement et prédiction sur les features d'URL.

Nécessite l'extra `ml`. Sans modèle entraîné, l'analyse continue avec les règles seules.
"""

import csv
import os
from functools import lru_cache
from pathlib import Path

from qrguard.features import FEATURE_NAMES, extract_features

DEFAULT_MODEL_PATH = Path("models/url_model.joblib")
LABELS_MALVEILLANTS = {"1", "phishing", "malicious", "bad", "malveillant"}
LABELS_BENINS = {"0", "benign", "legitimate", "good", "safe", "sur"}


def load_dataset(chemin: str | Path) -> tuple[list[str], list[int]]:
    """Lit un CSV avec les colonnes `url` et `label`. Les URLs restent du texte."""
    urls, labels = [], []
    with open(chemin, newline="", encoding="utf-8") as fichier:
        for ligne in csv.DictReader(fichier):
            label = ligne["label"].strip().lower()
            if label in LABELS_MALVEILLANTS:
                labels.append(1)
            elif label in LABELS_BENINS:
                labels.append(0)
            else:
                continue
            urls.append(ligne["url"])
    return urls, labels


def train(urls: list[str], labels: list[int], sortie: str | Path = DEFAULT_MODEL_PATH) -> dict:
    """Entraîne le modèle, l'évalue sur 20 % des données, l'enregistre et renvoie ses scores."""
    import joblib
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score
    from sklearn.model_selection import train_test_split

    X = [extract_features(url) for url in urls]
    X_train, X_test, y_train, y_test = train_test_split(
        X, labels, test_size=0.2, stratify=labels, random_state=42
    )
    modele = HistGradientBoostingClassifier(random_state=42)
    modele.fit(X_train, y_train)

    predictions = modele.predict(X_test)
    probabilites = modele.predict_proba(X_test)[:, 1]
    scores = {
        "exemples_train": len(X_train),
        "exemples_test": len(X_test),
        "precision": float(precision_score(y_test, predictions)),
        "recall": float(recall_score(y_test, predictions)),
        "f1": float(f1_score(y_test, predictions)),
        "roc_auc": float(roc_auc_score(y_test, probabilites)),
    }

    sortie = Path(sortie)
    sortie.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"modele": modele, "features": FEATURE_NAMES, "scores": scores}, sortie)
    return scores


@lru_cache(maxsize=1)
def _load(chemin: str):
    """Charge le modèle une seule fois. joblib exécute du code : n'ouvre que tes propres modèles."""
    if not Path(chemin).exists():
        return None
    try:
        import joblib
    except ImportError:
        return None
    paquet = joblib.load(chemin)  # noqa: S301
    if tuple(paquet["features"]) != FEATURE_NAMES:
        raise ValueError(f"{chemin} a été entraîné avec d'autres features : ré-entraîne-le.")
    return paquet["modele"]


def predict_proba(url: str) -> float | None:
    """Renvoie la probabilité de phishing de l'URL, ou None si aucun modèle n'est disponible."""
    modele = _load(os.getenv("MODEL_PATH", str(DEFAULT_MODEL_PATH)))
    if modele is None:
        return None
    return float(modele.predict_proba([extract_features(url)])[0, 1])
