"""Convertit le CSV PhiUSIIL (UCI, dataset 967) au format url,label de `qrguard train`.

Attention : dans PhiUSIIL, label 1 = légitime et 0 = phishing, l'inverse de notre convention.
Usage : python script/prepare_phiusiil.py <PhiUSIIL_Phishing_URL_Dataset.csv> data/raw/urls.csv
"""

import csv
import sys

LABELS = {"0": "phishing", "1": "benign"}


def main(entree: str, sortie: str) -> None:
    with (
        open(entree, newline="", encoding="utf-8-sig", errors="replace") as source,
        open(sortie, "w", newline="", encoding="utf-8") as cible,
    ):
        ecrivain = csv.writer(cible)
        ecrivain.writerow(["url", "label"])
        for ligne in csv.DictReader(source):
            ecrivain.writerow([ligne["URL"], LABELS[ligne["label"]]])


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
