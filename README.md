# QR Code Phishing Detector

> Un outil qui scanne un QR code, décode son contenu et indique s'il mène à un site de phishing, **avant** que l'utilisateur ne l'ouvre.

![Statut](https://img.shields.io/badge/statut-en%20développement-orange)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Licence](https://img.shields.io/badge/licence-MIT-green)

## Le problème

Le **quishing** (phishing par QR code) cache une URL malveillante dans une image. L'utilisateur ne voit pas l'adresse avant de scanner, et les filtres anti-phishing qui analysent le texte des e-mails ne la voient pas non plus. Les attaques observées incluent de faux QR codes collés sur des parcmètres et des bornes de recharge, de faux avis de contravention et des e-mails piégés ([Cybermalveillance.gouv.fr](https://www.cybermalveillance.gouv.fr/tous-nos-contenus/actualites/quishing-hameconnage-qr-code)).

## L'objectif

À partir d'une photo, d'une capture d'écran ou de la webcam, l'outil :

1. **extrait** le ou les QR codes de l'image ;
2. **identifie** le type de contenu (URL, Wi-Fi, SMS, téléphone, paiement crypto…) ;
3. **analyse** le contenu avec trois couches complémentaires :
   - des règles de sécurité (punycode, raccourcisseurs, imitation de marques…) ;
   - un modèle de machine learning entraîné sur des URLs étiquetées ;
   - des sources de réputation externes (optionnelles) ;
4. renvoie un **verdict** (sûr, suspect ou malveillant) avec les **raisons** qui l'expliquent.

L'outil **n'ouvre jamais** l'URL analysée.

## Feuille de route

- [ ] Mise en place du projet
- [ ] Extraction des QR codes (images, photos, PDF)
- [ ] Moteur de règles et interface en ligne de commande
- [ ] Données et modèle de machine learning
- [ ] Enrichissement par des sources de réputation
- [ ] API (FastAPI) et interface web (Streamlit)
- [ ] Docker, intégration continue et démo en ligne

## Installation

Prérequis : Python 3.11 ou plus récent.

```bash
git clone https://github.com/VOTRE-PSEUDO/qr-phishing-detector.git
cd qr-phishing-detector

python -m venv .venv
source .venv/bin/activate        # Windows : .venv\Scripts\activate

pip install -e ".[dev]"          # cœur + outils de développement
# pip install -e ".[all]"        # tout : ML, PDF, web, dev

cp .env.example .env             # puis ajoute tes clés API (optionnelles)
```

## Utilisation

En cours de développement.

## Développement

```bash
ruff check .        # analyse du code
ruff format .       # formatage
pytest              # tests
```

## Structure du projet

```text
src/qrguard/   code source
app/           interface Streamlit
notebooks/     exploration et entraînement
data/          données (les données brutes ne sont pas versionnées)
tests/         tests unitaires
```

## Sécurité et éthique

- Les jeux de données contiennent de vraies URLs malveillantes : elles sont manipulées uniquement comme du texte et ne sont jamais ouvertes.
- Les URLs affichées sont « désarmées » (`hxxps://exemple[.]com`).
- Les clés API restent dans un fichier `.env` local, jamais dans le dépôt.
- Projet éducatif et non commercial, conformément aux conditions d'utilisation des API utilisées.

## Licence

Distribué sous licence MIT. Voir [LICENSE](LICENSE).
