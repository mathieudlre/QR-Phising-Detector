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

- [x] Mise en place du projet
- [x] Extraction des QR codes (images, photos, PDF)
- [x] Moteur de règles et interface en ligne de commande
- [x] Pipeline de machine learning
- [ ] Entraînement du modèle sur un vrai jeu de données
- [x] Enrichissement par des sources de réputation
- [x] API (FastAPI) et interface web (Streamlit)
- [x] Docker et intégration continue
- [ ] Démo en ligne

## Installation

Prérequis : Python 3.11 ou plus récent.

```bash
git clone https://github.com/mathieudlre/QR-Phising-Detector.git
cd QR-Phising-Detector

python -m venv .venv
source .venv/bin/activate        # Windows : .venv\Scripts\activate

pip install -e ".[dev]"          # cœur + outils de développement
# pip install -e ".[all]"        # tout : ML, PDF, web, dev

cp .env.example .env             # puis ajoute tes clés API (optionnelles)
```

## Utilisation

### En ligne de commande

```bash
qrguard scan data/samples/01_url.png           # image ou PDF
qrguard check "http://paypal-secure.xyz/login" # contenu déjà décodé
qrguard scan photo.jpg --json                  # sortie JSON
```

Code de sortie : `0` sûr, `1` suspect, `2` malveillant, `3` erreur.

### Verdict

Chaque signal détecté ajoute des points à un score plafonné à 100 : **sûr** en dessous de 30, **suspect** de 30 à 69, **malveillant** à partir de 70. Une source de réputation qui signale le lien suffit à le classer malveillant. Un verdict « sûr » signifie qu'aucun signal n'a été trouvé, pas que le contenu est garanti sans danger.

L'outil repère les liens de phishing et les liens qui téléchargent un exécutable (`.apk`, `.exe`...). Comme il n'ouvre jamais l'URL, il n'analyse pas le fichier lui-même : seules les sources de réputation peuvent confirmer un malware connu.

### Modèle de machine learning (optionnel)

Sans modèle, l'analyse repose sur les règles. Pour en entraîner un, fournis un CSV avec les colonnes `url` et `label` (`phishing`/`benign` ou `1`/`0`), placé dans `data/raw/`, qui n'est pas versionné :

```bash
pip install -e ".[ml]"
qrguard train data/raw/urls.csv
```

Les scores obtenus sur 20 % des données mises de côté sont affichés à la fin de l'entraînement.

### API et interface web

```bash
pip install -e ".[web,pdf]"
uvicorn qrguard.api:app --port 8000
streamlit run app/streamlit_app.py
```

- `POST /analyze` : envoie une image ou un PDF (champ `file`) ;
- `POST /analyze/content` : envoie un contenu décodé (`{"content": "..."}`) ;
- `GET /health` : état du service ; documentation interactive sur `/docs`.

Avec Docker : `docker compose up --build`, puis ouvre http://localhost:8501.

### Sources de réputation

Désactivées par défaut. Renseigne tes clés dans `.env` et passe `ENABLE_EXTERNAL_LOOKUPS=true`. Chaque URL analysée est alors transmise aux services configurés. Ce sont de simples consultations : aucun scan n'est déclenché.

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
script/        génération des QR codes d'exemple
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
