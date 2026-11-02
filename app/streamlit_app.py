"""Interface web. Lancement : streamlit run app/streamlit_app.py (l'API doit tourner)."""

import os

import httpx
import streamlit as st
from dotenv import load_dotenv

load_dotenv()
API_URL = os.getenv("API_URL", "http://localhost:8000")
DELAI_SECONDES = 60

AFFICHAGE = {"sûr": st.success, "suspect": st.warning, "malveillant": st.error}


def afficher(resultat: dict) -> None:
    message = f"**{resultat['verdict'].upper()}** : risque {resultat['score']}/100"
    AFFICHAGE[resultat["verdict"]](message)
    st.write(f"Type de contenu : `{resultat['kind']}`")
    # st.code : le contenu reste du texte brut, jamais un lien cliquable
    st.code(resultat["content"], language=None, wrap_lines=True)
    for finding in resultat["findings"]:
        st.text(f"• {finding['reason']}")  # st.text : pas d'interprétation Markdown
    if resultat["ml_probability"] is not None:
        st.write(f"Modèle ML : {resultat['ml_probability']:.0%} de risque")
    for r in resultat["reputation"]:
        st.write(f"{r['source']} : {r['status']} {r['detail']}")
    if not resultat["findings"]:
        st.caption("Aucun signal détecté, ce qui ne garantit pas que le contenu est sûr.")


def appeler_api(chemin: str, **kwargs) -> dict | None:
    try:
        reponse = httpx.post(f"{API_URL}{chemin}", timeout=DELAI_SECONDES, **kwargs)
    except httpx.HTTPError:
        st.error(f"L'API ne répond pas à l'adresse {API_URL}.")
        return None
    if reponse.status_code != 200:
        st.error(reponse.json().get("detail", "Erreur de l'API."))
        return None
    return reponse.json()


def analyser_fichier(nom: str, contenu: bytes) -> None:
    donnees = appeler_api("/analyze", files={"file": (nom, contenu)})
    if donnees is None:
        return
    if not donnees["count"]:
        st.info("Aucun QR code trouvé dans ce fichier.")
    for resultat in donnees["results"]:
        afficher(resultat)


st.set_page_config(page_title="QR Phishing Detector", page_icon="🔍")
st.title("QR Phishing Detector")
st.write("Vérifie un QR code **avant** de l'ouvrir. Le contenu analysé n'est jamais visité.")

onglet_fichier, onglet_camera, onglet_texte = st.tabs(["Fichier", "Webcam", "Texte"])

with onglet_fichier:
    fichier = st.file_uploader("Image ou PDF", type=["png", "jpg", "jpeg", "webp", "bmp", "pdf"])
    if fichier is not None:
        analyser_fichier(fichier.name, fichier.getvalue())

with onglet_camera:
    if st.toggle("Activer la webcam"):
        photo = st.camera_input("Montre le QR code à la caméra")
        if photo is not None:
            analyser_fichier("webcam.jpg", photo.getvalue())

with onglet_texte:
    with st.form("formulaire_texte"):
        contenu = st.text_input("Contenu décodé (URL, SMSTO:..., texte...)")
        envoye = st.form_submit_button("Analyser")
    if envoye and contenu:
        resultat = appeler_api("/analyze/content", json={"content": contenu})
        if resultat is not None:
            afficher(resultat)
