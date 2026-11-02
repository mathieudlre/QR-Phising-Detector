"""Interface en ligne de commande : qrguard scan | check | train."""

import argparse
import json
import sys

from dotenv import load_dotenv
from PIL import UnidentifiedImageError

from qrguard.analyzer import DANGEROUS, SUSPECT, Analysis, analyze_content, analyze_qr
from qrguard.extractor import extract_from_file
from qrguard.model import DEFAULT_MODEL_PATH, load_dataset, train

CODE_SUSPECT = 1
CODE_MALVEILLANT = 2
CODE_ERREUR = 3


def _afficher(analyse: Analysis) -> None:
    print(f"Verdict : {analyse.verdict.upper()} (risque {analyse.score}/100)")
    print(f"Type    : {analyse.kind}")
    print(f"Contenu : {analyse.content}")
    for finding in analyse.findings:
        print(f"  - {finding.reason}")
    if analyse.ml_probability is not None:
        print(f"  Modèle ML : {analyse.ml_probability:.0%} de risque")
    for r in analyse.reputation:
        print(f"  {r.source} : {r.status} {r.detail}".rstrip())
    if not analyse.findings:
        print("  Aucun signal détecté (cela ne garantit pas que le contenu est sûr).")


def _code_sortie(analyses: list[Analysis]) -> int:
    """Permet d'utiliser l'outil dans un script : 0 sûr, 1 suspect, 2 malveillant."""
    verdicts = {a.verdict for a in analyses}
    if DANGEROUS in verdicts:
        return CODE_MALVEILLANT
    if SUSPECT in verdicts:
        return CODE_SUSPECT
    return 0


def _rendre(analyses: list[Analysis], en_json: bool) -> int:
    if en_json:
        print(json.dumps([a.to_dict() for a in analyses], ensure_ascii=False, indent=2))
    else:
        for i, analyse in enumerate(analyses):
            if i:
                print()
            _afficher(analyse)
    return _code_sortie(analyses)


def _cmd_scan(args: argparse.Namespace) -> int:
    try:
        qrs = extract_from_file(args.image)
    except (OSError, UnidentifiedImageError, ImportError, RuntimeError, ValueError) as erreur:
        print(f"Erreur : impossible de lire {args.image} : {erreur}", file=sys.stderr)
        return CODE_ERREUR
    if not qrs:
        print(f"Aucun QR code trouvé dans {args.image}.", file=sys.stderr)
        return CODE_ERREUR
    return _rendre([analyze_qr(qr) for qr in qrs], args.json)


def _cmd_check(args: argparse.Namespace) -> int:
    return _rendre([analyze_content(args.contenu)], args.json)


def _cmd_train(args: argparse.Namespace) -> int:
    try:
        urls, labels = load_dataset(args.csv)
        scores = train(urls, labels, args.sortie)
    except ImportError:
        print('Erreur : installe les dépendances ML : pip install -e ".[ml]"', file=sys.stderr)
        return CODE_ERREUR
    except (OSError, KeyError, ValueError) as erreur:
        print(f"Erreur : CSV inutilisable (colonnes url,label) : {erreur}", file=sys.stderr)
        return CODE_ERREUR
    print(json.dumps(scores, indent=2))
    print(f"Modèle enregistré dans {args.sortie}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qrguard", description="Détecte le phishing dans les QR codes, sans les ouvrir."
    )
    commandes = parser.add_subparsers(dest="commande", required=True)

    scan = commandes.add_parser("scan", help="analyse une image ou un PDF")
    scan.add_argument("image")
    scan.add_argument("--json", action="store_true", help="sortie au format JSON")
    scan.set_defaults(fonction=_cmd_scan)

    check = commandes.add_parser("check", help="analyse un contenu déjà décodé (URL, texte...)")
    check.add_argument("contenu")
    check.add_argument("--json", action="store_true", help="sortie au format JSON")
    check.set_defaults(fonction=_cmd_check)

    entrainer = commandes.add_parser("train", help="entraîne le modèle sur un CSV (url,label)")
    entrainer.add_argument("csv")
    entrainer.add_argument("--sortie", default=str(DEFAULT_MODEL_PATH))
    entrainer.set_defaults(fonction=_cmd_train)
    return parser


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    # La console Windows n'accepte pas toujours les accents par défaut
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    args = build_parser().parse_args(argv)
    return args.fonction(args)


if __name__ == "__main__":
    sys.exit(main())
