import pytest

from qrguard.analyzer import DANGEROUS, SAFE, SUSPECT, analyze_content, defang
from qrguard.features import FEATURE_NAMES, extract_features, host_is_ip, parse_url
from qrguard.rules import check_url


def codes(url):
    return {f.code for f in check_url(url)}


@pytest.mark.parametrize(
    ("url", "code"),
    [
        ("http://example.com", "http"),
        ("https://192.168.1.10/a", "ip"),
        ("http://3232235777/", "ip"),
        ("https://paypal.com@evil.example/", "arobase"),
        ("https://xn--pypal-4ve.com/", "punycode"),
        ("https://bit.ly/abc", "raccourcisseur"),
        ("https://exemple.xyz/", "tld_risque"),
        ("https://a.b.c.example.com/", "sous_domaines"),
        ("https://example.com:8443/", "port"),
        ("https://example.com/connexion/login", "mots_sensibles"),
        ("https://example.com/app.apk", "telechargement"),
        ("https://example.com/facture.zip", "archive"),
        ("https://example.com/r?u=https%3A%2F%2Fevil.example", "redirection"),
        ("https://paypal-secure.com/", "marque_imitee"),
        ("https://paypa1.com/", "typosquatting"),
        ("https://paypal.com.evil.example/", "marque_en_sous_domaine"),
        ("https://sites.example.com/netflix/", "marque_dans_chemin"),
        ("https://paypal.ru/", "marque_autre_extension"),
    ],
)
def test_regles_url(url, code):
    assert code in codes(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/menu",
        "https://www.paypal.com/signin",
        "https://login.microsoftonline.com/",
        "https://pineapple.com/",
        "https://amelie.fr/",
        "https://apply.com/",
    ],
)
def test_sites_legitimes_sans_alerte_marque(url):
    assert not {c for c in codes(url) if "marque" in c or c == "typosquatting"}
    assert analyze_content(url).verdict == SAFE


@pytest.mark.parametrize(
    ("contenu", "verdict"),
    [
        ("https://example.com/menu", SAFE),
        ("http://paypal-secure-login.xyz/verify", DANGEROUS),
        ("https://example.com/update.apk", DANGEROUS),
        ("javascript:alert(1)", DANGEROUS),
        ("tel:%2A%2321%23", DANGEROUS),
        ("tel:*#21#", DANGEROUS),
        ("tel:0899123456", SUSPECT),
        ("SMSTO:36665:STOP", SUSPECT),
        ("WIFI:T:nopass;S:Gratuit;;", SUSPECT),
        ("WIFI:T:WPA;S:Maison;P:secret;;", SAFE),
        ("bitcoin:bc1qxyz?amount=1", SUSPECT),
        ("otpauth://totp/Service?secret=ABC", SUSPECT),
        ("Bonjour tout le monde", SAFE),
        ("Payez ici : http://paypal-secure-login.xyz/verify", DANGEROUS),
        ("SMSTO:+33639980000:Colis bloqué https://bit.ly/abc", SUSPECT),
    ],
)
def test_verdicts(contenu, verdict):
    assert analyze_content(contenu).verdict == verdict


@pytest.mark.parametrize("contenu", ["http://[malforme", "https://", "http://exemple.com:99999/"])
def test_url_malformee_ne_plante_pas(contenu):
    assert analyze_content(contenu).verdict in (SAFE, SUSPECT, DANGEROUS)


def test_defang():
    assert defang("https://evil.example/a.b") == "hxxps://evil[.]example/a[.]b"
    assert defang("Voir www.evil.example ici.") == "Voir www[.]evil[.]example ici."


def test_contenu_affiche_toujours_desarme():
    assert analyze_content("evil.example/page").content == "evil[.]example/page"
    assert "https://" not in analyze_content("https://evil.example").content


@pytest.mark.parametrize(
    "url",
    ["https://paypal.com@www.evil.example/", "https://paypal.www.evil.example/"],
)
def test_raisons_toujours_desarmees(url):
    assert all("evil.example" not in f.reason for f in analyze_content(url).findings)


def test_le_score_est_plafonne():
    assert analyze_content("http://paypal.com@1.2.3.4:8080/login/verify/x.apk").score == 100


def test_domaine_reel_et_features():
    p = parse_url("https://login.paypal.com.evil.co.uk:8443/a?b=1")
    assert p.registered_domain == "evil.co.uk"
    assert p.port == 8443
    assert len(extract_features(p.url)) == len(FEATURE_NAMES)
    assert host_is_ip("::1")
    assert not host_is_ip("example.com")


def test_analyse_sans_reseau(monkeypatch):
    def interdit(*_args, **_kwargs):
        raise AssertionError("connexion réseau interdite")

    monkeypatch.setattr("socket.socket.connect", interdit)
    assert analyze_content("https://evil.example/login").kind == "url"
