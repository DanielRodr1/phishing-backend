import re
import time
import requests
import numpy as np
from urllib.parse import urlparse
from datetime import datetime
from bs4 import BeautifulSoup
import whois
from scipy.stats import entropy

# Funciones auxiliares
def contar_digitos(texto):
    return sum(c.isdigit() for c in texto)

def obtener_tld(subdominio):
    return subdominio.split('.')[-1] if '.' in subdominio else ''

def string_entropy(s):
    prob = [s.count(c) / len(s) for c in set(s)]
    return entropy(prob, base=2)

def obtener_google_index(url):
    try:
        parsed = urlparse(url)
        dominio = parsed.hostname
        if dominio is None:
            return 0
        headers = {"API-Key": "01969e7f-04c8-744a-8245-79c2573fe845"}  # ← reemplaza si usas API real
        params = {"q": f"domain:{dominio}", "size": 1}
        response = requests.get("https://urlscan.io/api/v1/search/", params=params, headers=headers)
        if response.status_code == 200:
            data = response.json()
            return int(data.get("total", 0) > 0)
        return 0
    except:
        return 0

def obtener_page_rank(dominio):
    try:
        url = "https://openpagerank.com/api/v1.0/getPageRank"
        headers = {"API-OPR": "088o008o0gsgcw8k0444k8wswo84888cc0ck8kg4"}  # ← reemplaza si usas API real
        params = {"domains[]": dominio}
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()
            return data['response'][0].get("page_rank_integer", -1)
        return -1
    except:
        return -1

def extraer_features(url: str) -> np.ndarray:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or ''
    path = parsed.path or ''

    features = dict()
    features['longest_words_raw'] = max([len(word) for word in re.split(r'\W+', url)]) if url else 0
    features['nb_eq'] = url.count('=')
    features['length_hostname'] = len(hostname)
    features['length_url'] = len(url)

    try:
        dominio_sin_www = hostname[4:] if hostname.startswith("www.") else hostname
        info = whois.whois(dominio_sin_www)
        creation_date = info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        features['domain_age'] = (datetime.now() - creation_date).days if isinstance(creation_date, datetime) else 0
    except:
        features['domain_age'] = 0

    features['nb_slash'] = url.count('/')
    path_words = re.split(r'\W+', path)
    features['longest_word_path'] = max([len(word) for word in path_words]) if path_words else 0
    hints = ['secure', 'account', 'update', 'login', 'verify', 'bank', 'confirm']
    features['phish_hints'] = sum(hint in url.lower() for hint in hints)
    features['nb_dots'] = url.count('.')
    host_words = hostname.split('.') if hostname else []
    features['shortest_word_host'] = min([len(w) for w in host_words]) if host_words else 0
    features['google_index'] = obtener_google_index(url)
    tld = obtener_tld(hostname)
    subdomain = hostname.split('.')[0] if hostname else ''
    features['tld_in_subdomain'] = int(tld in subdomain) if tld else 0
    digits_url = contar_digitos(url)
    features['ratio_digits_url'] = digits_url / len(url) if len(url) > 0 else 0
    features['prefix_suffix'] = int('-' in hostname)
    features['ip'] = int(bool(re.fullmatch(r'(\d{1,3}\.){3}\d{1,3}', hostname)))
    features['nb_qm'] = url.count('?')
    digits_host = contar_digitos(hostname)
    features['ratio_digits_host'] = digits_host / len(hostname) if len(hostname) > 0 else 0
    features['nb_www'] = url.lower().count('www')
    features['page_rank'] = obtener_page_rank(hostname)

    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, "html.parser")
    except:
        soup = BeautifulSoup("", "html.parser")

    title = soup.title.string.strip().lower() if soup.title and soup.title.string else ""
    features['domain_in_title'] = int(hostname in title)
    links = soup.find_all("a", href=True)
    features['nb_hyperlinks'] = len(links)
    ext_links = [a for a in links if a['href'].startswith(("http://", "https://")) and hostname not in a['href']]
    features['ratio_extHyperlinks'] = len(ext_links) / len(links) if links else 0

    time.sleep(5)  # evitar bloqueo por exceso de requests

    # Añadir esta lista al inicio o final del archivo
    orden_columnas = [
        'google_index', 'page_rank', 'domain_age', 'nb_hyperlinks', 'nb_qm', 'domain_in_title',
        'nb_eq', 'length_hostname', 'longest_word_path', 'tld_in_subdomain', 'ratio_digits_host',
        'nb_www', 'ip', 'shortest_word_host', 'ratio_digits_url', 'nb_slash', 'length_url',
        'longest_words_raw', 'prefix_suffix', 'nb_dots', 'phish_hints', 'ratio_extHyperlinks'
    ]

    # Al final de la función extraer_features(url):
    return np.array([features[k] for k in orden_columnas])