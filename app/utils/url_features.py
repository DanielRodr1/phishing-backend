from urllib.parse import urlparse
from datetime import datetime
import pandas as pd
import re
import whois
import time
import requests
import os
from tqdm import tqdm
from scipy.stats import entropy
from bs4 import BeautifulSoup
from itertools import groupby

import requests
import numpy as np
from urllib.parse import urlparse
from datetime import datetime
from bs4 import BeautifulSoup
import whois
from scipy.stats import entropy

def resolver_redireccion(url):
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(url, timeout=8, allow_redirects=True, headers=headers)
        return response.url
    except:
        return url

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
        headers = {"API-Key": "01969e7f-04c8-744a-8245-79c2573fe845"}
        params = {"q": f"domain:{dominio}", "size": 1}
        response = requests.get("https://urlscan.io/api/v1/search/", params=params, headers=headers, timeout=3)
        return int(response.status_code == 200 and response.json().get("total", 0) > 0)
    except:
        return 0

def obtener_page_rank(dominio, api_key="088o008o0gsgcw8k0444k8wswo84888cc0ck8kg4"):
    try:
        url = "https://openpagerank.com/api/v1.0/getPageRank"
        headers = {"API-OPR": api_key}
        params = {"domains[]": dominio}
        response = requests.get(url, headers=headers, params=params, timeout=3)
        if response.status_code == 200:
            return response.json()['response'][0].get("page_rank_integer", -1)
        return -1
    except:
        return -1

def extraer_features(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    # Resolver redirección: muy importante para analizar la URL final real
    url = resolver_redireccion(url)

    parsed = urlparse(url)
    hostname = parsed.hostname or ''
    path = parsed.path or ''

    features = {}

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
        features['whois_registered_domain'] = int(info.domain_name is not None)
    except:
        features['domain_age'] = 0
        features['whois_registered_domain'] = 0

    features['nb_slash'] = url.count('/')
    path_words = re.split(r'\W+', path)
    features['longest_word_path'] = max([len(word) for word in path_words]) if path_words else 0
    features['phish_hints'] = sum(hint in url.lower() for hint in ['secure', 'account', 'update', 'login', 'verify', 'bank', 'confirm'])
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
    features['nb_semicolumn'] = url.count(';')

    tlds_sospechosos = ['.zip', '.review', '.country', '.stream', '.biz', '.tk', '.ml', '.ga', '.cf']
    features['suspecious_tld'] = int(any(tld in hostname for tld in tlds_sospechosos))

    features['abnormal_subdomain'] = int(len(hostname.split('.')) > 3)

    # HTML features
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, "html.parser")
    except:
        soup = BeautifulSoup("", "html.parser")

    title = soup.title.string.strip().lower() if soup.title and soup.title.string else ""
    features['domain_in_title'] = int(hostname in title)
    features['empty_title'] = int(title == '')
    features['domain_with_copyright'] = int('copyright' in soup.get_text().lower())

    forms = soup.find_all("form")
    features['login_form'] = int(any('password' in str(f).lower() for f in forms))
    features['submit_email'] = int(any('mailto:' in (f.get("action") or '').lower() for f in forms))
    features['sfh'] = int(any((f.get("action") in ['', '#', 'about:blank']) for f in forms))

    links = soup.find_all("a", href=True)
    features['nb_hyperlinks'] = len(links)
    ext_links = [a for a in links if a['href'].startswith(("http://", "https://")) and hostname not in a['href']]
    int_links = [a for a in links if hostname in a['href']]
    features['ratio_extHyperlinks'] = len(ext_links) / len(links) if links else 0
    features['ratio_intHyperlinks'] = len(int_links) / len(links) if links else 0
    features['safe_anchor'] = sum(1 for a in links if a['href'].strip() == '#') / len(links) if links else 0

    tags_with_links = soup.find_all(['script', 'meta', 'link'])
    features['links_in_tags'] = sum('href' in tag.attrs or 'src' in tag.attrs for tag in tags_with_links)

    redir_meta = soup.find_all("meta", attrs={"http-equiv": "refresh"})
    features['ratio_extRedirection'] = len(redir_meta) / (len(links) + 1)

    error_links = [tag for tag in soup.find_all(["img", "script"]) if tag.get("src", "").startswith("http") and "404" in tag.get("src", "")]
    features['ratio_extErrors'] = len(error_links) / (len(links) + 1)

    styles = soup.find_all("link", rel="stylesheet")
    features['nb_extCSS'] = sum(1 for s in styles if s.get("href") and hostname not in s['href'])

    favicon = soup.find("link", rel=lambda x: x and "icon" in x.lower())
    favicon_href = favicon.get("href") if favicon else None
    features['external_favicon'] = int(favicon_href is not None and hostname not in favicon_href)

    scripts = soup.find_all("script")
    features['popup_window_size'] = int(any("window.open" in s.get_text() and ("width=" in s.get_text() or "height=" in s.get_text()) for s in scripts))
    features['right_clic'] = int(any("event.button==2" in s.get_text() or "contextmenu" in s.get_text() for s in scripts))
    features['onmouseover'] = int(any("onmouseover" in s.get_text().lower() for s in scripts))

    features['avg_word_path'] = sum(len(w) for w in path_words) / len(path_words) if path_words else 0
    features['avg_word_host'] = sum(len(w) for w in host_words) / len(host_words) if host_words else 0
    features['char_repeat'] = max((len(list(g)) for _, g in groupby(url)), default=0)

    features['iframe'] = int(bool(soup.find("iframe")))

    features['brand_in_subdomain'] = int(any(brand in subdomain for brand in ['paypal', 'bank', 'login', 'secure']))
    features['brand_in_path'] = int(any(brand in path for brand in ['paypal', 'bank', 'login', 'secure']))
    features['domain_in_brand'] = int(hostname in path)

    try:
        alexa_response = requests.get(f"https://data.alexa.com/data?cli=10&url={hostname}", timeout=3)
        features['web_traffic'] = int("REACH" in alexa_response.text)
    except:
        features['web_traffic'] = 0

    # Añadir esta lista al inicio o final del archivo
    orden_columnas = [
        'abnormal_subdomain', 'longest_word_path', 'domain_in_title', 'web_traffic', 'google_index', 'char_repeat',
        'length_url', 'domain_age', 'nb_www', 'ratio_intHyperlinks', 'nb_extCSS', 'nb_eq', 'longest_words_raw',
        'domain_in_brand', 'tld_in_subdomain', 'length_hostname', 'links_in_tags', 'nb_dots', 'avg_word_host',
        'avg_word_path', 'domain_with_copyright', 'ratio_extErrors', 'nb_hyperlinks', 'empty_title', 'page_rank',
        'phish_hints', 'login_form', 'right_clic', 'safe_anchor', 'nb_slash', 'ip', 'external_favicon', 'prefix_suffix',
        'ratio_extHyperlinks', 'onmouseover', 'suspecious_tld', 'nb_qm', 'shortest_word_host', 'iframe', 'ratio_digits_url',
        'ratio_digits_host', 'ratio_extRedirection'
    ]

    for key in orden_columnas:
        if key not in features:
            features[key] = 0

    # Al final de la función extraer_features(url):
    return np.array([features[k] for k in orden_columnas])