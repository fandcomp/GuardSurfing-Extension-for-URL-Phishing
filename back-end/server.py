import os
import pickle
import joblib
import numpy as np
from flask import Flask, request, jsonify
from flask_cors import CORS
from FeatureExt import FeatureExtraction
import pandas as pd
import re
from typing import Optional, Tuple, List, Dict
from urllib.parse import urlparse
import json
import os
import requests

try:
    import xgboost as xgb  # optional, used for fast SHAP contributions
except Exception:  # pragma: no cover
    xgb = None

app = Flask(__name__)
CORS(app)

# Resolve paths relative to this file
HERE = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(HERE, 'models')
CANONICAL_SCHEMA = os.path.join(HERE, 'phishing.csv')

MODEL = None
THRESHOLD = 0.5
FEATURE_NAMES = []
USE_LLM = os.environ.get('USE_LLM', '0') in ('1', 'true', 'True')
LLM_MODEL = os.environ.get('LLM_MODEL', 'llama3.1:8b')
OLLAMA_URL = os.environ.get('OLLAMA_URL', 'http://127.0.0.1:11434')
LLM_TIMEOUT = float(os.environ.get('LLM_TIMEOUT', '8'))


def load_feature_names_from_schema(schema_path: str) -> list:
    try:
        cols = pd.read_csv(schema_path, nrows=0).columns.tolist()
        # Expect: Index, <features...>, class
        if cols and cols[0].lower() == 'index' and cols[-1].lower() in ('class', 'label'):
            return cols[1:-1]
        # Fallback: drop Index/label if present
        return [c for c in cols if c.lower() not in ('index', 'class', 'label')]
    except Exception:
        # Known default ordering for FeatureExtraction
        return [
            'UsingIP','LongURL','ShortURL','Symbol@','Redirecting//','PrefixSuffix-','SubDomains','HTTPS','DomainRegLen','Favicon',
            'NonStdPort','HTTPSDomainURL','RequestURL','AnchorURL','LinksInScriptTags','ServerFormHandler','InfoEmail','AbnormalURL',
            'WebsiteForwarding','StatusBarCust','DisableRightClick','UsingPopupWindow','IframeRedirection','AgeofDomain','DNSRecording',
            'WebsiteTraffic','PageRank','GoogleIndex','LinksPointingToPage','StatsReport'
        ]


def try_load_best_model():
    global MODEL, THRESHOLD, FEATURE_NAMES
    try:
        pointer_path = os.path.join(MODELS_DIR, 'best_pointer.joblib')
        ptr = joblib.load(pointer_path)
        model_path = ptr['path'] if isinstance(ptr, dict) else ptr
        blob = joblib.load(model_path)
        MODEL = blob.get('model', None)
        THRESHOLD = float(blob.get('threshold', 0.5))
        FEATURE_NAMES = blob.get('features') or load_feature_names_from_schema(CANONICAL_SCHEMA)
        return True
    except Exception:
        # Fallback to legacy pickle if exists
        try:
            legacy_path = os.path.join(HERE, 'XgClassifierModel.pickle')
            with open(legacy_path, 'rb') as f:
                MODEL = pickle.load(f)
            THRESHOLD = 0.5
            FEATURE_NAMES = load_feature_names_from_schema(CANONICAL_SCHEMA)
            return True
        except Exception:
            return False


_loaded = try_load_best_model()


def get_phish_probability(model, x_vec: np.ndarray) -> float:
    # Returns probability of phishing in [0,1]
    if hasattr(model, 'predict_proba'):
        proba = model.predict_proba(x_vec)[0]
        # If classes_ present, choose phishing class index
        cls = getattr(model, 'classes_', None)
        if cls is not None:
            cls = list(cls)
            if 1 in cls and 0 in cls:
                return float(proba[cls.index(1)])  # XGB trained with 1=phishing
            if -1 in cls:
                return float(proba[cls.index(-1)])  # scikit models trained with -1=phishing
        # Fallback: assume proba of positive class is phishing
        return float(proba[-1])
    # Decision function fallback: map to 0..1 via logistic
    if hasattr(model, 'decision_function'):
        df = float(model.decision_function(x_vec)[0])
        # sigmoid
        return 1.0 / (1.0 + np.exp(-df))
    # Last resort: predict label
    pred = model.predict(x_vec)[0]
    return 1.0 if pred in (1, -1) and pred != 1 else 0.0


def _sigmoid(z: float) -> float:
    try:
        return 1.0 / (1.0 + np.exp(-z))
    except Exception:
        return float('nan')


def explain_prediction(model, x_vec: np.ndarray, feature_names: List[str], feature_values: List[float]) -> Dict:
    """
    Returns per-feature contributions to the decision in log-odds space when possible.
    For XGBoost: uses pred_contribs (SHAP). For LogisticRegression: uses coef_.
    Fallback: uses feature_importances_ heuristics.
    Output keys:
      - method: str
      - base: float (bias term, log-odds if applicable)
      - contributions: list of { name, value, contrib, impact }
      - logit: float (sum base+contribs)
      - probability: float (sigmoid(logit)) if applicable
      - top: top 3 contributors (name, sign, abs contrib)
    """
    n = len(feature_names)
    base = 0.0
    contribs = np.zeros(n, dtype=float)
    method = 'unknown'
    logit = None

    # 1) XGBoost SHAP contributions (fast, exact)
    try:
        if xgb is not None and hasattr(model, 'get_booster'):
            booster = model.get_booster()
            dm = xgb.DMatrix(x_vec, feature_names=feature_names)
            arr = booster.predict(dm, pred_contribs=True)
            # arr shape: (1, n_features+1); last column is bias
            contribs = np.array(arr[0][:-1], dtype=float)
            base = float(arr[0][-1])
            logit = float(base + contribs.sum())
            method = 'xgboost_shap'
    except Exception:
        pass

    # 2) LogisticRegression linear contributions
    if method == 'unknown':
        try:
            coef = getattr(model, 'coef_', None)
            intercept = getattr(model, 'intercept_', None)
            if coef is not None and intercept is not None and coef.shape[0] in (1, 2):
                # Binary classifier: take the phishing class weights
                w = coef[0]
                # If classes_ present and -1 indicates phishing, flip sign
                cls = getattr(model, 'classes_', None)
                if cls is not None and (-1 in cls) and (1 in cls):
                    # Ensure weight corresponds to phishing side
                    # scikit usually uses classes_[1] weights; be conservative
                    pass
                x = x_vec[0]
                contribs = (w * x).astype(float)
                base = float(intercept[0])
                logit = float(base + contribs.sum())
                method = 'logistic'
        except Exception:
            pass

    # 3) Fallback: importance-weighted heuristic
    if method == 'unknown':
        try:
            imps = getattr(model, 'feature_importances_', None)
            if imps is not None and len(imps) == n:
                imps = np.asarray(imps, dtype=float)
                imps = imps / (imps.sum() + 1e-9)
                # Treat value -1 as risk-up, +1 as risk-down, 0 neutral
                val = np.asarray(feature_values, dtype=float)
                sign = np.where(val < 0, 1.0, np.where(val > 0, -1.0, 0.0))
                contribs = imps * sign
                logit = float(contribs.sum())
                method = 'importances_heuristic'
        except Exception:
            pass

    probability = _sigmoid(logit) if logit is not None else None
    # Build contributions list
    rows = []
    for i, name in enumerate(feature_names):
        val = float(feature_values[i]) if i < len(feature_values) else 0.0
        c = float(contribs[i])
        rows.append({
            'name': name,
            'value': val,
            'contrib': c,
            'impact': 'up' if c > 0 else ('down' if c < 0 else 'neutral')
        })
    # Top 3 by absolute contribution
    top_idx = np.argsort(-np.abs(contribs))[:3] if len(contribs) else []
    top = [{ 'name': feature_names[i], 'contrib': float(contribs[i]) } for i in top_idx]
    return {
        'method': method,
        'base': base,
        'logit': logit,
        'probability': probability,
        'contributions': rows,
        'top': top,
    }


def llm_judge_links(page_url: str, items: List[dict]) -> List[dict]:
    """Use local Ollama to judge if links look like ads/malicious redirects by their text/title/context.
    Returns list of { idx, score (0-1), reason } aligned to items order.
    """
    try:
        if not USE_LLM:
            return []
        payload = {
            'model': LLM_MODEL,
            'prompt': (
                'You are a phishing risk auditor. Given a page URL and a set of links with text/title/context, '
                'score each link in [0,1] for risk of phishing or malicious redirection. Also give a one-line reason.\n'
                f'Page: {page_url}\nLinks:\n' +
                '\n'.join([f'[{i}] url={it.get("url","")}, text={it.get("text","")}, title={it.get("title","")}, context={it.get("context","")}' for i,it in enumerate(items)]) +
                '\nRespond as JSON array of objects: {"idx":i, "score":float, "reason":"..."}.'
            ),
            'stream': False,
        }
        r = requests.post(f'{OLLAMA_URL}/api/generate', json=payload, timeout=LLM_TIMEOUT)
        r.raise_for_status()
        data = r.json()
        # Ollama returns { response: "..." }
        txt = data.get('response') or ''
        # Try to parse JSON array from response
        start = txt.find('[')
        end = txt.rfind(']')
        arr = json.loads(txt[start:end+1]) if start != -1 and end != -1 else []
        out = []
        for o in arr:
            try:
                out.append({'idx': int(o.get('idx')), 'score': float(o.get('score', 0.0)), 'reason': str(o.get('reason',''))})
            except Exception:
                continue
        return out
    except Exception:
        return []


def is_punycode_domain(host: str) -> bool:
    try:
        if not host:
            return False
        return any(lbl.startswith('xn--') for lbl in host.split('.'))
    except Exception:
        return False


def sld(host: str) -> str:
    try:
        parts = host.split('.')
        if len(parts) >= 2:
            return parts[-2]
        return host
    except Exception:
        return host or ''


def looks_like_brand(s: str, brand: str) -> bool:
    """Check if string s looks like brand using simple substitutions (0->o, 1->l/i, 3->e, 5->s, 7->t)."""
    if not s or not brand:
        return False
    s0 = s.lower()
    b0 = brand.lower()
    subs = str.maketrans({'0':'o','1':'l','3':'e','5':'s','7':'t','!':'i','$':'s','@':'a'})
    s1 = s0.translate(subs)
    # Direct match after substitutions or small edit distance
    if s1 == b0:
        return True
    # Levenshtein distance <= 1
    if abs(len(s1) - len(b0)) > 1:
        return False
    # simple distance 0/1 check
    mism = 0
    i=j=0
    while i < len(s1) and j < len(b0):
        if s1[i] == b0[j]:
            i+=1; j+=1
        else:
            mism += 1
            if mism > 1:
                return False
            # try skip one in either
            if len(s1) > len(b0):
                i+=1
            elif len(b0) > len(s1):
                j+=1
            else:
                i+=1; j+=1
    if i < len(s1) or j < len(b0):
        mism += 1
    return mism <= 1


BRAND_KEYWORDS = [
    'google','facebook','instagram','twitter','x','paypal','apple','microsoft','amazon','bank',
    'bri','bca','mandiri','bni','dana','ovo','gopay','shopee','tokopedia','bukalapak','tiktok'
]


def classify_category_from_url(u: str) -> Optional[str]:
    try:
        parsed = urlparse(u)
        host = (parsed.netloc or '').lower()
        path = (parsed.path or '').lower()
        combo = host + path
        patterns = [
            ('crypto-scam', r'crypto(aid|doubler|multiplier)|airdrop|claim-?nft|giveaway-?crypto|elon-?musk'),
            ('gift-scam', r'free-?gift|free-?iphone|lucky-?draw|spin-?win|congratulations'),
            ('gaming-freebies', r'free-?robux|free-?uc|free-?diamonds'),
            ('credential-harvest', r'login-?verify|re-?activate|account-?locked|confirm-?password'),
        ]
        for name, rx in patterns:
            if re.search(rx, combo):
                return name
        return None
    except Exception:
        return None


def human_reasons(feature_names: list, feature_values: list, importances: np.ndarray | None, max_items: int = 2):
    # Simple heuristic explanations focusing on features with suspicious values
    phrases = {
        'ShortURL': 'URL menggunakan shortener',
        'LongURL': 'URL sangat panjang',
        'Symbol@': 'URL mengandung simbol @',
        'Redirecting//': 'Redirecting ganda (//) terdeteksi',
        'PrefixSuffix-': 'Tanda - pada domain',
        'SubDomains': 'Subdomain berantai/berlebih',
        'HTTPS': 'Tidak menggunakan HTTPS',
        'UsingIP': 'Menggunakan alamat IP',
        'DomainRegLen': 'Masa registrasi domain pendek',
        'Favicon': 'Favicon tidak konsisten',
        'NonStdPort': 'Menggunakan port non-standar',
        'ServerFormHandler': 'Aksi form mencurigakan',
        'InfoEmail': 'Terdapat email info/mailto',
        'AbnormalURL': 'URL abnormal',
        'WebsiteForwarding': 'Forwarding berantai',
        'StatusBarCust': 'Manipulasi status bar',
        'DisableRightClick': 'Disable klik kanan',
        'UsingPopupWindow': 'Popup mencurigakan',
        'IframeRedirection': 'Iframe/Frame redirection',
        'AgeofDomain': 'Usia domain muda',
        'DNSRecording': 'DNS recording singkat',
        'WebsiteTraffic': 'Traffic sangat rendah',
        'PageRank': 'PageRank rendah',
        'GoogleIndex': 'Tidak terindeks Google',
        'LinksPointingToPage': 'Sedikit link menunjuk ke halaman',
        'StatsReport': 'Match daftar blacklist',
    }
    suspicious = set(['ShortURL','Symbol@','Redirecting//','PrefixSuffix-','SubDomains','UsingIP','NonStdPort','ServerFormHandler','InfoEmail','AbnormalURL','WebsiteForwarding','StatusBarCust','DisableRightClick','UsingPopupWindow','IframeRedirection','StatsReport'])
    items = list(zip(feature_names, feature_values))
    # Score features by importance (if available) and suspicious value
    scores = []
    if importances is None or len(importances) != len(feature_names):
        importances = np.ones(len(feature_names))
    for i, (name, val) in enumerate(items):
        is_bad = (val == -1) or (name == 'HTTPS' and val == -1) or (name in ('LongURL',) and val == -1)
        base = importances[i]
        # Boost suspicious ones
        score = base * (2.0 if (is_bad or name in suspicious) else 1.0)
        scores.append((score, name, val))
    scores.sort(reverse=True)
    reasons = []
    for _, name, val in scores:
        if val == -1 and name in phrases:
            reasons.append(phrases[name])
        elif name == 'HTTPS' and val == -1:
            reasons.append(phrases['HTTPS'])
        if len(reasons) >= max_items:
            break
    return reasons


def compute_fast_features(url: str) -> list[int]:
    # Minimal offline subset (8 fitur pertama), sisanya nol
    try:
        import ipaddress
        try:
            ipaddress.ip_address(url)
            using_ip = -1
        except Exception:
            using_ip = 1
    except Exception:
        using_ip = 1
    L = len(url)
    long_url = 1 if L < 54 else (0 if L <= 75 else -1)
    shortener_re = re.compile(r"bit\.ly|goo\.gl|t\.co|tinyurl|is\.gd|ow\.ly|adf\.ly|j\.mp|rb\.gy|cutt\.ly|lnkd\.in", re.I)
    short_url = -1 if shortener_re.search(url) else 1
    symbol_at = -1 if "@" in url else 1
    redirecting = -1 if url.rfind("//") > 6 else 1
    try:
        from urllib.parse import urlparse
        domain = urlparse(url).netloc
    except Exception:
        domain = ""
    prefix_suffix = -1 if "-" in domain else 1
    dot_count = len(re.findall(r"\.", url))
    subdomains = 1 if dot_count == 1 else (0 if dot_count == 2 else -1)
    scheme = url.split(":", 1)[0].lower() if ":" in url else ""
    https = 1 if "https" in scheme else -1
    rest = [0] * 22
    return [using_ip, long_url, short_url, symbol_at, redirecting, prefix_suffix, subdomains, https] + rest


def _build_vector_from_values(feature_values: List[int]) -> Tuple[np.ndarray, List[int]]:
    """Align raw feature values to the model FEATURE_NAMES order, returns x_vec and ordered list."""
    canonical_from_schema = load_feature_names_from_schema(CANONICAL_SCHEMA)
    vals = feature_values[:]
    if len(vals) != len(canonical_from_schema):
        if len(vals) < len(canonical_from_schema):
            vals = vals + [0] * (len(canonical_from_schema) - len(vals))
        else:
            vals = vals[:len(canonical_from_schema)]
    value_by_name = {name: vals[i] for i, name in enumerate(canonical_from_schema)}
    x_ordered = [value_by_name.get(n, 0) for n in FEATURE_NAMES]
    x_vec = np.array([x_ordered])
    return x_vec, x_ordered


@app.route('/process', methods=['POST'])
def process():
    try:
        data = request.json
        if not isinstance(data, dict) or 'url' not in data:
            return jsonify({'error': 'Missing "url" key in JSON request'}), 400

        url = data['url']
        mode = str(data.get('mode', '')).lower().strip() if isinstance(data, dict) else ''
        fast = bool(data.get('fast', False)) if isinstance(data, dict) else False

        if MODEL is None:
            return jsonify({'error': 'Model not loaded'}), 500

        # Features
        if fast:
            feature_values = compute_fast_features(url)
        else:
            try:
                fx = FeatureExtraction(url)
                feature_values = fx.extract_all_features()
            except Exception:
                feature_values = None
            if not isinstance(feature_values, list) or len(feature_values) != 30:
                feature_values = compute_fast_features(url)

        # Vector
        x_vec, x_ordered = _build_vector_from_values(feature_values)

        # Prob/decision
        p_phish = get_phish_probability(MODEL, x_vec)
        risk = int(round(p_phish * 100))
        thr = THRESHOLD
        if mode == 'strict':
            thr = max(0.05, THRESHOLD - 0.05)
        elif mode == 'relaxed':
            thr = min(0.95, THRESHOLD + 0.05)
        label = -1 if p_phish >= thr else 1

        # Reasons and explanation
        importances = getattr(MODEL, 'feature_importances_', None)
        reasons = human_reasons(FEATURE_NAMES, x_ordered, importances, max_items=3)
        explanation = explain_prediction(MODEL, x_vec, FEATURE_NAMES, x_ordered)

        return jsonify({
            'prediction': int(label),
            'risk': risk,
            'threshold': thr,
            'reasons': reasons,
            'explanation': explanation,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/analyze_page', methods=['POST'])
def analyze_page():
    try:
        data = request.json or {}
        page_url = data.get('page_url') or data.get('url')
        items = data.get('links', [])
        mode = str(data.get('mode', '')).lower().strip()
        fast = bool(data.get('fast', True))
        top_k_full = int(data.get('top_k_full', 0))
        req_llm = bool(data.get('llm', False))
        llm_max = int(data.get('llm_max', 10))
        llm_only_external = bool(data.get('llm_only_external', False))
        kids_mode = bool(data.get('kids_mode', False))

        if MODEL is None:
            return jsonify({'error': 'Model not loaded'}), 500

        seen = set()
        links = []
        for it in items:
            u = it.get('url') or it.get('href') or ''
            if not isinstance(u, str) or not u:
                continue
            if not (u.startswith('http://') or u.startswith('https://')):
                continue
            if u in seen:
                continue
            seen.add(u)
            links.append({
                'url': u,
                'banner': bool(it.get('banner')),
                'tag': it.get('tag') or 'a',
                'text': it.get('text') or '',
                'title': it.get('title') or '',
                'context': it.get('context') or '',
                'shortener': bool(it.get('shortener', False)),
            })

        try:
            origin = urlparse(page_url).netloc
        except Exception:
            origin = ''

        results = []
        for it in links:
            u = it['url']
            fv = compute_fast_features(u) if fast else None
            if not fv:
                try:
                    fx = FeatureExtraction(u)
                    fv = fx.extract_all_features()
                except Exception:
                    fv = compute_fast_features(u)
            x_vec, x_ordered = _build_vector_from_values(fv)
            p = get_phish_probability(MODEL, x_vec)
            risk = int(round(p * 100))
            thr = THRESHOLD
            if mode == 'strict':
                thr = max(0.05, THRESHOLD - 0.05)
            elif mode == 'relaxed':
                thr = min(0.95, THRESHOLD + 0.05)
            pred = -1 if p >= thr else 1
            importances = getattr(MODEL, 'feature_importances_', None)
            reasons = human_reasons(FEATURE_NAMES, x_ordered, importances, max_items=2)
            exp = explain_prediction(MODEL, x_vec, FEATURE_NAMES, x_ordered)
            try:
                ext = urlparse(u).netloc != origin and urlparse(u).netloc != ''
            except Exception:
                ext = False
            try:
                host = urlparse(u).netloc.lower()
            except Exception:
                host = ''
            text_blob = ' '.join(filter(None, [it.get('text') or '', it.get('title') or '', it.get('context') or '']))
            dom_re = re.compile(r"\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)
            m = dom_re.search(text_blob)
            mentioned_host = m.group(0).lower() if m else None
            brand_mismatch = False
            if mentioned_host and host and mentioned_host not in host and host not in mentioned_host:
                brand_mismatch = True
            puny = is_punycode_domain(host)
            cat = classify_category_from_url(u)

            results.append({
                'url': u,
                'prediction': int(pred),
                'risk': risk,
                'threshold': thr,
                'external': ext,
                'banner': it.get('banner', False),
                'shortener': bool(it.get('shortener', False)),
                'text': it.get('text') or '',
                'title': it.get('title') or '',
                'context': it.get('context') or '',
                'punycode': puny,
                'category': cat,
                'brand_mismatch': brand_mismatch,
                'reasons': reasons,
                'explanation': { 'top': exp.get('top', []) }
            })

        if top_k_full > 0:
            top_idxs = np.argsort([-r['risk'] for r in results])[:top_k_full]
            for idx in top_idxs:
                try:
                    u = results[idx]['url']
                    fx = FeatureExtraction(u)
                    fv = fx.extract_all_features()
                    x_vec, x_ordered = _build_vector_from_values(fv)
                    p = get_phish_probability(MODEL, x_vec)
                    risk = int(round(p * 100))
                    thr = results[idx]['threshold']
                    pred = -1 if p >= thr else 1
                    importances = getattr(MODEL, 'feature_importances_', None)
                    reasons = human_reasons(FEATURE_NAMES, x_ordered, importances, max_items=2)
                    exp = explain_prediction(MODEL, x_vec, FEATURE_NAMES, x_ordered)
                    results[idx].update({
                        'prediction': int(pred),
                        'risk': risk,
                        'reasons': reasons,
                        'explanation': { 'top': exp.get('top', []) },
                    })
                except Exception:
                    pass

        if USE_LLM or req_llm:
            cand_idxs = list(range(len(results)))
            if llm_only_external:
                cand_idxs = [i for i, r in enumerate(results) if r.get('external')]
            cand_idxs.sort(key=lambda i: results[i]['risk'], reverse=True)
            cand_idxs = cand_idxs[:max(0, llm_max)]
            subset = []
            for i in cand_idxs:
                r = results[i]
                subset.append({
                    'url': r.get('url', ''),
                    'text': r.get('text', ''),
                    'title': r.get('title', ''),
                    'context': r.get('context', ''),
                })
            judged = llm_judge_links(page_url, subset)
            if judged:
                for j in judged:
                    try:
                        ridx = cand_idxs[int(j.get('idx'))]
                    except Exception:
                        continue
                    res = results[ridx]
                    score = float(j.get('score', 0.0))
                    res['llm_score'] = score
                    res['llm_reason'] = j.get('reason', '')
                    blended = max(res['risk'] / 100.0, score)
                    res['risk'] = int(round(blended * 100))

        BANNER_FLAG_MIN = 35
        SHORTENER_FLAG_MIN = 25
        LLM_FLAG_MIN = 0.6
        for r in results:
            try:
                if r.get('external') and r.get('brand_mismatch'):
                    r['risk'] = min(100, r.get('risk', 0) + 12)
                    rs = r.get('reasons') or []
                    if len(rs) < 5:
                        rs.append('Teks/judul menyebut domain lain')
                        r['reasons'] = rs
                if r.get('punycode'):
                    r['risk'] = min(100, r.get('risk', 0) + 10)
                    rs = r.get('reasons') or []
                    if 'Domain IDN/punycode' not in rs:
                        rs.append('Domain IDN/punycode')
                        r['reasons'] = rs
                txt = ' '.join(filter(None, [r.get('text',''), r.get('title',''), r.get('context','')])).lower()
                sld_host = sld(urlparse(r.get('url','')).netloc.lower() if r.get('url') else '')
                for b in BRAND_KEYWORDS:
                    if b in txt and looks_like_brand(sld_host, b) and b not in sld_host:
                        r['risk'] = min(100, r.get('risk', 0) + 15)
                        rs = r.get('reasons') or []
                        rs.append(f'Domain menyerupai brand “{b}”')
                        r['reasons'] = rs
                        break
                cat = r.get('category')
                if cat:
                    boost = 10 if cat in ('gift-scam','gaming-freebies') else 15
                    r['risk'] = min(100, r.get('risk', 0) + boost)
                    rs = r.get('reasons') or []
                    if len(rs) < 5:
                        rs.append(f'Kategori mencurigakan: {cat}')
                        r['reasons'] = rs
                    if kids_mode and r.get('external'):
                        r['prediction'] = -1
            except Exception:
                pass
            if r.get('prediction', 1) != -1:
                if r.get('banner') and (r.get('external') or r.get('shortener')) and r.get('risk', 0) >= BANNER_FLAG_MIN:
                    r['prediction'] = -1
                elif r.get('shortener') and r.get('risk', 0) >= SHORTENER_FLAG_MIN:
                    r['prediction'] = -1
                elif float(r.get('llm_score', 0.0)) >= LLM_FLAG_MIN:
                    r['prediction'] = -1

        total_links = len(links)
        external_links = sum(1 for r in results if r.get('external'))
        flagged = [r for r in results if r['prediction'] == -1]
        flagged_count = len(flagged)
        banner_flagged = sum(1 for r in flagged if r.get('banner'))

        return jsonify({
            'page': page_url,
            'total_links': total_links,
            'external_links': external_links,
            'analyzed': len(results),
            'flagged': flagged_count,
            'banner_flagged': banner_flagged,
            'items': results[:100],
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/health', methods=['GET'])
def health():
    ok = MODEL is not None
    return jsonify({
        'ok': ok,
        'threshold': THRESHOLD if ok else None,
        'features': FEATURE_NAMES if ok else None,
    }), (200 if ok else 500)


@app.route('/version', methods=['GET'])
def version():
    try:
        ptr_path = os.path.join(MODELS_DIR, 'best_pointer.joblib')
        ptr = joblib.load(ptr_path)
        model_path = ptr['path'] if isinstance(ptr, dict) else ptr
        model_name = os.path.basename(model_path)
    except Exception:
        model_name = None
    return jsonify({
        'model': model_name,
        'features': FEATURE_NAMES,
        'threshold': THRESHOLD,
        'explain': True,
    })


@app.route('/config', methods=['GET'])
def config():
    try:
        ptr_path = os.path.join(MODELS_DIR, 'best_pointer.joblib')
        ptr = joblib.load(ptr_path)
        model_path = ptr['path'] if isinstance(ptr, dict) else ptr
        model_name = os.path.basename(model_path)
    except Exception:
        model_name = None
    return jsonify({
        'model': model_name,
        'features': FEATURE_NAMES,
        'threshold': THRESHOLD,
        'use_llm': USE_LLM,
        'llm_model': LLM_MODEL,
        'ollama_url': OLLAMA_URL,
        'llm_timeout': LLM_TIMEOUT,
        'version': 1,
    })


if __name__ == '__main__':
    app.run(debug=True)
