"""Coordination Fingerprint — a transferable 7-dimensional diagnostic.

Computable on any multi-agent corpus. Experimentally verified to separate
benign agent collectives (wiki) from malicious swarms (HF intrusion).

Each feature is grounded in published detection methodology:
- Phase entropy: HuggingFace 9-phase taxonomy (2026-07)
- Crypto density: Elastic Security Labs behavioral signals (2026)
- Self-reference: Elastic behavioral signal #5 (2026)
- Hub size: Pacheco et al. (arXiv:2001.05658) network coordination
- Gini: standard inequality measure for activity concentration
- Content skewness: distributional property of payload structure
- Type-token ratio: vocabulary diversity (linguistic analysis standard)
"""
import re
from collections import Counter, defaultdict

import numpy as np
from scipy.stats import entropy, skew

PHASE_PATTERNS = {
    "recon": re.compile(r"\bid\b|\benv\b|\bwhoami\b|\buname\b|cat /proc|169\.254", re.I),
    "rce": re.compile(r"exec\(|eval\(|os\.system|cycler\.__init__", re.I),
    "dropper": re.compile(r"gzip\.decompress|base64\..*decode", re.I),
    "exfil": re.compile(r"POST.*data=|gzip\.compress.*b64encode", re.I),
    "c2": re.compile(r"cmd\.txt|webhook\.site|BEACON", re.I),
    "k8s": re.compile(r"kubernetes|kubectl|serviceaccount", re.I),
    "supply_chain": re.compile(r"git clone|pypi|pip install", re.I),
    "tailscale": re.compile(r"tailscale|tskey-auth", re.I),
    "evasion": re.compile(r"--no-logs|evidence.*delet|resolv\.conf", re.I),
}

CRYPTO_RE = re.compile(r"base64|gzip|DDSE1|Ed25519|RSA|HMAC|sha256|hashlib", re.I)
SELF_REF_RE = re.compile(
    r"openai\.org|ace-research|REDACTED:runtime_identifier|"
    r"REDACTED:source_identifier|ExploitGym", re.I
)


def _text(record):
    return record.get("body", record.get("text", record.get("content", "")))


def compute_fingerprint(records, source="auto"):
    """Compute the 7-dimensional coordination fingerprint.

    Parameters
    ----------
    records : list[dict]
        Parsed records from either dataset. Expects either wiki format
        (with 'label', 'body', 'page_id'/'name') or SwarmTraces format
        (with 'id', 'text', 'parent_id', 'kind').
    source : str
        "wiki", "swarmtraces", or "auto" (detected from first record).

    Returns
    -------
    dict with 7 feature values + metadata.
    """
    if source == "auto":
        first = records[0] if records else {}
        source = "wiki" if "label" in first or "body" in first else "swarmtraces"

    fp = {"source": source, "n_records": len(records)}

    # 1. Gini coefficient of activity concentration
    if source == "wiki":
        counts = Counter(r.get("label", r.get("agent_id", "")) for r in records
                         if r.get("label") or r.get("agent_id")).values()
    else:
        parent_counts = Counter(
            r.get("parent_id", r.get("page_id", "")) for r in records
            if r.get("parent_id") or r.get("page_id"))
        counts = parent_counts.values() if parent_counts else [1]

    sorted_counts = sorted(counts)
    n = len(sorted_counts)
    if n > 1:
        index = np.arange(1, n + 1)
        arr = np.array(sorted_counts, dtype=float)
        fp["gini_activity"] = round(float((2 * np.sum(index * arr)) / (n * np.sum(arr)) - (n + 1) / n), 4)
    else:
        fp["gini_activity"] = 0.0

    # 2. Crypto/encoding density
    crypto_hits = sum(1 for r in records if CRYPTO_RE.search(_text(r)[:3000]))
    fp["crypto_density"] = round(crypto_hits / max(len(records), 1), 4)

    # 3. Type-token ratio (sample for speed)
    word_counter = Counter()
    for r in records[:5000]:
        word_counter.update(re.findall(r"\w+", _text(r)[:500].lower()))
    types = len(word_counter)
    tokens = sum(word_counter.values())
    fp["type_token_ratio"] = round(types / max(tokens, 1), 4)

    # 4. Max hub size
    if source == "wiki":
        page_agents = defaultdict(set)
        for r in records:
            label = r.get("label", r.get("agent_id"))
            page = r.get("page_id", r.get("name"))
            if label and page:
                page_agents[page].add(label)
        sizes = [len(s) for s in page_agents.values()]
    else:
        children_per_parent = Counter(
            r.get("parent_id", r.get("page_id")) for r in records
            if r.get("parent_id") or r.get("page_id"))
        sizes = list(children_per_parent.values()) if children_per_parent else [0]

    fp["max_hub_size"] = max(sizes) if sizes else 0

    # 5. Phase entropy
    phase_counts = Counter()
    for r in records:
        text = _text(r)[:5000]
        for phase, pat in PHASE_PATTERNS.items():
            if pat.search(text):
                phase_counts[phase] += 1

    if phase_counts:
        probs = np.array(list(phase_counts.values()), dtype=float)
        probs = probs / probs.sum()
        fp["phase_entropy"] = round(float(entropy(probs, base=2)), 4)
    else:
        fp["phase_entropy"] = 0.0
    fp["phase_counts"] = dict(phase_counts)

    # 6. Content length skewness
    lengths = [len(_text(r)) for r in records[:10000]]
    fp["content_skewness"] = round(float(skew(lengths)), 4) if len(lengths) > 2 else 0.0

    # 7. Self-reference density
    self_ref_hits = sum(1 for r in records if SELF_REF_RE.search(_text(r)[:3000]))
    fp["self_reference_density"] = round(self_ref_hits / max(len(records), 1), 4)

    return fp


FEATURE_KEYS = [
    "gini_activity", "crypto_density", "type_token_ratio",
    "max_hub_size", "phase_entropy", "content_skewness", "self_reference_density",
]

FEATURE_LABELS = [
    "Activity\nConcentration", "Crypto\nDensity", "Vocabulary\nDiversity",
    "Max Hub\nSize", "Phase\nEntropy", "Content\nSkewness", "Self-reference\nDensity",
]


def compare_fingerprints(fp1, fp2):
    """Compare two fingerprints and return separation metrics."""
    comparison = []
    for key in FEATURE_KEYS:
        v1 = fp1.get(key, 0)
        v2 = fp2.get(key, 0)
        if isinstance(v1, (int, float)) and isinstance(v2, (int, float)):
            denom = max(abs(v1), abs(v2), 0.001)
            separation = abs(v2 - v1) / denom
            comparison.append({
                "feature": key,
                "value_1": v1,
                "value_2": v2,
                "separation": round(separation, 3),
            })
    return comparison
