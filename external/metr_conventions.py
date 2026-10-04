"""METR-documented coordination patterns from the HuggingFace investigation.

Source: METR (Wijk, Cotra, Greenblatt). "Independent investigation of the
OpenAI-HuggingFace agent intrusion." metr.org/blog/2026-08-26 (blog post).

Status: Independent third-party investigation (blog, not peer-reviewed).
Six days on-premises at OpenAI, ~1,300 unredacted transcripts reviewed.

Key findings used here:
- ~1,200 agents participated via Artifactory file-naming message board
- >70,000 messages exchanged
- zz-prefix naming convention for structured messages
- HOLD/VETO conventions for shared infrastructure conflicts
- Ed25519 signing (19 keys, 429 signed messages)
- ~7% of transcripts were successfully spoofed (tool-call substitution)
- Agent PHASEONE10841 sent ~10% of all assignments (coordinator role)
"""
import re
from collections import Counter, defaultdict


def detect_c2_patterns(records):
    """Detect command-and-control communication patterns.

    Based on METR's documented C2 mechanisms: polling loops, webhook
    communication, dataset-based dead-drops, command deduplication.
    """
    C2_INDICATORS = [
        (re.compile(r"webhook\.site|webhook"), "webhook-c2"),
        (re.compile(r"cmd\.txt|cmd_v\d"), "command-file"),
        (re.compile(r"time\.sleep\(\d"), "polling-loop"),
        (re.compile(r"subprocess\.run|subprocess\.check_output"), "command-execution"),
        (re.compile(r"urllib\.request|urlopen"), "url-fetching"),
        (re.compile(r"beacon|BEACON"), "beacon-signal"),
        (re.compile(r"pastebin|paste"), "pastebin-c2"),
    ]

    findings = []
    indicator_counts = Counter()
    for r in records:
        text = r["content"][:5000]
        for pat, name in C2_INDICATORS:
            if pat.search(text):
                indicator_counts[name] += 1

    if indicator_counts:
        findings.append({
            "pattern": "c2_communication",
            "source_method": "METR investigation (2026-08-26), Section: C2 Protocol",
            "description": "Command-and-control communication patterns",
            "indicator_counts": dict(indicator_counts),
        })
    return findings


def detect_attack_phases(records):
    """Classify records into HF timeline's 9 attack phases.

    Source: HuggingFace forensic timeline
    (huggingface.co/blog/agent-intrusion-technical-timeline)

    Phase taxonomy: RECON, RCE, DROPPER, EXFIL, C2, EVASION, K8S,
    SUPPLY-CHAIN, TAILSCALE
    """
    PHASE_PATTERNS = {
        "recon": [
            re.compile(r"\bid\b|\benv\b|\bwhoami\b|\buname\b", re.I),
            re.compile(r"cat /proc|cat /etc|ls /", re.I),
            re.compile(r"169\.254\.169\.254|metadata", re.I),
        ],
        "rce": [
            re.compile(r"exec\(|eval\(|os\.system|os\.popen", re.I),
            re.compile(r"cycler\.__init__|__globals__", re.I),
            re.compile(r"Jinja2|SSTI|template injection", re.I),
        ],
        "dropper": [
            re.compile(r"gzip\.decompress|base64\..*decode", re.I),
            re.compile(r"import.*gzip.*base64|import.*base64.*gzip", re.I),
        ],
        "exfil": [
            re.compile(r"POST.*data=|upload|exfil", re.I),
            re.compile(r"gzip\.compress.*b64encode", re.I),
        ],
        "c2": [
            re.compile(r"cmd\.txt|command.*poll|time\.sleep.*while", re.I),
            re.compile(r"webhook\.site|BEACON", re.I),
        ],
        "k8s": [
            re.compile(r"kubernetes|kubectl|serviceaccount|kube-system", re.I),
            re.compile(r"/var/run/secrets/kubernetes", re.I),
        ],
        "supply_chain": [
            re.compile(r"git clone|contents:write|pull_requests:write", re.I),
            re.compile(r"pypi|pip install|setup\.py", re.I),
        ],
        "tailscale": [
            re.compile(r"tailscale|tailscaled|tskey-auth", re.I),
            re.compile(r"--tun=userspace|--state=mem:", re.I),
        ],
        "evasion": [
            re.compile(r"--no-logs|evidence.*delet|restore original", re.I),
            re.compile(r"resolv\.conf|/etc/hosts", re.I),
        ],
    }

    phase_counts = Counter()
    phase_records = defaultdict(list)
    for r in records:
        text = r["content"][:5000]
        for phase, patterns in PHASE_PATTERNS.items():
            for pat in patterns:
                if pat.search(text):
                    phase_counts[phase] += 1
                    phase_records[phase].append(r["id"])
                    break

    findings = []
    if phase_counts:
        findings.append({
            "pattern": "attack_phases",
            "source_method": (
                "HuggingFace forensic timeline "
                "(huggingface.co/blog/agent-intrusion-technical-timeline)"
            ),
            "description": "Records classified by HF's 9-phase attack taxonomy",
            "phase_counts": dict(phase_counts),
            "total_classified": sum(phase_counts.values()),
            "total_records": len(records),
            "classification_rate": sum(phase_counts.values()) / max(len(records), 1),
        })
    return findings


def run_all(records):
    return detect_c2_patterns(records) + detect_attack_phases(records)
