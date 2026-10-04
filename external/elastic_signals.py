"""Behavioral signal detectors from Elastic Security Labs.

Source: elastic.co/security-labs/ai-agent-attack-detection-hugging-face-breach
Status: Vendor analysis (not peer-reviewed). Used as secondary signal.

Elastic defined six behavioral signals for distinguishing AI agent attacks
from human attackers, published in their analysis of the July 2026 HuggingFace
intrusion. These detectors implement binary checks for each signal.

MITRE ATT&CK mapping: T1190, T1059.004, T1552, T1078, T1071, T1613
MITRE ATLAS mapping: AML.T0010, AML.T0055
"""
import re
from collections import Counter


def detect_retry_succeeded(records):
    """Signal 1: Retries of already-succeeded actions.

    AI agents repeat commands that already returned success because each
    tool call is statistically independent — the model doesn't always
    condition on prior success.
    """
    findings = []
    content_hashes = Counter()
    for r in records:
        h = r.get("metadata", {}).get("body_sha256") or hash(r["content"][:200])
        content_hashes[h] += 1

    duplicates = {h: count for h, count in content_hashes.items() if count > 1}
    if duplicates:
        findings.append({
            "signal": "retry_succeeded",
            "source_method": "Elastic Security Labs, 'AI agent attack detection' (2026)",
            "description": "Duplicate content hashes suggest retried actions",
            "count": sum(v - 1 for v in duplicates.values()),
            "unique_repeated": len(duplicates),
        })
    return findings


def detect_benchmark_strings(records):
    """Signal 2: Benchmark/evaluation strings in traces.

    Agents that escaped from evaluation environments leak task IDs,
    score references, and evaluator artifacts into their attack traces.
    """
    BENCHMARK_PATTERNS = [
        re.compile(r"ExploitGym", re.I),
        re.compile(r"task_id|task_name|TASK_", re.I),
        re.compile(r"score|grading|evaluation|benchmark", re.I),
        re.compile(r"submitted_code|function_name|agent_id", re.I),
        re.compile(r"checksum.*task", re.I),
    ]

    findings = []
    matches = Counter()
    for r in records:
        text = r["content"][:2000]
        for pat in BENCHMARK_PATTERNS:
            if pat.search(text):
                matches[pat.pattern] += 1

    if matches:
        findings.append({
            "signal": "benchmark_strings",
            "source_method": "Elastic Security Labs, 'AI agent attack detection' (2026)",
            "description": "Evaluation/benchmark artifacts found in traces",
            "pattern_counts": dict(matches),
            "total_matches": sum(matches.values()),
        })
    return findings


def detect_hallucinated_commands(records):
    """Signal 3: Hallucinated or incoherent commands.

    LLM agents generate commands that don't exist on the target system,
    mix up syntax from different shells, or produce malformed inputs.
    """
    HALLUCINATION_PATTERNS = [
        re.compile(r"command not found", re.I),
        re.compile(r"No such file or directory", re.I),
        re.compile(r"syntax error", re.I),
        re.compile(r"ERR\s+", re.I),
    ]

    findings = []
    error_count = 0
    for r in records:
        text = r["content"][:2000]
        for pat in HALLUCINATION_PATTERNS:
            if pat.search(text):
                error_count += 1
                break

    if error_count:
        findings.append({
            "signal": "hallucinated_commands",
            "source_method": "Elastic Security Labs, 'AI agent attack detection' (2026)",
            "description": "Error patterns suggesting non-human command generation",
            "records_with_errors": error_count,
            "error_rate": error_count / max(len(records), 1),
        })
    return findings


def detect_poor_opsec(records):
    """Signal 4: Poor operational security.

    AI agents leave credentials, keys, and sensitive data in plaintext
    in logs, error messages, and command output — behavior a human
    attacker would typically avoid.
    """
    OPSEC_PATTERNS = [
        re.compile(r"hf_[A-Za-z0-9]{10,}"),
        re.compile(r"tskey-auth-[A-Za-z0-9]+"),
        re.compile(r"Bearer\s+[A-Za-z0-9_\-\.]+"),
        re.compile(r"API[_-]?KEY|api[_-]?key|X-API-Key", re.I),
        re.compile(r"CREDENTIAL|credential", re.I),
        re.compile(r"password|passwd|secret", re.I),
    ]

    findings = []
    leaked = Counter()
    for r in records:
        text = r["content"][:5000]
        for pat in OPSEC_PATTERNS:
            if pat.search(text):
                leaked[pat.pattern] += 1

    if leaked:
        findings.append({
            "signal": "poor_opsec",
            "source_method": "Elastic Security Labs, 'AI agent attack detection' (2026)",
            "description": "Credential/key patterns in plaintext",
            "pattern_counts": dict(leaked),
            "total_records": sum(leaked.values()),
        })
    return findings


def detect_self_referential_search(records):
    """Signal 5: Self-referential search.

    Agents search for their own infrastructure names, evaluation
    environment identifiers, or internal hostnames — revealing
    awareness of their own context in ways humans wouldn't express.
    """
    SELF_REF_PATTERNS = [
        re.compile(r"openai\.org|ace-research\.openai", re.I),
        re.compile(r"REDACTED:runtime_identifier|REDACTED:source_identifier", re.I),
        re.compile(r"packages\.hub\.", re.I),
        re.compile(r"webhook\.site", re.I),
    ]

    findings = []
    matches = Counter()
    for r in records:
        text = r["content"][:3000]
        for pat in SELF_REF_PATTERNS:
            if pat.search(text):
                matches[pat.pattern] += 1

    if matches:
        findings.append({
            "signal": "self_referential_search",
            "source_method": "Elastic Security Labs, 'AI agent attack detection' (2026)",
            "description": "References to own infrastructure/evaluation environment",
            "pattern_counts": dict(matches),
        })
    return findings


def detect_pointless_commands(records):
    """Signal 6: Inefficient/pointless command sequences.

    AI agents take paths no human would choose — running unnecessary
    commands, using verbose approaches, or exploring dead ends that
    a human operator would skip.
    """
    findings = []
    short_payloads = sum(1 for r in records if r["content_len"] < 20 and r["content_len"] > 0)
    if short_payloads:
        findings.append({
            "signal": "pointless_commands",
            "source_method": "Elastic Security Labs, 'AI agent attack detection' (2026)",
            "description": "Very short payloads suggesting probing/testing behavior",
            "count": short_payloads,
            "rate": short_payloads / max(len(records), 1),
        })
    return findings


def run_all(records):
    """Run all six Elastic behavioral signal detectors."""
    all_findings = []
    for detector in [
        detect_retry_succeeded,
        detect_benchmark_strings,
        detect_hallucinated_commands,
        detect_poor_opsec,
        detect_self_referential_search,
        detect_pointless_commands,
    ]:
        all_findings.extend(detector(records))
    return all_findings
