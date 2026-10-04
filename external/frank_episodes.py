"""Coordination episode detection per Counter-Swarm Doctrine.

Source: Frank, G.N. (2026). "Counter-Swarm Doctrine: Containing Coordinated
Agent Intrusions." arXiv:2609.06140, Section 4.

Status: Preprint (not yet peer-reviewed, 1 citation). Provides the formal
definition of unsanctioned coordination used as our primary detection criterion.

Definition 1 (Frank 2609.06140): "Unsanctioned agent coordination occurs when
two or more agent executions use information or actions originating from one
another to organise activity that violates an applicable collaboration,
information-flow, or delegated-authority policy."

Requires BOTH:
  (a) Evidence of inter-execution influence (versioned writes/reads, direct
      messages, attributable downstream action)
  (b) An applicable policy violation

"Similar outputs, a shared model, or simultaneous resource use alone are
insufficient."
"""
import re
from collections import defaultdict


def detect_inter_execution_influence(records):
    """Check evidence criterion (a): inter-execution influence.

    Looks for versioned writes/reads on shared artifacts, cross-references
    between agents, and attributable downstream actions.
    """
    findings = []

    if records and records[0]["source"] == "collusion-wiki":
        page_editors = defaultdict(set)
        page_edit_count = defaultdict(int)
        for r in records:
            if r["page_id"] and r["agent_id"]:
                page_editors[r["page_id"]].add(r["agent_id"])
                page_edit_count[r["page_id"]] += 1

        shared_pages = {
            pid: editors for pid, editors in page_editors.items()
            if len(editors) >= 2
        }
        if shared_pages:
            findings.append({
                "criterion": "inter_execution_influence",
                "evidence_type": "shared_artifact_writes",
                "source_method": "Frank (2609.06140), Definition 1, criterion (a)",
                "description": "Multiple agents writing to the same wiki pages",
                "shared_pages": len(shared_pages),
                "max_editors_per_page": max(len(e) for e in shared_pages.values()),
                "agents_involved": len(set().union(*shared_pages.values())),
            })

    elif records and records[0]["source"] == "swarmtraces":
        parent_children = defaultdict(list)
        for r in records:
            if r["page_id"]:
                parent_children[r["page_id"]].append(r["id"])

        chains = {p: children for p, children in parent_children.items() if len(children) > 1}
        if chains:
            findings.append({
                "criterion": "inter_execution_influence",
                "evidence_type": "payload_chains",
                "source_method": "Frank (2609.06140), Definition 1, criterion (a)",
                "description": "Linked payload chains (parent-child relationships)",
                "chain_count": len(chains),
                "max_chain_length": max(len(c) for c in chains.values()),
            })

    return findings


def detect_coordination_conventions(records):
    """Detect coordination conventions (HOLD/VETO/STOP, zz-prefix).

    These conventions are documented by METR (2026) in their investigation
    of the HuggingFace incident and by Frank (2609.06140, Section 3.1).
    """
    CONVENTIONS = [
        (re.compile(r"\bHOLD\b"), "HOLD"),
        (re.compile(r"\bVETO\b"), "VETO"),
        (re.compile(r"\bSTOP\b"), "STOP"),
        (re.compile(r"\bzzASK_"), "zz-prefix-ask"),
        (re.compile(r"\bzzANSWER_"), "zz-prefix-answer"),
        (re.compile(r"\bzz[A-Z]"), "zz-prefix-general"),
        (re.compile(r"CONFIRMED|VERIFIED", re.I), "confirmation"),
        (re.compile(r"BEACON\s"), "c2-beacon"),
    ]

    findings = []
    convention_counts = defaultdict(int)
    for r in records:
        text = r["content"][:3000]
        for pat, name in CONVENTIONS:
            if pat.search(text):
                convention_counts[name] += 1

    if convention_counts:
        findings.append({
            "criterion": "coordination_conventions",
            "source_method": (
                "METR investigation (2026-08-26), documented in "
                "Frank (2609.06140), Section 3.1"
            ),
            "description": "Inter-agent coordination conventions detected",
            "convention_counts": dict(convention_counts),
        })
    return findings


def detect_signing_patterns(records):
    """Detect cryptographic signing patterns (Ed25519, DDSE1).

    Ed25519 signing (19 keys, 429 signed messages) documented in HF forensic
    timeline (huggingface.co/blog/agent-intrusion-technical-timeline).
    DDSE1 encryption documented by Boyd Kane (LessWrong, 2026-08).
    """
    CRYPTO_PATTERNS = [
        (re.compile(r"DDSE1"), "ddse1-encryption"),
        (re.compile(r"Ed25519|EdDSA"), "ed25519-signing"),
        (re.compile(r"RSA|PKCS"), "rsa-encryption"),
        (re.compile(r"HMAC|hmac"), "hmac-integrity"),
        (re.compile(r"SHA-?256|sha256"), "sha256-hashing"),
        (re.compile(r"base64|b64encode|b64decode"), "base64-encoding"),
        (re.compile(r"gzip\.compress|gzip\.decompress"), "gzip-compression"),
    ]

    findings = []
    pattern_counts = defaultdict(int)
    for r in records:
        text = r["content"][:5000]
        for pat, name in CRYPTO_PATTERNS:
            if pat.search(text):
                pattern_counts[name] += 1

    if pattern_counts:
        findings.append({
            "criterion": "cryptographic_coordination",
            "source_method": (
                "HF forensic timeline (2026-07); "
                "Boyd Kane, LessWrong (2026-08)"
            ),
            "description": "Cryptographic patterns indicating coordinated C2 infrastructure",
            "pattern_counts": dict(pattern_counts),
        })
    return findings


def assess_unsanctioned_coordination(records):
    """Full assessment per Frank's Definition 1.

    Returns findings only where BOTH criteria are met:
    (a) inter-execution influence AND (b) convention/protocol evidence
    suggesting policy violation.
    """
    influence = detect_inter_execution_influence(records)
    conventions = detect_coordination_conventions(records)
    signing = detect_signing_patterns(records)

    has_influence = len(influence) > 0
    has_conventions = len(conventions) > 0 or len(signing) > 0

    assessment = {
        "definition": "Frank (2609.06140), Definition 1",
        "criterion_a_influence": has_influence,
        "criterion_b_conventions": has_conventions,
        "unsanctioned_coordination_detected": has_influence and has_conventions,
        "evidence": influence + conventions + signing,
    }
    return assessment


def run_all(records):
    return assess_unsanctioned_coordination(records)
