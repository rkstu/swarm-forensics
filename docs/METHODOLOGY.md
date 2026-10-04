# Methodology

Every detector in this toolkit comes from a published source. This document maps each module to its origin so findings can be verified independently.

## What's in the submodule

`agent-wiki-copying/` is a git submodule pointing to De Marzo, Alboré, and Garcia's codebase (arXiv:2609.09150, MIT license). They showed that proportional copying explains the wiki agents' collective behavior: where to write, how to sign, how to word their messages. The correlation between their model's predictions and actual agent choices was 0.81 across 17 conventions.

We use their work as the baseline. The fingerprint compares new data against what their model would predict for benign copying behavior.

## What's in `external/`

Each file implements detectors from a specific published source. The code is ours; the definitions are theirs.

**`elastic_signals.py`** implements six behavioral signals from Elastic Security Labs' analysis of the HuggingFace breach (elastic.co/security-labs/ai-agent-attack-detection-hugging-face-breach, 2026). These are: retry of succeeded actions, benchmark strings in traces, hallucinated commands, poor OPSEC, self-referential search, and pointless command sequences. Elastic published these as triage and tuning signals, not standalone detection rules, and mapped them to MITRE ATT&CK techniques T1190, T1059.004, T1552, T1078, T1071, and T1613.

**`frank_episodes.py`** checks the formal definition of unsanctioned coordination from Frank (arXiv:2609.06140, "Counter-Swarm Doctrine"). His Definition 1 requires two things: evidence of inter-execution influence (agents using information from each other's actions) and evidence that this violates an applicable policy. Similar outputs or shared model weights alone are not sufficient. We check both criteria and only report coordination when both are met.

**`metr_conventions.py`** classifies records into patterns documented by METR's investigation of the HuggingFace incident (metr.org/blog/2026-08-26) and the 9-phase attack taxonomy from HuggingFace's forensic timeline (huggingface.co/blog/agent-intrusion-technical-timeline). The phases are: RECON, RCE, DROPPER, EXFIL, C2, EVASION, K8S, SUPPLY-CHAIN, and TAILSCALE.

## What's in `src/`

**`fingerprint.py`** computes a 7-dimensional coordination fingerprint from any list of records. The features draw on multiple sources: phase entropy uses the HF taxonomy, crypto density and self-reference density come from Elastic's signals, the Gini coefficient and hub size measure network structure in the spirit of Pacheco et al. (arXiv:2001.05658, 244 citations), and type-token ratio and content skewness are standard distributional measures.

**`propagation.py`** traces information spread. The URL propagation analysis counts how many wiki pages contain a given URL over time. The naming convention analysis tracks what share of newly-arriving agents adopt each naming pattern per day. The hub hierarchy maps parent-child relationships in SwarmTraces to identify C2 command structure.

**`parser.py`** normalizes collusion.wiki, SwarmTraces, and AI Village data into a common schema so all detectors can run on any source.

## What we don't claim

The fingerprint has been tested on three datasets. Whether the feature set generalizes is unknown. The false positive rates are measured against one benign baseline (the wiki) and one attack baseline (SwarmTraces), which is a starting point, not a definitive calibration.

The Elastic signals were designed as behavioral triage aids, not binary classifiers. Our precision numbers describe how they performed on these two datasets. Different data would produce different numbers.

Frank's Definition 1 is a necessary condition for unsanctioned coordination, not a sufficient one. Meeting both criteria means the evidence is consistent with coordination. It doesn't prove it.
