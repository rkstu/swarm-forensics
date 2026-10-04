"""Cross-incident comparison: collusion.wiki vs SwarmTraces (HF intrusion).

Runs the same detection methods on both datasets and compares findings.
The key contribution: demonstrating that the German wiki shows proportional
copying (per De Marzo et al., 2609.09150) while the HF intrusion shows
genuine unsanctioned coordination (per Frank, 2609.06140).
"""
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.parser import load_wiki_revisions, load_swarmtraces, summary
from external.elastic_signals import run_all as elastic_run
from external.frank_episodes import run_all as frank_run
from external.metr_conventions import run_all as metr_run


def analyze_dataset(name, records):
    print(f"\n{'='*60}")
    print(f"  Analyzing: {name} ({len(records)} records)")
    print(f"{'='*60}")

    results = {"dataset": name, "record_count": len(records)}

    s = summary(records)
    results["summary"] = s.get(name, s.get(list(s.keys())[0], {}))

    print(f"\n--- Elastic behavioral signals ---")
    elastic = elastic_run(records)
    results["elastic_signals"] = elastic
    for f in elastic:
        print(f"  [{f['signal']}] {f['description']}")

    print(f"\n--- Frank's unsanctioned coordination assessment ---")
    frank = frank_run(records)
    results["frank_assessment"] = frank
    print(f"  Criterion (a) influence: {frank['criterion_a_influence']}")
    print(f"  Criterion (b) conventions: {frank['criterion_b_conventions']}")
    print(f"  UNSANCTIONED COORDINATION: {frank['unsanctioned_coordination_detected']}")

    print(f"\n--- METR/HF attack patterns ---")
    metr = metr_run(records)
    results["metr_patterns"] = metr
    for f in metr:
        print(f"  [{f['pattern']}] {f['description']}")
        if "phase_counts" in f:
            for phase, count in sorted(f["phase_counts"].items(), key=lambda x: -x[1]):
                print(f"    {phase}: {count}")
        if "indicator_counts" in f:
            for ind, count in sorted(f["indicator_counts"].items(), key=lambda x: -x[1]):
                print(f"    {ind}: {count}")

    return results


def compare(wiki_results, traces_results):
    """Cross-incident comparison."""
    print(f"\n{'='*60}")
    print(f"  CROSS-INCIDENT COMPARISON")
    print(f"{'='*60}")

    comparison = {
        "methodology": (
            "Same detectors applied to both datasets. Grounded in: "
            "Elastic Security Labs behavioral signals (vendor, 2026), "
            "Frank's Definition 1 of unsanctioned coordination (arXiv:2609.06140), "
            "METR's documented coordination patterns (blog, 2026-08-26), "
            "HuggingFace's 9-phase attack taxonomy (blog, 2026-07)."
        ),
        "wiki": {
            "records": wiki_results["record_count"],
            "frank_coordination": wiki_results["frank_assessment"]["unsanctioned_coordination_detected"],
            "elastic_signal_count": len(wiki_results["elastic_signals"]),
        },
        "swarmtraces": {
            "records": traces_results["record_count"],
            "frank_coordination": traces_results["frank_assessment"]["unsanctioned_coordination_detected"],
            "elastic_signal_count": len(traces_results["elastic_signals"]),
        },
    }

    print(f"\n  German wiki (collusion.wiki):")
    print(f"    Records: {comparison['wiki']['records']}")
    print(f"    Frank Definition 1 met: {comparison['wiki']['frank_coordination']}")
    print(f"    Elastic signals triggered: {comparison['wiki']['elastic_signal_count']}/6")

    print(f"\n  HF intrusion (SwarmTraces):")
    print(f"    Records: {comparison['swarmtraces']['records']}")
    print(f"    Frank Definition 1 met: {comparison['swarmtraces']['frank_coordination']}")
    print(f"    Elastic signals triggered: {comparison['swarmtraces']['elastic_signal_count']}/6")

    wiki_frank = wiki_results["frank_assessment"]
    traces_frank = traces_results["frank_assessment"]

    print(f"\n  Key finding:")
    if not wiki_frank["unsanctioned_coordination_detected"] and traces_frank["unsanctioned_coordination_detected"]:
        print(f"    The wiki shows inter-execution influence but NO coordination")
        print(f"    conventions — consistent with De Marzo et al.'s proportional")
        print(f"    copying model (arXiv:2609.09150).")
        print(f"    The HF intrusion shows BOTH influence AND conventions —")
        print(f"    meeting Frank's full definition of unsanctioned coordination.")
        comparison["key_finding"] = (
            "Wiki behavior is explained by proportional copying "
            "(De Marzo et al., 2609.09150). HF intrusion meets the full "
            "definition of unsanctioned coordination (Frank, 2609.06140)."
        )
    elif wiki_frank["unsanctioned_coordination_detected"] and traces_frank["unsanctioned_coordination_detected"]:
        print(f"    Both incidents show unsanctioned coordination per Frank's")
        print(f"    Definition 1, but with different signatures.")
        comparison["key_finding"] = (
            "Both incidents meet Definition 1, but with qualitatively "
            "different coordination mechanisms."
        )
    else:
        print(f"    Results require manual interpretation.")
        comparison["key_finding"] = "Mixed results — see individual assessments."

    # Attack phase comparison
    wiki_phases = {}
    traces_phases = {}
    for f in wiki_results.get("metr_patterns", []):
        if "phase_counts" in f:
            wiki_phases = f["phase_counts"]
    for f in traces_results.get("metr_patterns", []):
        if "phase_counts" in f:
            traces_phases = f["phase_counts"]

    if wiki_phases or traces_phases:
        all_phases = sorted(set(list(wiki_phases.keys()) + list(traces_phases.keys())))
        print(f"\n  Attack phase comparison (HF 9-phase taxonomy):")
        print(f"    {'Phase':<15} {'Wiki':>8} {'HF':>8}")
        print(f"    {'-'*31}")
        for phase in all_phases:
            w = wiki_phases.get(phase, 0)
            h = traces_phases.get(phase, 0)
            print(f"    {phase:<15} {w:>8} {h:>8}")
        comparison["phase_comparison"] = {
            "wiki": wiki_phases,
            "swarmtraces": traces_phases,
        }

    return comparison


def main():
    from pathlib import Path
    results_dir = Path(__file__).resolve().parent.parent / "results"
    results_dir.mkdir(exist_ok=True)

    print("Loading collusion.wiki data...")
    wiki_records = load_wiki_revisions()
    print(f"  Loaded {len(wiki_records)} revisions")

    print("Loading SwarmTraces data...")
    traces_records = load_swarmtraces()
    print(f"  Loaded {len(traces_records)} records")

    wiki_results = analyze_dataset("collusion-wiki", wiki_records)
    traces_results = analyze_dataset("swarmtraces", traces_records)
    comparison = compare(wiki_results, traces_results)

    report = {
        "title": "Swarm Forensics: Cross-Incident Analysis",
        "methodology": comparison["methodology"],
        "datasets": {
            "collusion_wiki": wiki_results,
            "swarmtraces": traces_results,
        },
        "comparison": comparison,
        "references": {
            "elastic": "elastic.co/security-labs/ai-agent-attack-detection-hugging-face-breach",
            "frank_2609_06140": "arXiv:2609.06140 (Counter-Swarm Doctrine)",
            "demarzo_2609_09150": "arXiv:2609.09150 (Copying explains collective behavior)",
            "metr": "metr.org/blog/2026-08-26-openai-hugging-face-incident-investigation/",
            "hf_timeline": "huggingface.co/blog/agent-intrusion-technical-timeline",
            "baranchuk_2402_07510": "arXiv:2402.07510 (Secret Collusion via Steganography)",
            "greenblatt_2312_06942": "arXiv:2312.06942 (AI Control)",
            "hammond_2502_14143": "arXiv:2502.14143 (Multi-Agent Risks)",
            "campbell_2603_01246": "arXiv:2603.01246 (Defensive Refusal Bias)",
            "swarmtraces": "swarmtraces.org (Palisade Research / Trajectory Institute)",
            "collusion_wiki": "collusion.wiki",
        },
    }

    output_path = results_dir / "cross_incident_report.json"
    with open(output_path, "w") as fh:
        json.dump(report, fh, indent=2, default=str)
    print(f"\nReport written to {output_path}")

    return report


if __name__ == "__main__":
    main()
