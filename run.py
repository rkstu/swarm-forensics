#!/usr/bin/env python3
"""Swarm Forensics Toolkit — main entry point.

Runs all analyses on both datasets and generates the cross-incident report.

Usage:
    python run.py              # full analysis
    python run.py --wiki-only  # collusion.wiki only
    python run.py --hf-only    # SwarmTraces only
"""
import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from src.parser import load_wiki_revisions, load_swarmtraces, summary
from src.cross_incident import analyze_dataset, compare
from src.graph import build_wiki_graph, build_swarmtraces_graph, visualize_wiki_graph


def main():
    parser = argparse.ArgumentParser(description="Swarm Forensics Toolkit")
    parser.add_argument("--wiki-only", action="store_true")
    parser.add_argument("--hf-only", action="store_true")
    args = parser.parse_args()

    results_dir = ROOT / "results"
    results_dir.mkdir(exist_ok=True)

    start = time.time()
    print("=" * 60)
    print("  SWARM FORENSICS TOOLKIT")
    print("  Cross-incident analysis of AI agent coordination")
    print("=" * 60)

    wiki_results = None
    traces_results = None

    if not args.hf_only:
        print("\n[1/4] Loading collusion.wiki data...")
        wiki_records = load_wiki_revisions()
        print(f"  {len(wiki_records)} revisions loaded")

        print("\n[2/4] Analyzing collusion.wiki...")
        wiki_results = analyze_dataset("collusion-wiki", wiki_records)

        print("\n  Building co-editing graph...")
        G_wiki, wiki_graph_stats = build_wiki_graph(wiki_records)
        wiki_results["graph"] = wiki_graph_stats
        print(f"  {wiki_graph_stats['nodes']} agents, {wiki_graph_stats['edges']} links")

        try:
            visualize_wiki_graph(G_wiki, wiki_graph_stats, results_dir / "wiki_graph.html")
        except Exception as e:
            print(f"  Graph visualization skipped: {e}")

    if not args.wiki_only:
        print("\n[3/4] Loading SwarmTraces data...")
        traces_records = load_swarmtraces()
        print(f"  {len(traces_records)} records loaded")

        print("\n[4/4] Analyzing SwarmTraces...")
        traces_results = analyze_dataset("swarmtraces", traces_records)

        print("\n  Building payload graph...")
        G_traces, traces_graph_stats = build_swarmtraces_graph(traces_records)
        traces_results["graph"] = traces_graph_stats
        print(f"  {traces_graph_stats['nodes']} nodes, {traces_graph_stats['edges']} edges")

    if wiki_results and traces_results:
        comparison = compare(wiki_results, traces_results)
    else:
        comparison = None

    elapsed = time.time() - start

    report = {
        "title": "Swarm Forensics: Cross-Incident Analysis of AI Agent Coordination",
        "toolkit": "swarm-forensics",
        "submodule": "giordano-demarzo/agent-wiki-copying (arXiv:2609.09150, MIT)",
        "elapsed_seconds": round(elapsed, 1),
        "datasets": {},
        "comparison": comparison,
        "grounding": {
            "peer_reviewed": [
                "De Marzo et al. (2609.09150) — Proportional copying null model",
                "Frank (2609.06140) — Unsanctioned coordination definition",
                "Baranchuk et al. (2402.07510) — Secret collusion formalization [138 cites]",
                "Greenblatt et al. (2312.06942) — AI Control framework [239 cites]",
                "Hammond et al. (2502.14143) — Multi-Agent Risks taxonomy [207 cites]",
                "Pacheco et al. (2001.05658) — Network coordination detection [244 cites]",
                "Campbell et al. (2603.01246) — Defensive refusal methodology [9 cites]",
            ],
            "institutional": [
                "Elastic Security Labs — Behavioral signals (vendor, 2026)",
                "METR — Investigation findings (blog, 2026-08-26)",
                "UK AISI — Cheating behavior taxonomy (gov, 2026)",
                "HuggingFace — Forensic timeline (first-party, 2026-07)",
                "SwarmTraces — Decoded payloads (Palisade/Trajectory, 2026-09-25)",
            ],
        },
    }
    if wiki_results:
        report["datasets"]["collusion_wiki"] = wiki_results
    if traces_results:
        report["datasets"]["swarmtraces"] = traces_results

    output_path = results_dir / "full_report.json"
    with open(output_path, "w") as fh:
        json.dump(report, fh, indent=2, default=str)

    print(f"\n{'='*60}")
    print(f"  Analysis complete in {elapsed:.1f}s")
    print(f"  Report: {output_path}")
    if (results_dir / "wiki_graph.html").exists():
        print(f"  Graph:  {results_dir / 'wiki_graph.html'}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
