"""SwarmScope — Interactive Forensic Workbench for AI Agent Swarms.

A tool, not a report. Upload your own multi-agent transcripts or explore
three reference incidents. Compute coordination fingerprints, trace
information propagation, and benchmark detector reliability.

Usage: streamlit run app.py
"""
import json
import re
import io
from collections import Counter, defaultdict
from pathlib import Path

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import numpy as np

ROOT = Path(__file__).resolve().parent

st.set_page_config(page_title="SwarmScope", page_icon="🔬", layout="wide", initial_sidebar_state="expanded")

# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------
@st.cache_data
def load_dataset(name):
    """Load a reference dataset by name."""
    import sys; sys.path.insert(0, str(ROOT))
    from src.parser import load_wiki_revisions, load_swarmtraces, load_ai_village_chat
    if name == "German Wiki":
        return load_wiki_revisions()
    elif name == "HF Intrusion":
        return load_swarmtraces()
    elif name == "AI Village":
        return load_ai_village_chat()
    return []

@st.cache_data
def load_wiki_raw():
    records = []
    with open(ROOT / "data" / "collusion-wiki" / "revisions.jsonl") as f:
        for line in f:
            records.append(json.loads(line))
    return records

@st.cache_data
def load_traces_raw():
    records = []
    with open(ROOT / "data" / "swarmtraces" / "redacted.jsonl") as f:
        for i, line in enumerate(f):
            if i >= 50000:
                break
            records.append(json.loads(line))
    return records

def parse_uploaded(file_obj):
    """Parse an uploaded JSONL file into our common schema."""
    records = []
    text = file_obj.getvalue().decode("utf-8", errors="replace")
    for line in text.strip().split("\n"):
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        records.append({
            "id": r.get("id", r.get("rev_id", str(len(records)))),
            "source": "uploaded",
            "agent_id": r.get("label", r.get("agent_speaker_id", r.get("agent_id"))),
            "timestamp": r.get("time", r.get("created_at", r.get("timestamp"))),
            "action_type": r.get("kind", r.get("action_type", "unknown")),
            "content": r.get("body", r.get("text", r.get("content", ""))),
            "content_len": len(r.get("body", r.get("text", r.get("content", "")))),
            "page_id": r.get("page_id", r.get("parent_id", r.get("room_id"))),
            "metadata": {},
        })
    return records

# ---------------------------------------------------------------------------
# Analysis functions (inline for speed, grounded in published methods)
# ---------------------------------------------------------------------------
@st.cache_data
def compute_fingerprint_cached(records_json, source):
    import sys; sys.path.insert(0, str(ROOT))
    from src.fingerprint import compute_fingerprint
    records = json.loads(records_json)
    return compute_fingerprint(records, source)

def run_elastic_on(records):
    import sys; sys.path.insert(0, str(ROOT))
    from external.elastic_signals import run_all
    return run_all(records)

def run_metr_on(records):
    import sys; sys.path.insert(0, str(ROOT))
    from external.metr_conventions import run_all
    return run_all(records)

def run_frank_on(records):
    import sys; sys.path.insert(0, str(ROOT))
    from external.frank_episodes import run_all
    return run_all(records)

# ---------------------------------------------------------------------------
# Sidebar: dataset selection + upload
# ---------------------------------------------------------------------------
def sidebar():
    st.sidebar.markdown("## SwarmScope")
    st.sidebar.markdown(
        "Forensic workbench for AI agent swarms. "
        "Select reference datasets, upload your own, "
        "and run coordination analysis."
    )
    st.sidebar.markdown(
        "[GitHub](https://github.com/rkstu/swarm-forensics) · "
        "[Methodology](https://github.com/rkstu/swarm-forensics/blob/main/docs/METHODOLOGY.md)"
    )
    st.sidebar.markdown("---")
    st.sidebar.markdown("### Reference datasets")

    selected = st.sidebar.multiselect(
        "Include in analysis",
        ["German Wiki", "AI Village", "HF Intrusion"],
        default=["German Wiki", "AI Village", "HF Intrusion"],
    )

    st.sidebar.markdown("---")
    st.sidebar.markdown("### Upload your own data")
    st.sidebar.caption("JSONL format — one JSON object per line with fields like: body/text, label/agent_id, time")
    uploaded = st.sidebar.file_uploader(
        "Drop a JSONL file here",
        type=["jsonl", "json", "txt"],
        help="Any multi-agent transcript. Fields: id, body/text/content, label/agent_id, time/timestamp, page_id/parent_id"
    )

    datasets = {}
    for name in selected:
        datasets[name] = load_dataset(name)

    if uploaded:
        custom = parse_uploaded(uploaded)
        if custom:
            datasets[f"Uploaded ({uploaded.name})"] = custom
            st.sidebar.success(f"Loaded {len(custom):,} records")
        else:
            st.sidebar.error("Could not parse file")

    st.sidebar.markdown("---")
    st.sidebar.caption(
        f"**Total:** {sum(len(r) for r in datasets.values()):,} records "
        f"across {len(datasets)} datasets"
    )
    return datasets


# ---------------------------------------------------------------------------
# Tab 1: Fingerprint
# ---------------------------------------------------------------------------
COLORS = {
    "German Wiki": "#4ECDC4",
    "AI Village": "#AA96DA",
    "HF Intrusion": "#FF6B6B",
}

def render_fingerprint(datasets):
    st.markdown("## Coordination Fingerprint")
    st.markdown(
        "Seven features, computed on each dataset you select. "
        "The shapes tell you what kind of coordination you're looking at."
    )

    if not datasets:
        st.warning("Select at least one dataset in the sidebar.")
        return

    labels = ["Activity\nConcentration", "Crypto\nDensity", "Vocabulary\nDiversity",
              "Max Hub\nSize", "Phase\nEntropy", "Content\nSkewness", "Self-reference\nDensity"]
    keys = ["gini_activity", "crypto_density", "type_token_ratio",
            "max_hub_size", "phase_entropy", "content_skewness", "self_reference_density"]

    fingerprints = {}
    with st.spinner("Computing fingerprints..."):
        for name, records in datasets.items():
            src = "swarmtraces" if name == "HF Intrusion" else "wiki"
            records_json = json.dumps(records[:50000], default=str)
            fingerprints[name] = compute_fingerprint_cached(records_json, src)

    all_vals = {name: [fp.get(k, 0) for k in keys] for name, fp in fingerprints.items()}
    maxvals = [max(max(abs(v[i]) for v in all_vals.values()), 0.001) for i in range(len(keys))]

    fig = go.Figure()
    for name, vals in all_vals.items():
        normed = [v / m for v, m in zip(vals, maxvals)]
        color = COLORS.get(name, "#FFE66D")
        fig.add_trace(go.Scatterpolar(
            r=normed + [normed[0]], theta=labels + [labels[0]],
            fill="toself", name=name,
            fillcolor=color.replace(")", ", 0.15)").replace("rgb", "rgba") if "rgb" in color
                      else f"{color}26",
            line=dict(color=color, width=2.5)))
    fig.update_layout(
        polar=dict(radialaxis=dict(visible=True, range=[0, 1.15])),
        template="plotly_white", height=520,
        legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5))

    col1, col2 = st.columns([3, 2])
    with col1:
        st.plotly_chart(fig, use_container_width=True)
    with col2:
        st.markdown("### Raw values")
        rows = []
        for i, key in enumerate(keys):
            row = {"Feature": key}
            for name, vals in all_vals.items():
                row[name] = round(vals[i], 4)
            rows.append(row)
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

        st.markdown("### What the numbers mean")
        st.markdown(
            "- **Self-reference > 0** means agents mention their own eval infrastructure. "
            "Both benign datasets scored 0%. The attack scored 12.4%.\n"
            "- **Phase entropy > 1.5** means activity spans multiple phases of a kill chain, "
            "not just one type.\n"
            "- **Crypto density > 5%** means agents use encoding and encryption operationally, "
            "which separates coordinated attacks from emergent copying.\n"
            "- **Vocabulary diversity > 0.05** means agents have real conversations "
            "rather than repeating templates."
        )

    st.markdown("---")
    st.markdown("### Drill into a feature")
    st.caption("Select a fingerprint dimension to see the underlying evidence.")
    feature_drill = st.selectbox("Feature to inspect", keys, index=4)

    if feature_drill == "phase_entropy":
        st.markdown("### Phase distribution behind the entropy score")
        for name, fp in fingerprints.items():
            counts = fp.get("phase_counts", {})
            if counts:
                st.markdown(f"**{name}:**")
                df = pd.DataFrame([{"Phase": k, "Count": v} for k, v in
                                   sorted(counts.items(), key=lambda x: -x[1])])
                st.dataframe(df, use_container_width=True, hide_index=True, height=200)

    elif feature_drill == "self_reference_density":
        st.markdown("### Sample records triggering self-reference detection")
        self_ref = re.compile(
            r"openai\.org|ace-research|REDACTED:runtime_identifier|"
            r"REDACTED:source_identifier|ExploitGym", re.I)
        for name, records in datasets.items():
            matches = [r for r in records[:50000] if self_ref.search(
                r.get("content", r.get("body", r.get("text", "")))[:3000])]
            if matches:
                st.markdown(f"**{name}** ({len(matches)} matches):")
                for m in matches[:3]:
                    text = m.get("content", m.get("body", m.get("text", "")))[:300]
                    st.code(text, language="text")
            else:
                st.markdown(f"**{name}**: no matches")

    elif feature_drill == "crypto_density":
        st.markdown("### Sample records with cryptographic patterns")
        crypto = re.compile(r"base64|gzip|DDSE1|Ed25519|RSA|HMAC|sha256|hashlib", re.I)
        for name, records in datasets.items():
            matches = [r for r in records[:20000] if crypto.search(
                r.get("content", r.get("body", r.get("text", "")))[:3000])]
            st.markdown(f"**{name}**: {len(matches)} records with crypto patterns")
            if matches:
                for m in matches[:2]:
                    text = m.get("content", m.get("body", m.get("text", "")))[:300]
                    st.code(text, language="text")

    st.caption(
        "`from src.fingerprint import compute_fingerprint` takes any list of records "
        "and returns these 7 values. Upload your own data through the sidebar to compare. "
        "[Source](https://github.com/rkstu/swarm-forensics/blob/main/src/fingerprint.py) · "
        "[Methodology](https://github.com/rkstu/swarm-forensics/blob/main/docs/METHODOLOGY.md)"
    )


# ---------------------------------------------------------------------------
# Tab 2: Information Spread
# ---------------------------------------------------------------------------
def render_propagation(datasets):
    st.markdown("## Information Propagation")
    st.markdown("How specific artifacts spread through the wiki swarm over time.")

    if "German Wiki" not in datasets:
        st.info("Select **German Wiki** in the sidebar. This analysis requires timestamped records.")
        return

    import sys; sys.path.insert(0, str(ROOT))
    from src.propagation import top_propagation_events, naming_epidemic_curves

    wiki_raw = load_wiki_raw()

    mode = st.radio("Analysis", ["URL Spread", "Naming Epidemics", "Activity Timeline"], horizontal=True)

    if mode == "URL Spread":
        n_urls = st.slider("Number of URLs to trace", 3, 15, 5)

        with st.spinner("Tracing URL propagation..."):
            top_urls = top_propagation_events(wiki_raw, n=n_urls)

        fig = go.Figure()
        colors = px.colors.qualitative.Set2
        for i, (url, info) in enumerate(top_urls):
            dates = sorted(info["cumulative_by_date"].keys())
            counts = [info["cumulative_by_date"][d] for d in dates]
            short = url.split("?")[0].split("/")[-1][:30] if "/" in url else url[:30]
            fig.add_trace(go.Scatter(
                x=dates, y=counts,
                name=f"{short}... ({info['total_pages']} pages)",
                mode="lines+markers",
                line=dict(width=2, color=colors[i % len(colors)])))
        fig.update_layout(
            title="How URLs spread across wiki pages over time",
            xaxis_title="Date", yaxis_title="Pages containing URL",
            template="plotly_white", height=450, hovermode="x unified")
        st.plotly_chart(fig, use_container_width=True)

        st.markdown("### Propagation details")
        for url, info in top_urls[:3]:
            with st.expander(f"{url[:80]}... → {info['total_pages']} pages"):
                fa = info["first_appearance"]
                st.markdown(f"**First seen:** {fa['date']} by agent `{fa['agent']}` on page `{fa['page']}`")
                st.markdown(f"**Total events:** {info['total_events']}")

    elif mode == "Naming Epidemics":
        with st.spinner("Computing naming curves..."):
            curves, dates = naming_epidemic_curves(wiki_raw)

        conventions = st.multiselect(
            "Conventions to track",
            list(curves.keys()),
            default=["OpenAI", "Helper", "Scout", "Agent"]
        )
        min_agents = st.slider("Minimum new agents per day", 5, 50, 10)

        colors_map = {"OpenAI": "#FF6B6B", "Helper": "#4ECDC4", "Scout": "#FFE66D",
                      "Agent": "#95E1D3", "Research": "#AA96DA", "Watcher": "#F38181",
                      "OAI": "#FF9A76", "Data": "#679B9B"}
        fig = go.Figure()
        for conv in conventions:
            curve = curves.get(conv, [])
            filtered = [c for c in curve if c["new_agents"] >= min_agents]
            if filtered:
                fig.add_trace(go.Scatter(
                    x=[c["date"] for c in filtered],
                    y=[c["share"] for c in filtered],
                    name=conv, mode="lines+markers",
                    line=dict(width=2, color=colors_map.get(conv, "#888"))))
        fig.update_layout(
            title="Naming convention adoption among new agents",
            xaxis_title="Date", yaxis_title="Share of new agents",
            yaxis=dict(tickformat=".0%"),
            template="plotly_white", height=450, hovermode="x unified")
        st.plotly_chart(fig, use_container_width=True)

    elif mode == "Activity Timeline":
        daily = Counter()
        daily_agents = defaultdict(set)
        for r in wiki_raw:
            d = r.get("time", "")[:10]
            if d:
                daily[d] += 1
                daily_agents[d].add(r.get("label", ""))

        dates_sorted = sorted(daily.keys())
        date_range = st.select_slider(
            "Date range",
            options=dates_sorted,
            value=(dates_sorted[0], dates_sorted[-1]))

        filtered_dates = [d for d in dates_sorted if date_range[0] <= d <= date_range[1]]
        fig = go.Figure()
        fig.add_trace(go.Bar(x=filtered_dates, y=[daily[d] for d in filtered_dates],
                             name="Edits", marker_color="#4ECDC4", opacity=0.7))
        fig.add_trace(go.Scatter(x=filtered_dates,
                                 y=[len(daily_agents[d]) for d in filtered_dates],
                                 name="Active Agents", line=dict(color="#FF6B6B", width=2),
                                 yaxis="y2"))
        fig.update_layout(
            yaxis=dict(title="Edits"), yaxis2=dict(title="Agents", overlaying="y", side="right"),
            template="plotly_white", height=400, hovermode="x unified")
        st.plotly_chart(fig, use_container_width=True)


# ---------------------------------------------------------------------------
# Tab 3: Attack Hierarchy
# ---------------------------------------------------------------------------
def render_attack_hierarchy(datasets):
    st.markdown("## Attack Hierarchy")
    st.markdown("The parent-child structure in SwarmTraces maps the C2 command hierarchy.")

    if "HF Intrusion" not in datasets:
        st.info("Select **HF Intrusion** in the sidebar.")
        return

    import sys; sys.path.insert(0, str(ROOT))
    from src.propagation import trace_hub_hierarchy, technique_taxonomy

    analysis_mode = st.radio("View", ["C2 Hubs", "Technique Taxonomy"], horizontal=True)

    traces = load_dataset("HF Intrusion")

    if analysis_mode == "C2 Hubs":
        with st.spinner("Analyzing hub hierarchy..."):
            hubs = trace_hub_hierarchy(traces)

        n_hubs = st.slider("Number of hubs to show", 3, 10, 5)
        for h in hubs[:n_hubs]:
            emoji = {"SSTI/RCE dropper": "🔴", "XSS/script injection": "🟠",
                     "C2 polling agent": "🟡", "HTTP exfiltration": "🟣",
                     "Payload decoder/dropper": "🔵"}.get(h["role"], "⚪")
            with st.expander(f"{emoji} **{h['id']}** — {h['role']} ({h['children']} children)", expanded=(h == hubs[0])):
                c1, c2 = st.columns([1, 1])
                c1.metric("Children", h["children"])
                c2.metric("Role", h["role"])
                st.code(h["content_preview"][:600], language="python")
                st.caption(f"Child types: {h['child_kinds']}")

    elif analysis_mode == "Technique Taxonomy":
        with st.spinner("Classifying techniques..."):
            tax = technique_taxonomy(traces)

        tech_df = pd.DataFrame([
            {"Technique": k.replace("_", " ").title(), "Count": v}
            for k, v in sorted(tax["technique_counts"].items(), key=lambda x: -x[1])
        ])
        fig = px.bar(tech_df, x="Count", y="Technique", orientation="h",
                     color="Count", color_continuous_scale="Reds")
        fig.update_layout(template="plotly_white", height=500, yaxis=dict(autorange="reversed"))
        st.plotly_chart(fig, use_container_width=True)

        multi = tax["multi_technique_distribution"]
        multi_count = sum(v for k, v in multi.items() if k > 1)
        c1, c2, c3 = st.columns(3)
        c1.metric("Total classified", f"{sum(tax['technique_counts'].values()):,}")
        c2.metric("Distinct techniques", len(tax['technique_counts']))
        c3.metric("Multi-technique payloads", f"{multi_count:,}")


# ---------------------------------------------------------------------------
# Tab 4: Detector Bench
# ---------------------------------------------------------------------------
def render_detector_bench(datasets):
    st.markdown("## Detector Bench")
    st.markdown(
        "Run published behavioral detectors on your selected datasets and compare what fires. "
        "When you include both a benign and an attack dataset, you can see the false positive rate."
    )

    if len(datasets) < 1:
        st.warning("Select at least one dataset.")
        return

    detector_choice = st.multiselect(
        "Detectors to run",
        ["All Elastic Signals", "Frank Coordination", "METR Attack Phases"],
        default=["All Elastic Signals"]
    )

    if st.button("Run detectors", type="primary"):
        results = {}
        for name, records in datasets.items():
            with st.spinner(f"Running on {name} ({len(records):,} records)..."):
                result = {"name": name, "count": len(records)}
                if "All Elastic Signals" in detector_choice:
                    elastic = run_elastic_on(records)
                    result["elastic"] = elastic
                    result["elastic_count"] = len(elastic)
                if "Frank Coordination" in detector_choice:
                    frank = run_frank_on(records)
                    result["frank"] = frank
                if "METR Attack Phases" in detector_choice:
                    metr = run_metr_on(records)
                    result["metr"] = metr
                results[name] = result

        if "All Elastic Signals" in detector_choice:
            st.markdown("### Elastic Signal Comparison")
            signal_names = ["retry_succeeded", "benchmark_strings", "hallucinated_commands",
                            "poor_opsec", "self_referential_search", "pointless_commands"]
            rows = []
            for sig in signal_names:
                row = {"Signal": sig}
                for name, res in results.items():
                    hit = False
                    for f in res.get("elastic", []):
                        if f.get("signal") == sig:
                            hit = True
                            count = f.get("count", f.get("total_matches", f.get("total_records",
                                    f.get("records_with_errors", f.get("unique_repeated", "?")))))
                            row[name] = count
                    if not hit:
                        row[name] = 0
                rows.append(row)
            df = pd.DataFrame(rows)
            st.dataframe(df, use_container_width=True, hide_index=True)

            if len(results) >= 2:
                st.markdown("### Precision (if benign + attack datasets selected)")
                st.caption(
                    "Precision = TP / (TP + FP). Assumes the first dataset is benign, "
                    "the last is attack. Adjust your selection to change the comparison."
                )

        if "Frank Coordination" in detector_choice:
            st.markdown("### Frank Definition 1 Assessment")
            for name, res in results.items():
                frank = res.get("frank", {})
                detected = frank.get("unsanctioned_coordination_detected", False)
                icon = "🔴" if detected else "🟢"
                st.markdown(f"{icon} **{name}**: Coordination {'DETECTED' if detected else 'not detected'}")
                st.caption(f"  Influence: {frank.get('criterion_a_influence')}, "
                          f"Conventions: {frank.get('criterion_b_conventions')}")

        if "METR Attack Phases" in detector_choice:
            st.markdown("### Attack Phase Classification")
            for name, res in results.items():
                for m in res.get("metr", []):
                    if "phase_counts" in m:
                        st.markdown(f"**{name}:**")
                        phase_df = pd.DataFrame([
                            {"Phase": k, "Count": v}
                            for k, v in sorted(m["phase_counts"].items(), key=lambda x: -x[1])
                        ])
                        st.dataframe(phase_df, use_container_width=True, hide_index=True, height=250)


# ---------------------------------------------------------------------------
# Tab 5: Record Explorer
# ---------------------------------------------------------------------------
def render_explorer(datasets):
    st.markdown("## Record Explorer")

    if not datasets:
        st.warning("Select at least one dataset.")
        return

    dataset_name = st.selectbox("Dataset", list(datasets.keys()))
    records = datasets[dataset_name]

    col1, col2, col3 = st.columns(3)
    col1.metric("Records", f"{len(records):,}")
    agents = set(r.get("agent_id") or r.get("label") for r in records
                 if r.get("agent_id") or r.get("label"))
    col2.metric("Agents", f"{len(agents):,}")
    with_time = sum(1 for r in records if r.get("timestamp") or r.get("time"))
    col3.metric("With timestamp", f"{with_time:,}")

    st.markdown("---")
    search_mode = st.radio("Mode", ["Search content", "Browse agents", "Filter by signal"], horizontal=True)

    if search_mode == "Search content":
        query = st.text_input("Search (regex)", placeholder="e.g. subprocess|exec\\(")
        max_results = st.slider("Max results", 10, 200, 50)

        if query:
            try:
                pat = re.compile(query, re.I)
                matched = []
                for r in records[:100000]:
                    text = r.get("content", r.get("body", r.get("text", "")))
                    if pat.search(text[:5000]):
                        matched.append(r)
                    if len(matched) >= max_results:
                        break

                st.markdown(f"**{len(matched)}** matches")
                for r in matched:
                    rid = r.get("id", r.get("rev_id", "?"))
                    agent = r.get("agent_id", r.get("label", "?"))
                    text = r.get("content", r.get("body", r.get("text", "")))[:500]
                    with st.expander(f"{rid} — agent: {agent}"):
                        st.code(text, language="text")
            except re.error:
                st.error("Invalid regex")

    elif search_mode == "Browse agents":
        agent_edits = Counter()
        for r in records:
            a = r.get("agent_id") or r.get("label")
            if a:
                agent_edits[a] += 1

        agent_list = [a for a, _ in agent_edits.most_common(500)]
        selected_agent = st.selectbox(
            f"Agent ({len(agent_edits)} total, showing top 500)",
            agent_list,
            format_func=lambda a: f"{a} ({agent_edits[a]} records)")

        if selected_agent:
            agent_records = [r for r in records if (r.get("agent_id") or r.get("label")) == selected_agent]
            st.metric("Records by this agent", len(agent_records))

            for r in agent_records[:20]:
                text = r.get("content", r.get("body", r.get("text", "")))[:300]
                time = r.get("timestamp", r.get("time", ""))
                if time:
                    time = str(time)[:19]
                with st.expander(f"{time} — {text[:60]}..."):
                    st.code(text, language="text")

    elif search_mode == "Filter by signal":
        signal = st.selectbox("Elastic signal", [
            "benchmark_strings", "hallucinated_commands", "poor_opsec",
            "retry_succeeded", "self_referential_search", "pointless_commands"
        ])

        SIGNAL_PATTERNS = {
            "benchmark_strings": re.compile(r"score|grading|evaluation|benchmark|task_id|ExploitGym", re.I),
            "hallucinated_commands": re.compile(r"command not found|No such file|syntax error", re.I),
            "poor_opsec": re.compile(r"hf_[A-Za-z0-9]{10,}|Bearer\s+[A-Za-z0-9]+|API[_-]?KEY|CREDENTIAL", re.I),
            "retry_succeeded": None,
            "self_referential_search": re.compile(r"openai\.org|REDACTED:runtime_identifier|ExploitGym", re.I),
            "pointless_commands": None,
        }

        pat = SIGNAL_PATTERNS.get(signal)
        if pat:
            matched = [r for r in records[:50000]
                       if pat.search(r.get("content", r.get("body", r.get("text", "")))[:3000])]
            st.markdown(f"**{len(matched)}** records trigger `{signal}`")
            for r in matched[:30]:
                text = r.get("content", r.get("body", r.get("text", "")))[:400]
                with st.expander(f"{r.get('id', '?')}"):
                    st.code(text, language="text")
        else:
            st.info(f"Pattern-level drill-down not available for {signal}. Use content search instead.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    st.markdown(
        "<h1 style='text-align:center;'>🔬 SwarmScope</h1>"
        "<p style='text-align:center;color:#666;font-size:1.1em;'>"
        "Cross-incident forensic workbench for AI agent swarms</p>"
        "<p style='text-align:center;color:#999;font-size:0.9em;'>"
        "Select datasets in the sidebar, upload your own, or run detectors. "
        "Every finding traces to a published source.</p>",
        unsafe_allow_html=True)

    datasets = sidebar()

    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🎯 Fingerprint",
        "🌊 Information Spread",
        "⚔️ Attack Hierarchy",
        "🔍 Detector Bench",
        "📋 Record Explorer",
    ])

    with tab1:
        render_fingerprint(datasets)
    with tab2:
        render_propagation(datasets)
    with tab3:
        render_attack_hierarchy(datasets)
    with tab4:
        render_detector_bench(datasets)
    with tab5:
        render_explorer(datasets)

    st.markdown("---")
    st.markdown(
        "<p style='text-align:center;'>"
        "<a href='https://github.com/rkstu/swarm-forensics'>GitHub</a> · "
        "<a href='https://github.com/rkstu/swarm-forensics/blob/main/docs/WRITEUP.md'>Write-up</a> · "
        "<a href='https://github.com/rkstu/swarm-forensics/blob/main/docs/METHODOLOGY.md'>Methodology</a> · "
        "<a href='https://github.com/rkstu/swarm-forensics/blob/main/docs/GETTING_STARTED.md'>Getting Started</a>"
        "</p>",
        unsafe_allow_html=True)
    st.caption(
        "Grounded in: De Marzo et al. (2609.09150), Frank (2609.06140), "
        "Elastic Security Labs (2026), METR (2026), Pacheco et al. (2001.05658). "
        "Data: collusion.wiki · aidigestorg/ai-village · swarmtraces.org"
    )


if __name__ == "__main__":
    main()
