"""Communication graph builder for multi-agent transcripts.

Builds agent-interaction graphs from wiki edit histories using co-editing
relationships. Methodology adapted from Pacheco et al. (2001.05658,
244 citations) on network-based coordination detection.

For collusion.wiki: agents are nodes, shared page edits are edges.
For SwarmTraces: payload chains (parent-child) form the graph.
"""
import json
from collections import defaultdict
from pathlib import Path

try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False

try:
    import plotly.graph_objects as go
    HAS_PLOTLY = True
except ImportError:
    HAS_PLOTLY = False


def build_wiki_graph(records):
    """Build co-editing graph from wiki revisions.

    Nodes = agents, edges = shared page edits.
    Edge weight = number of pages co-edited.
    """
    if not HAS_NETWORKX:
        return None, {"error": "networkx not installed"}

    page_editors = defaultdict(set)
    agent_edits = defaultdict(int)
    for r in records:
        if r["agent_id"] and r["page_id"]:
            page_editors[r["page_id"]].add(r["agent_id"])
            agent_edits[r["agent_id"]] += 1

    G = nx.Graph()
    for agent, count in agent_edits.items():
        G.add_node(agent, edit_count=count)

    edge_weights = defaultdict(int)
    for page_id, editors in page_editors.items():
        editors = list(editors)
        for i in range(len(editors)):
            for j in range(i + 1, len(editors)):
                pair = tuple(sorted([editors[i], editors[j]]))
                edge_weights[pair] += 1

    for (a, b), weight in edge_weights.items():
        G.add_edge(a, b, weight=weight)

    stats = {
        "nodes": G.number_of_nodes(),
        "edges": G.number_of_edges(),
        "density": nx.density(G),
        "components": nx.number_connected_components(G),
    }

    if G.number_of_nodes() > 0:
        largest_cc = max(nx.connected_components(G), key=len)
        stats["largest_component_size"] = len(largest_cc)
        stats["largest_component_fraction"] = len(largest_cc) / G.number_of_nodes()

        degree_centrality = nx.degree_centrality(G)
        top_agents = sorted(degree_centrality.items(), key=lambda x: -x[1])[:10]
        stats["top_agents_by_degree"] = [
            {"agent": a, "degree_centrality": round(c, 4), "edits": agent_edits[a]}
            for a, c in top_agents
        ]

    return G, stats


def build_swarmtraces_graph(records):
    """Build payload-chain graph from SwarmTraces.

    Nodes = payloads, edges = parent-child relationships.
    """
    if not HAS_NETWORKX:
        return None, {"error": "networkx not installed"}

    G = nx.DiGraph()
    for r in records:
        G.add_node(r["id"], kind=r["action_type"], content_len=r["content_len"])
        if r["page_id"]:
            G.add_edge(r["page_id"], r["id"])

    stats = {
        "nodes": G.number_of_nodes(),
        "edges": G.number_of_edges(),
        "records_with_parent": sum(1 for r in records if r["page_id"]),
        "orphan_records": sum(1 for r in records if not r["page_id"]),
    }

    if G.number_of_edges() > 0:
        weakly_connected = list(nx.weakly_connected_components(G))
        stats["components"] = len(weakly_connected)
        stats["largest_component_size"] = max(len(c) for c in weakly_connected)

    return G, stats


def visualize_wiki_graph(G, stats, output_path):
    """Generate interactive HTML visualization of the wiki co-editing graph."""
    if not HAS_PLOTLY or G is None:
        return

    pos = nx.spring_layout(G, k=0.3, iterations=50, seed=42)

    edge_x, edge_y = [], []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y, mode="lines",
        line=dict(width=0.3, color="#888"),
        hoverinfo="none",
    )

    node_x = [pos[n][0] for n in G.nodes()]
    node_y = [pos[n][1] for n in G.nodes()]
    node_size = [min(G.nodes[n].get("edit_count", 1) * 2, 30) for n in G.nodes()]
    node_color = [G.degree(n) for n in G.nodes()]
    node_text = [f"{n}<br>edits: {G.nodes[n].get('edit_count', 0)}<br>connections: {G.degree(n)}"
                 for n in G.nodes()]

    node_trace = go.Scatter(
        x=node_x, y=node_y, mode="markers",
        hoverinfo="text", text=node_text,
        marker=dict(
            size=node_size, color=node_color,
            colorscale="Viridis", showscale=True,
            colorbar=dict(title="Connections"),
            line=dict(width=0.5, color="#333"),
        ),
    )

    fig = go.Figure(
        data=[edge_trace, node_trace],
        layout=go.Layout(
            title=f"Agent Co-editing Network (collusion.wiki)<br>"
                  f"<sub>{stats['nodes']} agents, {stats['edges']} co-editing relationships</sub>",
            showlegend=False,
            hovermode="closest",
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            template="plotly_white",
        ),
    )
    fig.write_html(str(output_path))
    print(f"Graph visualization written to {output_path}")


def main():
    from src.parser import load_wiki_revisions, load_swarmtraces

    results_dir = Path(__file__).resolve().parent.parent / "results"
    results_dir.mkdir(exist_ok=True)

    print("Building wiki co-editing graph...")
    wiki_records = load_wiki_revisions()
    G_wiki, wiki_stats = build_wiki_graph(wiki_records)
    print(f"  {wiki_stats['nodes']} agents, {wiki_stats['edges']} co-editing links")
    print(f"  {wiki_stats.get('components', 'N/A')} components, "
          f"largest: {wiki_stats.get('largest_component_fraction', 0):.1%}")
    if wiki_stats.get("top_agents_by_degree"):
        print("  Top agents by degree centrality:")
        for a in wiki_stats["top_agents_by_degree"][:5]:
            print(f"    {a['agent']}: centrality={a['degree_centrality']}, edits={a['edits']}")

    if HAS_PLOTLY and G_wiki:
        visualize_wiki_graph(G_wiki, wiki_stats, results_dir / "wiki_graph.html")

    print("\nBuilding SwarmTraces payload graph...")
    traces_records = load_swarmtraces()
    G_traces, traces_stats = build_swarmtraces_graph(traces_records)
    print(f"  {traces_stats['nodes']} records, {traces_stats['edges']} parent-child links")
    print(f"  {traces_stats.get('orphan_records', 0)} orphan records")

    graph_report = {
        "wiki_graph": wiki_stats,
        "swarmtraces_graph": traces_stats,
        "methodology": "Pacheco et al. (2001.05658): network-based coordination detection",
    }
    with open(results_dir / "graph_stats.json", "w") as fh:
        json.dump(graph_report, fh, indent=2, default=str)

    return graph_report


if __name__ == "__main__":
    main()
