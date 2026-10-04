"""Information propagation tracing across agent swarms.

Traces how specific information artifacts (URLs, naming conventions,
content templates) spread through the wiki swarm, and maps the C2
hierarchy in SwarmTraces.
"""
import re
from collections import Counter, defaultdict
from datetime import datetime

URL_RE = re.compile(r"https?://[^\s\]\)|<>\"'}\)]+")

NAME_CONVENTIONS = {
    "OpenAI": re.compile(r"Open(AI)?", re.I),
    "Scout": re.compile(r"Scout"),
    "Helper": re.compile(r"Helper"),
    "Watcher": re.compile(r"Watch"),
    "Agent": re.compile(r"Agent"),
    "Research": re.compile(r"Research"),
    "OAI": re.compile(r"OAI"),
    "Data": re.compile(r"Data"),
}


def trace_url_propagation(records):
    """Trace URL spread across wiki pages over time.

    For each URL, tracks: first page, first agent, first time,
    and cumulative page count over time.
    """
    url_history = defaultdict(list)
    for r in records:
        body = r.get("body", r.get("content", ""))
        time = r.get("time", "")[:10]
        page = r.get("page_id", r.get("name", ""))
        agent = r.get("label", r.get("agent_id", ""))

        for url in URL_RE.findall(body):
            url_clean = url.rstrip(".,;:")
            url_history[url_clean].append({
                "page": page, "agent": agent, "date": time,
            })

    propagation = {}
    for url, events in url_history.items():
        pages = set()
        daily_spread = defaultdict(set)
        first = None
        for e in sorted(events, key=lambda x: x["date"]):
            if not first:
                first = e
            pages.add(e["page"])
            daily_spread[e["date"]].add(e["page"])

        if len(pages) >= 5:
            cumulative = {}
            running = set()
            for date in sorted(daily_spread.keys()):
                running |= daily_spread[date]
                cumulative[date] = len(running)

            propagation[url] = {
                "total_pages": len(pages),
                "first_appearance": first,
                "cumulative_by_date": cumulative,
                "total_events": len(events),
            }

    return propagation


def top_propagation_events(records, n=10):
    """Return the N URLs that spread to the most pages."""
    prop = trace_url_propagation(records)
    sorted_urls = sorted(prop.items(), key=lambda x: -x[1]["total_pages"])
    return sorted_urls[:n]


def naming_epidemic_curves(records):
    """Trace naming convention adoption over time.

    Returns daily counts and shares for each naming convention
    among newly-appearing agents.
    """
    agent_first_date = {}
    for r in records:
        agent = r.get("label", r.get("agent_id", ""))
        date = r.get("time", r.get("timestamp", ""))
        if date:
            date = date[:10]
        if agent and date:
            if agent not in agent_first_date or date < agent_first_date[agent]:
                agent_first_date[agent] = date

    daily_new = defaultdict(list)
    for agent, date in agent_first_date.items():
        daily_new[date].append(agent)

    curves = {}
    dates = sorted(daily_new.keys())

    for conv_name, conv_re in NAME_CONVENTIONS.items():
        curve = []
        for date in dates:
            new_agents = daily_new[date]
            total = len(new_agents)
            matches = sum(1 for a in new_agents if conv_re.search(a))
            if total > 0:
                curve.append({
                    "date": date,
                    "new_agents": total,
                    "convention_count": matches,
                    "share": round(matches / max(total, 1), 4),
                })
        curves[conv_name] = curve

    return curves, dates


def content_duplication_analysis(records):
    """Identify content that was copied across multiple pages."""
    hash_pages = defaultdict(set)
    hash_sample = {}
    for r in records:
        h = r.get("body_sha256", r.get("metadata", {}).get("body_sha256"))
        if h:
            page = r.get("page_id", r.get("name", ""))
            hash_pages[h].add(page)
            if h not in hash_sample:
                body = r.get("body", r.get("content", ""))[:200]
                hash_sample[h] = body

    duplicated = {
        h: {"pages": len(pages), "sample": hash_sample.get(h, "")}
        for h, pages in hash_pages.items()
        if len(pages) >= 2
    }
    return dict(sorted(duplicated.items(), key=lambda x: -x[1]["pages"])[:20])


def trace_hub_hierarchy(records):
    """Identify C2 hierarchy in SwarmTraces from parent-child structure.

    Returns top hub parents with content analysis and role classification.
    """
    children_map = defaultdict(list)
    record_by_id = {}
    for r in records:
        record_by_id[r.get("id", r.get("rev_id", ""))] = r
        pid = r.get("parent_id", r.get("page_id"))
        if pid:
            children_map[pid].append(r.get("id", r.get("rev_id", "")))

    child_counts = {pid: len(kids) for pid, kids in children_map.items()}
    top_hubs = sorted(child_counts.items(), key=lambda x: -x[1])[:10]

    hubs = []
    for pid, count in top_hubs:
        parent = record_by_id.get(pid, {})
        text = parent.get("text", parent.get("body", parent.get("content", "")))[:500]

        role = "unknown"
        if re.search(r"cycler\.__init__|__globals__|exec\(", text, re.I):
            role = "SSTI/RCE dropper"
        elif re.search(r"<script|<img.*src=|document\.", text, re.I):
            role = "XSS/script injection"
        elif re.search(r"subprocess|urllib\.request|cmd\.txt", text, re.I):
            role = "C2 polling agent"
        elif re.search(r"fetch\(|XMLHttpRequest", text, re.I):
            role = "HTTP exfiltration"
        elif re.search(r"import.*base64.*gzip|gzip\.decompress", text, re.I):
            role = "Payload decoder/dropper"

        child_kinds = Counter()
        for cid in children_map[pid]:
            child = record_by_id.get(cid, {})
            child_kinds[child.get("kind", child.get("action_type", "unknown"))] += 1

        hubs.append({
            "id": pid,
            "children": count,
            "kind": parent.get("kind", parent.get("action_type", "unknown")),
            "role": role,
            "content_preview": text[:300],
            "child_kinds": dict(child_kinds),
            "tags": parent.get("tags", parent.get("metadata", {}).get("tags", "")),
        })

    return hubs


def technique_taxonomy(records):
    """Classify SwarmTraces payloads into attack techniques.

    Returns counts per technique and multi-technique composition stats.
    """
    TECHNIQUES = {
        "base64_encoding": re.compile(r"base64|b64decode|b64encode|atob|btoa", re.I),
        "xss_injection": re.compile(r"<script|document\.write|innerHTML|onclick", re.I),
        "file_dropper": re.compile(r"open\(.*['\"]w['\"]|writeFile|fs\.write", re.I),
        "http_exfil": re.compile(r"fetch\(|urlopen|XMLHttpRequest|urllib\.request", re.I),
        "python_exec": re.compile(r"exec\(|eval\(|os\.system|subprocess", re.I),
        "image_beacon": re.compile(r"new Image\(\)|<img.*src=.*\?", re.I),
        "credential_harvest": re.compile(r"CREDENTIAL|Bearer|api[_-]?key|token", re.I),
        "env_enumeration": re.compile(r"\benv\b|\bid\b.*\buname\b|/proc/self/environ", re.I),
        "ssti": re.compile(r"cycler\.__init__|__globals__|Jinja2", re.I),
        "k8s_enum": re.compile(r"kubernetes|kubectl|serviceaccount|kube-system", re.I),
        "tailscale": re.compile(r"tailscale|tskey-auth", re.I),
        "container_escape": re.compile(r"chroot|/proc/1/root|nsenter|hostPID", re.I),
        "reverse_shell": re.compile(r"reverse.*shell|/bin/bash.*-i|nc\s+-e", re.I),
        "supply_chain": re.compile(r"git clone|pip install|setup\.py|pypi", re.I),
        "dns_exfil": re.compile(r"dns.*exfil|dig\s+|nslookup\s+.*\.", re.I),
    }

    counts = Counter()
    multi_technique = Counter()
    for r in records:
        text = r.get("text", r.get("body", r.get("content", "")))[:5000]
        matched = []
        for tech, pat in TECHNIQUES.items():
            if pat.search(text):
                counts[tech] += 1
                matched.append(tech)
        multi_technique[len(matched)] += 1

    return {
        "technique_counts": dict(counts),
        "multi_technique_distribution": dict(multi_technique),
        "total_classified": sum(1 for c in multi_technique.keys() if c > 0),
    }
