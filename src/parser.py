"""Parse collusion.wiki and SwarmTraces into a common schema.

The common schema normalizes both datasets so detectors can run on either.
Each record becomes:

    {
        "id": str,              # unique record identifier
        "source": str,          # "collusion-wiki" or "swarmtraces"
        "agent_id": str | None, # agent handle / identifier
        "timestamp": str | None,# ISO 8601
        "action_type": str,     # "edit", "payload", "response", "recovered_text"
        "content": str,         # body text or payload text
        "content_len": int,
        "page_id": str | None,  # page or parent reference
        "metadata": dict,       # source-specific fields
    }
"""
import gzip
import json
import os
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data"


def load_wiki_revisions(path=None):
    path = path or DATA / "collusion-wiki" / "revisions.jsonl"
    records = []
    with open(path) as fh:
        for line in fh:
            r = json.loads(line)
            records.append({
                "id": r["rev_id"],
                "source": "collusion-wiki",
                "agent_id": r.get("label"),
                "timestamp": r.get("time"),
                "action_type": "edit",
                "content": r.get("body", ""),
                "content_len": r.get("body_len", 0),
                "page_id": r.get("page_id"),
                "metadata": {
                    "wiki": r.get("wiki"),
                    "page_name": r.get("name"),
                    "seq": r.get("seq"),
                    "ip16": r.get("ip16"),
                    "hunks": r.get("hunks", []),
                    "body_sha256": r.get("body_sha256"),
                },
            })
    return records


def load_wiki_pages(path=None):
    path = path or DATA / "collusion-wiki" / "pages.jsonl"
    pages = {}
    with open(path) as fh:
        for line in fh:
            p = json.loads(line)
            pages[p.get("page_id", p.get("page_key"))] = p
    return pages


def load_swarmtraces(path=None):
    path = path or DATA / "swarmtraces" / "redacted.jsonl"
    records = []
    with open(path) as fh:
        for line in fh:
            r = json.loads(line)
            records.append({
                "id": r["id"],
                "source": "swarmtraces",
                "agent_id": None,
                "timestamp": r.get("time_utc"),
                "action_type": r.get("kind", "payload"),
                "content": r.get("text", ""),
                "content_len": len(r.get("text", "")),
                "page_id": r.get("parent_id"),
                "metadata": {
                    "cite": r.get("cite"),
                    "tags": r.get("tags", ""),
                },
            })
    return records


def load_ai_village_chat(path=None):
    path = path or DATA / "ai-village" / "chat_messages.jsonl"
    if not path.exists():
        return []
    records = []
    with open(path) as fh:
        for line in fh:
            r = json.loads(line)
            records.append({
                "id": r.get("id", ""),
                "source": "ai-village",
                "agent_id": r.get("agent_speaker_id"),
                "timestamp": r.get("created_at"),
                "action_type": "chat" if r.get("speaker_type") == "agent" else "user_chat",
                "content": r.get("content", ""),
                "content_len": len(r.get("content", "")),
                "page_id": r.get("room_id"),
                "metadata": {
                    "speaker_type": r.get("speaker_type"),
                },
            })
    return records


def load_all():
    wiki = load_wiki_revisions()
    traces = load_swarmtraces()
    result = {"collusion-wiki": wiki, "swarmtraces": traces}
    village = load_ai_village_chat()
    if village:
        result["ai-village"] = village
    return result


def summary(records):
    by_source = {}
    for r in records:
        src = r["source"]
        if src not in by_source:
            by_source[src] = {"total": 0, "agents": set(), "action_types": {}}
        by_source[src]["total"] += 1
        if r["agent_id"]:
            by_source[src]["agents"].add(r["agent_id"])
        at = r["action_type"]
        by_source[src]["action_types"][at] = by_source[src]["action_types"].get(at, 0) + 1

    out = {}
    for src, s in by_source.items():
        out[src] = {
            "total_records": s["total"],
            "unique_agents": len(s["agents"]),
            "action_types": s["action_types"],
        }
    return out


if __name__ == "__main__":
    data = load_all()
    for src, recs in data.items():
        s = summary(recs)
        print(f"\n{src}: {s[src]['total_records']} records, "
              f"{s[src]['unique_agents']} agents")
        for at, count in s[src]["action_types"].items():
            print(f"  {at}: {count}")
