# Getting Started

## What this does

SwarmScope computes a coordination fingerprint on multi-agent transcripts and compares it against three reference incidents: benign copying (German wiki), intentional cooperation (AI Village), and a real cyber attack (HuggingFace intrusion). You can upload your own data and see where it falls.

![Upload your own data](../screenshots/upload_custom.png)
*Upload any JSONL file through the sidebar. The tool parses it, fingerprints it, and compares against the reference datasets.*

## Setup

```bash
git clone --recurse-submodules https://github.com/rkstu/swarm-forensics.git
cd swarm-forensics
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

Open http://localhost:8501. The sidebar lets you select reference datasets and upload your own files.

## Your own data

Upload any JSONL file (one JSON object per line). The parser looks for these fields and uses whichever it finds:

| What | Field names we look for |
|------|------------------------|
| Content | `body`, `text`, `content` |
| Agent ID | `label`, `agent_id`, `agent_speaker_id` |
| Timestamp | `time`, `timestamp`, `created_at` |
| Context | `page_id`, `parent_id`, `room_id` |

Only the content field matters for the fingerprint. Everything else improves the analysis if present.

Example record:
```json
{"id": "001", "label": "AgentName", "time": "2026-01-15T10:00:00Z", "body": "the agent's output text", "page_id": "some_page"}
```

## Using the fingerprint in your own code

```python
from src.fingerprint import compute_fingerprint

records = [{"body": "...", "label": "agent1", "time": "..."}, ...]
fp = compute_fingerprint(records, source="auto")
```

Returns a dict with 7 features. Compare the values against the reference table in the README to interpret where your data falls.

## Building on this

Each module works independently:

```python
from external.elastic_signals import run_all
findings = run_all(records)  # returns list of signal hits

from external.frank_episodes import run_all
assessment = run_all(records)  # returns coordination assessment

from src.propagation import trace_hub_hierarchy
hubs = trace_hub_hierarchy(records)  # returns top parent nodes
```

Source code, methodology details, and the full evidence chain are at [github.com/rkstu/swarm-forensics](https://github.com/rkstu/swarm-forensics).
