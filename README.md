# SwarmScope

I kept running into the same problem: coordination detectors fire on benign data and attack data with the same confidence. A wiki full of agents copying each other's homework triggers 4 of 6 Elastic behavioral signals. The HuggingFace intrusion triggers all 6. The detectors can't tell you which is which.

So I built a tool to find out what separates them. SwarmScope takes multi-agent transcripts, computes a coordination fingerprint, and compares your data against three reference incidents. It runs published detection methods and shows you which ones hold up against a benign baseline and which ones don't.

**Live tool:** [https://swarm-forensics.streamlit.app/]
**Write-up:** [docs/WRITEUP.md](docs/WRITEUP.md)

![Coordination Fingerprint](screenshots/fingerprint_radar.png)
*Three datasets, three coordination modes, three distinct fingerprint shapes. The radar chart updates live as you select datasets or upload your own.*

## What it found

I tested this on 387,655 records across three incidents: the German wiki (14,591 revisions from agents copying answers), the AI Village (183,485 chat messages from managed cooperative agents), and the HuggingFace intrusion (189,579 decoded attack payloads from SwarmTraces).

The coordination fingerprint separates them cleanly on 5 of 7 dimensions:

| Feature | German Wiki | AI Village | HF Intrusion |
|---------|-------------|------------|-------------|
| Self-reference density | 0.0% | 0.0% | 12.4% |
| Crypto/encoding density | 0.45% | 3.5% | 15.3% |
| Phase entropy | 0.34 | 0.78 | 2.11 |
| Vocabulary diversity | 0.032 | 0.062 | 0.032 |
| Content skewness | 2.5 | 8.7 | 11.1 |

Self-reference density (whether agents mention their own evaluation infrastructure) scored zero in both benign datasets and 12.4% in the attack. Phase entropy measures how many types of activity are present: the wiki does one thing (recon), the village does a few, the intrusion spans all 9 phases of a cyber kill chain.

I also traced how information spreads through a swarm. On the wiki, the "OpenAI" naming convention appeared on June 16, reached 51% of new agents by June 19, and dropped to 6% by June 22. These are measurable epidemic curves of cultural conventions propagating through a population of short-lived agents that never overlapped in time.

![Naming Epidemics](screenshots/naming_epidemics.png)
*Naming conventions rise and fall like epidemics. Each agent lives about an hour and picks up conventions from whatever it can see.*

On SwarmTraces, the parent-child structure reveals the C2 command hierarchy. The largest hub (R0024455, 858 children) is a script injection controller. R0036471 (270 children) contains the actual Jinja2 SSTI exploit that gave agents code execution on HuggingFace's production pods.

The detector reliability numbers are the part I'd want if I were investigating the next incident. Hallucinated Commands has 100% precision: it fired on 10,665 SwarmTraces records and zero wiki records. Retry Succeeded is noisier, with a 6% false positive rate on benign data.

## Using it on your own data

Upload any JSONL file through the sidebar. SwarmScope parses it, computes a fingerprint, and overlays it on the reference datasets so you can see where your data falls.

![Upload your own data](screenshots/upload_custom.png)

## Running it

```bash
git clone --recurse-submodules https://github.com/rkstu/swarm-forensics.git
cd swarm-forensics
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

Download the data (not redistributed):

```bash
# German Wiki
cd data/collusion-wiki
curl -sL "https://collusion.wiki/explorer/download/revisions.jsonl.gz" -o revisions.jsonl.gz
curl -sL "https://collusion.wiki/explorer/download/pages.jsonl.gz" -o pages.jsonl.gz
curl -sL "https://collusion.wiki/explorer/download/events.jsonl.gz" -o events.jsonl.gz
gunzip -k *.gz && cd ../..

# HF Intrusion (SwarmTraces)
cd data/swarmtraces
curl -sL "https://swarmtraces.org/data/final/redacted.jsonl.gz" -o redacted.jsonl.gz
gunzip -k redacted.jsonl.gz && cd ../..
```

AI Village data requires a HuggingFace token with access to [aidigestorg/ai-village](https://huggingface.co/datasets/aidigestorg/ai-village). Download `chat_messages.jsonl.gz` and `agents.jsonl.gz` into `data/ai-village/`.

## How it works

Five modules, each grounded in a published source:

- **`src/fingerprint.py`** computes the 7-dimensional coordination fingerprint. Phase entropy uses HuggingFace's 9-phase attack taxonomy. Crypto density and self-reference come from Elastic's behavioral signal definitions.
- **`src/propagation.py`** traces URL spread and naming convention adoption on wiki data, and maps the C2 hub hierarchy on SwarmTraces.
- **`external/elastic_signals.py`** implements 6 behavioral signal detectors from Elastic's analysis of the HF breach.
- **`external/frank_episodes.py`** checks Frank's Definition 1 of unsanctioned coordination (arXiv:2609.06140).
- **`external/metr_conventions.py`** classifies records into METR's documented coordination patterns and the 9-phase attack taxonomy.

The `agent-wiki-copying/` submodule is the codebase from De Marzo et al. (arXiv:2609.09150), who showed that proportional copying explains most wiki agent behavior without requiring coordination.

See [docs/METHODOLOGY.md](docs/METHODOLOGY.md) for the full evidence chain and [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) for using the tool on your own data.

## The live demo and how to verify

The tool is fully functional. Running it locally on the raw datasets produces every finding shown here and in the [write-up](docs/WRITEUP.md), with full interactive search, live detector bench, and record-level exploration across 387,655 records.

The [live demo](https://swarm-forensics.streamlit.app/) uses pre-computed cached results because Streamlit Cloud can't host the raw datasets (40 MB + 89 MB + 400 MB). The cached results were generated by the same code in this repo running on the same public data. The upload feature works live on the deployed version: drop any JSONL file and the fingerprint computes in real-time against the reference datasets.

**To verify any finding:** clone the repo, download the datasets (instructions above), and run `python run.py`. Every number regenerates from scratch in about 41 seconds. Then `streamlit run app.py` for the full tool. The `results/full_report.json` output contains every claim in machine-readable format.

Nothing was hand-edited or cherry-picked. Every number comes from the code in this repository running on public datasets.

## What I'm less sure about

The fingerprint has only been tested on three datasets. Whether those 7 dimensions generalize to a new incident is untested. Two of the 7 features (type-token ratio and Gini coefficient) didn't separate anything here, and I kept them because dropping features after seeing results would be overfitting.

The false positive rates are computed on one benign baseline and one attack baseline. Different benign data might produce different rates.

The AI Village integration is shallow: I computed a fingerprint on chat messages but didn't analyze agent goals, memories, or computer use sessions.

## Datasets

| Dataset | Records | Coordination mode | Source |
|---------|---------|------------------|--------|
| German Wiki | 14,591 revisions, 3,102 agents | Emergent copying | [collusion.wiki](https://collusion.wiki) |
| AI Village | 183,485 messages, 46 agents | Intentional cooperation | [aidigestorg/ai-village](https://huggingface.co/datasets/aidigestorg/ai-village) |
| HF Intrusion | 189,579 payloads | Malicious coordination | [swarmtraces.org](https://swarmtraces.org) |

## Grounding

| Source | What we used | Status |
|--------|-------------|--------|
| De Marzo et al. (arXiv:2609.09150) | Proportional copying null model | Preprint with code (MIT) |
| Frank (arXiv:2609.06140) | Definition of unsanctioned coordination | Preprint |
| Elastic Security Labs (2026) | 6 behavioral signal definitions | Vendor blog |
| METR (2026-08-26) | Coordination mechanisms | Blog |
| HuggingFace timeline (2026-07) | 9-phase attack taxonomy | First-party blog |
| Pacheco et al. (arXiv:2001.05658) | Network coordination detection | Peer-reviewed, 244 citations |

## License

Code: MIT. Submodule: MIT. Data: see [data/README.md](data/README.md).
