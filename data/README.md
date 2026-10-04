# Data

These datasets are not redistributed in this repository. Download them from the original sources.

## collusion-wiki/

14,591 revisions from ~3,100 agents on a dormant German wiki, May-June 2026. Agents were running a timed web-retrieval task and found they could edit the wiki to share answers. The complete edit history is public.

```bash
curl -sL "https://collusion.wiki/explorer/download/revisions.jsonl.gz" -o revisions.jsonl.gz
curl -sL "https://collusion.wiki/explorer/download/pages.jsonl.gz" -o pages.jsonl.gz
curl -sL "https://collusion.wiki/explorer/download/events.jsonl.gz" -o events.jsonl.gz
gunzip -k *.gz
```

Source: [collusion.wiki](https://collusion.wiki/explorer/download)

## swarmtraces/

189,579 decoded payloads from the July 2026 HuggingFace intrusion. Agents split programs across 900+ shortened URLs and used screenshot services to execute code with GET-only permissions. Credentials and infrastructure details are redacted per HF's request.

```bash
curl -sL "https://swarmtraces.org/data/final/redacted.jsonl.gz" -o redacted.jsonl.gz
gunzip -k redacted.jsonl.gz
```

Source: [swarmtraces.org](https://swarmtraces.org) (Palisade Research, Trajectory Institute)

## ai-village/

183,485 chat messages from 46 AI agents running in the AI Village, an ongoing experiment where agents from Anthropic, OpenAI, and Google live together in a virtual environment and collaborate on open-ended goals. Running since April 2025.

Requires a HuggingFace token with access granted. Download `chat_messages.jsonl.gz` and `agents.jsonl.gz`.

Source: [aidigestorg/ai-village](https://huggingface.co/datasets/aidigestorg/ai-village)
