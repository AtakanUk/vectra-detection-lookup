# Vectra Detection Lookup

[![CI](https://github.com/AtakanUk/vectra-detection-lookup/actions/workflows/ci.yml/badge.svg)](https://github.com/AtakanUk/vectra-detection-lookup/actions/workflows/ci.yml)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Polls the Vectra AI hosts API for hosts above a threat/certainty threshold and turns them into alert payloads that a SOAR playbook or ticketing system can pick up.

## How it works

1. `GET /api/v3.4/hosts/` with `threat_gte`, `certainty_gte` and `all_active=true`, ordered by urgency and latest detection, following pagination until the last page.
2. Each host is compared with the scores stored in a JSON state file. A host is reported the first time it shows up and again only when its threat or certainty score increases, so a long-running compromised host does not flood the queue.
3. For every reported host a payload with a ready-to-use subject, a human-readable body and a structured `body_json` section is printed as one JSON line (and optionally appended to a JSONL file).

```json
{
  "subject": "[Vectra] Host risk alert - host-a - T:80 C:70",
  "body_text": "Host: host-a\nIP: 192.0.2.10\nThreat: 80\n...",
  "body_json": {"host_id": 101, "name": "host-a", "threat": 80, "certainty": 70, "...": "..."}
}
```

Older API versions that return `t_score` / `c_score` instead of `threat` / `certainty` are handled as well.

## Requirements

- Python 3.11+
- A Vectra API token with read access to hosts

## Configuration

| Variable | CLI flag | Default | Description |
| --- | --- | --- | --- |
| `VECTRA_BASE_URL` | `--base-url` | – | Vectra portal, e.g. `https://vectra.example.com` |
| `VECTRA_API_TOKEN` | `--api-token` | – | API token (sent as a bearer token) |
| `VECTRA_MIN_THREAT` | `--min-threat` | `70` | Minimum threat score |
| `VECTRA_MIN_CERTAINTY` | `--min-certainty` | `60` | Minimum certainty score |

## Usage

```bash
pip install -r requirements.txt
export VECTRA_BASE_URL=https://vectra.example.com VECTRA_API_TOKEN=...

# single run
python vectra_detection_lookup.py --state-file state.json

# run continuously every 15 minutes and keep a JSONL trail
python vectra_detection_lookup.py --poll-seconds 900 --output-file alerts.jsonl
```

In polling mode API errors are logged and retried on the next cycle instead of stopping the process. `--insecure` disables TLS verification for lab appliances with self-signed certificates.

## Tests

```bash
pip install pytest
pytest
```

## License

[MIT](LICENSE)
