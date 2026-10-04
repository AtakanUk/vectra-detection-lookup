"""Poll the Vectra hosts API for high-risk hosts and emit alert payloads.

A host is reported the first time it crosses the threat/certainty thresholds and
again whenever one of its scores increases; the last seen scores are kept in a
small JSON state file so restarts do not cause duplicate alerts.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import time
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path

import requests

LOG = logging.getLogger("vectra_detection_lookup")
# t_score / c_score are the score names used by older API versions.
DEFAULT_FIELDS = ",".join(
    [
        "id",
        "name",
        "ip",
        "threat",
        "certainty",
        "t_score",
        "c_score",
        "last_detection_timestamp",
        "last_modified",
        "host_url",
        "url",
        "tags",
        "sensor_name",
        "is_key_asset",
        "has_active_traffic",
    ]
)


@dataclass
class HostHit:
    host_id: int
    name: str
    ip: str
    threat: int
    certainty: int
    last_detection_timestamp: str | None = None
    host_url: str | None = None
    tags: list[str] = field(default_factory=list)
    sensor_name: str | None = None
    is_key_asset: bool | None = None
    has_active_traffic: bool | None = None

    @classmethod
    def from_api(cls, item: dict[str, object]) -> HostHit:
        return cls(
            host_id=int(item.get("id")),
            name=item.get("name") or "unknown",
            ip=item.get("ip") or "unknown",
            threat=int(item.get("threat") or item.get("t_score") or 0),
            certainty=int(item.get("certainty") or item.get("c_score") or 0),
            last_detection_timestamp=item.get("last_detection_timestamp"),
            host_url=item.get("host_url") or item.get("url"),
            tags=list(item.get("tags") or []),
            sensor_name=item.get("sensor_name"),
            is_key_asset=item.get("is_key_asset"),
            has_active_traffic=item.get("has_active_traffic"),
        )


class StateStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.state = self._load()

    def _load(self) -> dict[str, dict[str, int]]:
        if not self.path.exists():
            return {}
        return json.loads(self.path.read_text(encoding="utf-8"))

    def should_alert(self, hit: HostHit) -> bool:
        key = str(hit.host_id)
        previous = self.state.get(key)
        current = {"threat": hit.threat, "certainty": hit.certainty}
        if previous is None:
            self.state[key] = current
            return True
        if hit.threat > previous.get("threat", 0) or hit.certainty > previous.get("certainty", 0):
            self.state[key] = current
            return True
        return False

    def persist(self) -> None:
        self.path.write_text(json.dumps(self.state, indent=2, sort_keys=True), encoding="utf-8")


class VectraClient:
    def __init__(
        self, base_url: str, api_token: str, verify: bool = True, timeout: int = 30
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = verify
        self.session.headers.update(
            {
                "Authorization": f"Bearer {api_token}",
                "Accept": "application/json",
            }
        )

    def fetch_high_risk_hosts(
        self,
        *,
        min_threat: int,
        min_certainty: int,
        page_size: int = 500,
        fields: str = DEFAULT_FIELDS,
    ) -> list[HostHit]:
        page = 1
        results: list[HostHit] = []
        while True:
            response = self.session.get(
                f"{self.base_url}/api/v3.4/hosts/",
                params={
                    "page": page,
                    "page_size": page_size,
                    "threat_gte": min_threat,
                    "certainty_gte": min_certainty,
                    "all_active": "true",
                    "ordering": "-urgency_score,-last_detection_timestamp",
                    "fields": fields,
                },
                timeout=self.timeout,
            )
            response.raise_for_status()
            payload = response.json()
            results.extend(HostHit.from_api(item) for item in payload.get("results", []))
            if not payload.get("next"):
                break
            page += 1
        return results


def build_ticket_payload(hit: HostHit) -> dict[str, object]:
    return {
        "subject": f"[Vectra] Host risk alert - {hit.name} - T:{hit.threat} C:{hit.certainty}",
        "body_text": "\n".join(
            [
                f"Host: {hit.name}",
                f"IP: {hit.ip}",
                f"Threat: {hit.threat}",
                f"Certainty: {hit.certainty}",
                f"Last detection: {hit.last_detection_timestamp or 'unknown'}",
                f"Key asset: {hit.is_key_asset}",
                f"Active traffic: {hit.has_active_traffic}",
                f"Tags: {', '.join(hit.tags) if hit.tags else 'none'}",
                f"Host URL: {hit.host_url or 'not available'}",
            ]
        ),
        "body_json": asdict(hit),
    }


def _first(*values: object) -> object:
    return next((value for value in values if value not in (None, "")), None)


def load_config(args: argparse.Namespace) -> dict[str, object]:
    base_url = _first(args.base_url, os.environ.get("VECTRA_BASE_URL"))
    api_token = _first(args.api_token, os.environ.get("VECTRA_API_TOKEN"))
    if not base_url or not api_token:
        raise SystemExit("Set VECTRA_BASE_URL and VECTRA_API_TOKEN before running this tool.")
    return {
        "base_url": base_url,
        "api_token": api_token,
        "min_threat": int(_first(args.min_threat, os.environ.get("VECTRA_MIN_THREAT"), 70)),
        "min_certainty": int(
            _first(args.min_certainty, os.environ.get("VECTRA_MIN_CERTAINTY"), 60)
        ),
    }


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Query Vectra for high-risk hosts and print SOAR-friendly alert payloads."
    )
    parser.add_argument("--base-url")
    parser.add_argument("--api-token")
    parser.add_argument("--min-threat", type=int)
    parser.add_argument("--min-certainty", type=int)
    parser.add_argument("--page-size", type=int, default=500)
    parser.add_argument(
        "--poll-seconds", type=int, default=0, help="Repeat lookup every N seconds. Zero runs once."
    )
    parser.add_argument(
        "--state-file", default="state.json", help="JSON file used to suppress duplicate alerts."
    )
    parser.add_argument("--output-file", help="Optional JSONL output file for emitted payloads.")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification.")
    parser.add_argument(
        "--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"]
    )
    return parser.parse_args(list(argv) if argv is not None else None)


def emit_payloads(payloads: list[dict[str, object]], output_file: str | None) -> None:
    for payload in payloads:
        print(json.dumps(payload, ensure_ascii=False))
    if output_file:
        target = Path(output_file)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a", encoding="utf-8") as handle:
            for payload in payloads:
                handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def run_once(args: argparse.Namespace, state: StateStore) -> list[dict[str, object]]:
    config = load_config(args)
    client = VectraClient(
        base_url=str(config["base_url"]),
        api_token=str(config["api_token"]),
        verify=not args.insecure,
    )
    hits = client.fetch_high_risk_hosts(
        min_threat=int(config["min_threat"]),
        min_certainty=int(config["min_certainty"]),
        page_size=args.page_size,
    )
    LOG.info("Fetched %s matching hosts from Vectra", len(hits))
    payloads = [build_ticket_payload(hit) for hit in hits if state.should_alert(hit)]
    state.persist()
    return payloads


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    state = StateStore(Path(args.state_file))
    if args.poll_seconds <= 0:
        emit_payloads(run_once(args, state), args.output_file)
        return 0

    while True:
        started = time.monotonic()
        try:
            emit_payloads(run_once(args, state), args.output_file)
        except requests.RequestException as exc:
            LOG.error("Lookup failed, retrying next cycle: %s", exc)
        sleep_for = max(0.0, args.poll_seconds - (time.monotonic() - started))
        LOG.info("Sleeping %.0f seconds before the next lookup", sleep_for)
        time.sleep(sleep_for)


if __name__ == "__main__":
    raise SystemExit(main())
