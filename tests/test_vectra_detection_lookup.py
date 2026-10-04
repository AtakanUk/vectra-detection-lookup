from unittest.mock import MagicMock

from vectra_detection_lookup import HostHit, StateStore, VectraClient, build_ticket_payload


def sample_hit(threat: int = 80, certainty: int = 70) -> HostHit:
    return HostHit(
        host_id=101,
        name="host-a",
        ip="192.0.2.10",
        threat=threat,
        certainty=certainty,
        last_detection_timestamp="2026-01-01T00:00:00Z",
        host_url="https://vectra.example.com/hosts/101",
        tags=["critical"],
        sensor_name="sensor-a",
        is_key_asset=True,
        has_active_traffic=True,
    )


def test_state_store_only_alerts_on_new_or_higher_scores(tmp_path) -> None:
    state_path = tmp_path / "state.json"
    store = StateStore(state_path)
    assert store.should_alert(sample_hit()) is True
    assert store.should_alert(sample_hit()) is False
    assert store.should_alert(sample_hit(threat=85)) is True
    store.persist()

    reloaded = StateStore(state_path)
    assert reloaded.should_alert(sample_hit(threat=85)) is False


def test_build_ticket_payload_contains_summary() -> None:
    payload = build_ticket_payload(sample_hit())
    assert payload["subject"] == "[Vectra] Host risk alert - host-a - T:80 C:70"
    assert "IP: 192.0.2.10" in payload["body_text"]
    assert payload["body_json"]["host_id"] == 101


def test_client_pages_and_falls_back_to_legacy_scores() -> None:
    client = VectraClient("https://vectra.example.com", "token")
    pages = [
        {"results": [{"id": 1, "name": "a", "threat": 90, "certainty": 80}], "next": "page2"},
        {"results": [{"id": 2, "name": "b", "t_score": 75, "c_score": 65}], "next": None},
    ]
    responses = []
    for page in pages:
        response = MagicMock()
        response.json.return_value = page
        responses.append(response)
    client.session.get = MagicMock(side_effect=responses)

    hits = client.fetch_high_risk_hosts(min_threat=70, min_certainty=60)

    assert [(h.host_id, h.threat, h.certainty) for h in hits] == [(1, 90, 80), (2, 75, 65)]
    assert client.session.headers["Authorization"] == "Bearer token"
    assert client.session.get.call_args_list[1].kwargs["params"]["page"] == 2
