from infra.callback_resolver import (
    CallbackResolution,
    candidate_callback_urls,
    resolve_callback_url,
)


def test_candidate_callback_urls_are_unique_and_include_expected_hosts():
    urls = candidate_callback_urls(
        port=18765,
        extra_hosts=["127.0.0.1", "192.0.2.10", "192.0.2.10"],
        include_host_network=False,
        include_wsl=False,
    )

    assert urls[:3] == [
        "http://127.0.0.1:18765",
        "http://localhost:18765",
        "http://host.docker.internal:18765",
    ]
    assert urls.count("http://192.0.2.10:18765") == 1


def test_resolve_callback_url_records_probe_success():
    calls = []

    def fake_probe(url: str, harness: str, timeout_sec: float) -> bool:
        calls.append((url, harness, timeout_sec))
        return url.endswith("192.0.2.10:18765")

    resolution = resolve_callback_url(
        harness="hermes",
        port=18765,
        candidates=["http://127.0.0.1:18765", "http://192.0.2.10:18765"],
        probe=fake_probe,
    )

    assert resolution == CallbackResolution(
        callback_url="http://192.0.2.10:18765",
        callback_probe_ok=True,
        callback_probe_method="hermes",
        callback_candidates=["http://127.0.0.1:18765", "http://192.0.2.10:18765"],
    )
    assert calls == [
        ("http://127.0.0.1:18765", "hermes", 2.0),
        ("http://192.0.2.10:18765", "hermes", 2.0),
    ]
