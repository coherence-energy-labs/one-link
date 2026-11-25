"""The browser fixture's boot deadline cannot renew at a readiness boundary."""
from types import SimpleNamespace

import pytest

from tests import daemon_readiness as readiness


@pytest.fixture
def boot(tmp_path, monkeypatch):
    (tmp_path / "data").mkdir()
    clock = SimpleNamespace(now=0.0, on_sleep=lambda: None)
    proc = SimpleNamespace(returncode=None)
    proc.poll = lambda: proc.returncode
    requests = []
    state = SimpleNamespace(status=200, after_response=lambda: None)

    def sleep(seconds):
        clock.now += seconds
        clock.on_sleep()

    def publish():
        (tmp_path / "data" / "server.port").write_text("54321")
        (tmp_path / "data" / "ui.token").write_text("private-test-token")

    class Connection:
        def __init__(self, host, port, timeout):
            assert host == "127.0.0.1" and port == 54321
            assert 0 < timeout <= min(1.0, 45.0 - clock.now)

        def request(self, method, path, headers):
            assert method == "GET" and path == "/api/me"
            assert headers == {"Authorization": "Bearer private-test-token"}
            requests.append(clock.now)

        def getresponse(self):
            state.after_response()
            return SimpleNamespace(status=state.status, read=lambda _limit: b"{}")

        def close(self):
            pass

    monkeypatch.setattr(readiness, "monotonic", lambda: clock.now)
    monkeypatch.setattr(readiness, "sleep", sleep)
    monkeypatch.setattr(readiness.http.client, "HTTPConnection", Connection)
    return SimpleNamespace(
        home=tmp_path, proc=proc, clock=clock, publish=publish,
        requests=requests, state=state,
    )


def test_slow_file_publication_still_requires_authenticated_response(boot):
    def publish_late():
        if boot.clock.now >= 31.0:
            boot.publish()

    boot.clock.on_sleep = publish_late
    port, token, elapsed = readiness.wait_for_owner_http(boot.home, boot.proc)
    assert port == 54321 and token == "private-test-token"
    assert 31.0 <= elapsed < 31.1
    assert len(boot.requests) == 1


def test_http_readiness_does_not_get_a_fresh_deadline_after_files(boot):
    def publish_late():
        if boot.clock.now >= 44.0:
            boot.publish()

    boot.clock.on_sleep = publish_late
    boot.state.status = 503
    with pytest.raises(RuntimeError, match="authenticated HTTP.*45s total") as failure:
        readiness.wait_for_owner_http(boot.home, boot.proc)
    assert boot.clock.now == pytest.approx(45.0)
    assert boot.requests and min(boot.requests) >= 44.0
    assert "last_http_status=503" in str(failure.value)
    assert "private-test-token" not in str(failure.value)


def test_early_child_exit_fails_without_spending_the_deadline(boot):
    boot.proc.returncode = 7
    with pytest.raises(RuntimeError, match="exited with code 7"):
        readiness.wait_for_owner_http(boot.home, boot.proc)
    assert boot.clock.now == 0.0 and not boot.requests


def test_successful_response_does_not_qualify_a_child_that_died(boot):
    boot.publish()
    boot.state.after_response = lambda: setattr(boot.proc, "returncode", 2)
    with pytest.raises(RuntimeError, match="exited with code 2"):
        readiness.wait_for_owner_http(boot.home, boot.proc)


def test_partial_port_file_is_not_mistaken_for_readiness(boot):
    (boot.home / "data" / "server.port").write_text("")
    boot.clock.on_sleep = boot.publish
    port, _token, elapsed = readiness.wait_for_owner_http(boot.home, boot.proc)
    assert port == 54321 and elapsed == pytest.approx(0.05)
    assert len(boot.requests) == 1


def test_missing_files_have_one_finite_deadline_and_phase(boot):
    with pytest.raises(RuntimeError, match="ui.token \\+ server.port.*45s total"):
        readiness.wait_for_owner_http(boot.home, boot.proc)
    assert boot.clock.now == pytest.approx(45.0)
    assert not boot.requests


@pytest.mark.parametrize("timeout", [0.0, -1.0, float("nan"), float("inf")])
def test_invalid_budgets_cannot_make_an_unbounded_fixture(boot, timeout):
    with pytest.raises(ValueError, match="finite and positive"):
        readiness.wait_for_owner_http(boot.home, boot.proc, timeout=timeout)
    assert boot.clock.now == 0.0 and not boot.requests
