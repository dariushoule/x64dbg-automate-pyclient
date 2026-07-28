import queue
import time

from x64dbg_automate import X64DbgClient
from x64dbg_automate.events import DbgEvent, EventType


# x64dbg's log task coalesces several lines into a single GuiAddLogMessage call,
# so a buffer entry is not a log line. Anything asserting on quantity must count
# lines, or force entries apart in time -- never assume one entry per `log`.
LOG_TIMEOUT = 5.0


def _log(client: X64DbgClient, text: str) -> None:
    assert client.cmd_sync(f'log "{text}"')


def _lines(entries: list[str], marker: str) -> list[str]:
    return [line for entry in entries for line in entry.splitlines() if marker in line]


def _wait_for_log(client: X64DbgClient, marker: str, min_lines: int = 1,
                  timeout: float = LOG_TIMEOUT) -> tuple[int, list[str], int, int]:
    """Poll get_log until `marker` has produced at least `min_lines` matching lines."""
    deadline = time.time() + timeout
    while True:
        snapshot = client.get_log(0, 0, marker)
        if len(_lines(snapshot[1], marker)) >= min_lines or time.time() > deadline:
            return snapshot
        time.sleep(0.1)


def test_get_log_captures_output(client: X64DbgClient):
    """Regression guard: the log hook must actually be installed.

    A hook that fails to install leaves the buffer permanently empty while every
    other command keeps working, so nothing else in the suite notices. Run at
    both TEST_BITNESS values -- installation is bitness-conditional.
    """
    client.start_session(r'c:\Windows\system32\winver.exe')
    marker = 'XAUTO_LOG_CAPTURE_PROBE'
    _log(client, marker)

    _, entries, _, _ = _wait_for_log(client, marker)
    assert entries, 'log buffer is empty -- log hook not installed for this bitness?'
    assert _lines(entries, marker)


def test_get_log_event_published(client: X64DbgClient):
    """The same capture path must also publish EVENT_LOG_MESSAGE on PUB."""
    client.start_session(r'c:\Windows\system32\winver.exe')
    received: queue.Queue[DbgEvent] = queue.Queue()
    client.watch_debug_event(EventType.EVENT_LOG_MESSAGE, lambda e: received.put(e))

    marker = 'XAUTO_LOG_EVENT_PROBE'
    _log(client, marker)

    deadline = time.time() + LOG_TIMEOUT
    while time.time() < deadline:
        try:
            event = received.get(timeout=0.1)
        except queue.Empty:
            continue
        if marker in event.event_data.text:
            return
    raise AssertionError('no EVENT_LOG_MESSAGE carrying the marker was published')


def test_get_log_filter_matches_lines_not_entries(client: X64DbgClient):
    """filter is applied per line, so a coalesced entry is split, not returned whole."""
    client.start_session(r'c:\Windows\system32\winver.exe')
    keep, drop = 'XAUTO_FILTER_KEEP', 'XAUTO_FILTER_DROP'
    _log(client, keep)
    _log(client, drop)
    _wait_for_log(client, drop)

    _, entries, _, _ = _wait_for_log(client, keep)
    assert _lines(entries, keep)
    # Both markers are typically coalesced into one entry; only the matching
    # line may come back.
    assert not any(drop in entry for entry in entries)


def test_get_log_since_index_returns_only_new_entries(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    first, second = 'XAUTO_SINCE_FIRST', 'XAUTO_SINCE_SECOND'

    _log(client, first)
    _wait_for_log(client, first)
    next_index, _, _, _ = client.get_log(0, 0, '')

    _log(client, second)
    deadline = time.time() + LOG_TIMEOUT
    while time.time() < deadline:
        _, entries, _, _ = client.get_log(next_index, 0, '')
        if _lines(entries, second):
            break
        time.sleep(0.1)

    assert _lines(entries, second)
    assert not _lines(entries, first), 'entries before since_index leaked into the result'


def test_get_log_limit_reports_remaining(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    marker = 'XAUTO_LIMIT_PROBE'

    # Space the lines out so the log task flushes them as separate entries;
    # logged back-to-back they would coalesce into one and limit would be moot.
    deadline = time.time() + 15.0
    entries: list[str] = []
    i = 0
    while time.time() < deadline and len(entries) < 2:
        _log(client, f'{marker}_{i}')
        i += 1
        time.sleep(0.3)
        _, entries, _, _ = client.get_log(0, 0, marker)
    assert len(entries) >= 2, 'could not produce two distinct log entries'

    next_index, head, remaining, evicted = client.get_log(0, 1, marker)
    assert len(head) == 1
    assert head[0] == entries[0], 'limit must return the head, not the tail'
    assert remaining == len(entries) - 1
    assert evicted == 0

    _, rest, remaining_after, _ = client.get_log(next_index, 0, marker)
    assert remaining_after == 0
    assert head[0] not in rest
    assert len(head) + len(rest) == len(entries)
