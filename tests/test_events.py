"""
Pure unit tests for debug-event parsing. These do not require a live x64dbg
instance and exercise the wire-shape -> typed-model mapping in events.py.
"""
from x64dbg_automate.events import (
    DbgEvent,
    DebugEventQueueMixin,
    EventType,
    LogMessageEventData,
)


def test_log_message_event_parsing():
    # DbgEvent receives the event type and the trailing argument tuple, so the
    # message published by the plugin as ("EVENT_LOG_MESSAGE", msg) arrives here
    # as event_data[0].
    event = DbgEvent(EventType.EVENT_LOG_MESSAGE, ["hello from x64dbg"])
    assert event.event_type == EventType.EVENT_LOG_MESSAGE
    assert isinstance(event.event_data, LogMessageEventData)
    assert event.event_data.text == "hello from x64dbg"


def test_log_message_event_dispatch_and_watch():
    class Queue(DebugEventQueueMixin):
        pass

    q = Queue()
    received: list[DbgEvent] = []

    callback = lambda e: received.append(e)
    q.watch_debug_event(EventType.EVENT_LOG_MESSAGE, callback)
    try:
        # debug_event_publish consumes the raw wire list: [type, *args]
        event = q.debug_event_publish(["EVENT_LOG_MESSAGE", "buffered line"])
        assert event.event_type == EventType.EVENT_LOG_MESSAGE
        assert event.event_data.text == "buffered line"
        assert len(received) == 1
        assert received[0].event_data.text == "buffered line"
    finally:
        q.unwatch_debug_event(EventType.EVENT_LOG_MESSAGE, callback)


def test_log_events_do_not_evict_other_events():
    # A flood of EVENT_LOG_MESSAGE must not push a non-log event out of the main
    # queue -- the whole point of the separate log queue.
    q = DebugEventQueueMixin()
    q._init_event_queues(log_event_queue_maxlen=5)

    # one important non-log event
    q.debug_event_publish(["EVENT_SYSTEMBREAKPOINT", 0])

    # flood with far more log events than either cap
    for i in range(50):
        q.debug_event_publish(["EVENT_LOG_MESSAGE", f"line {i}"])

    # the non-log event survived in its own (main) queue
    ev = q.wait_for_debug_event(EventType.EVENT_SYSTEMBREAKPOINT, timeout=1)
    assert ev is not None
    assert ev.event_type == EventType.EVENT_SYSTEMBREAKPOINT

    # the log queue is bounded to its cap and holds only the most recent lines
    assert len(q._log_events_q) == 5
    msgs = [e.event_data.text for e in q._log_events_q]
    assert msgs == [f"line {i}" for i in range(45, 50)]


def test_log_event_queue_maxlen_configurable_and_resizable():
    q = DebugEventQueueMixin()
    q._init_event_queues(log_event_queue_maxlen=3)
    assert q.log_event_queue_maxlen == 3

    for i in range(10):
        q.debug_event_publish(["EVENT_LOG_MESSAGE", str(i)])
    assert len(q._log_events_q) == 3
    assert [e.event_data.text for e in q._log_events_q] == ["7", "8", "9"]

    # shrinking the cap keeps the most recent events
    q.log_event_queue_maxlen = 2
    assert q.log_event_queue_maxlen == 2
    assert [e.event_data.text for e in q._log_events_q] == ["8", "9"]


def test_clear_debug_events_targets_correct_queue():
    q = DebugEventQueueMixin()
    q._init_event_queues()
    q.debug_event_publish(["EVENT_SYSTEMBREAKPOINT", 0])
    q.debug_event_publish(["EVENT_LOG_MESSAGE", "a"])

    # clearing only log events leaves the main queue intact
    q.clear_debug_events(EventType.EVENT_LOG_MESSAGE)
    assert len(q._log_events_q) == 0
    assert q.peek_latest_debug_event().event_type == EventType.EVENT_SYSTEMBREAKPOINT

    # clearing everything empties both
    q.debug_event_publish(["EVENT_LOG_MESSAGE", "b"])
    q.clear_debug_events()
    assert len(q._log_events_q) == 0
    assert len(q._debug_events_q) == 0


def test_get_latest_excludes_log_events():
    q = DebugEventQueueMixin()
    q._init_event_queues()
    q.debug_event_publish(["EVENT_SYSTEMBREAKPOINT", 0])
    q.debug_event_publish(["EVENT_LOG_MESSAGE", "noise"])

    # get_latest / peek operate on the main queue only; log noise never masks
    # the real event.
    assert q.peek_latest_debug_event().event_type == EventType.EVENT_SYSTEMBREAKPOINT
    assert q.get_latest_debug_event().event_type == EventType.EVENT_SYSTEMBREAKPOINT
    assert q.get_latest_debug_event() is None  # main queue now empty
    # the log event is still retrievable from its own queue
    assert q.wait_for_debug_event(EventType.EVENT_LOG_MESSAGE, timeout=1).event_data.text == "noise"
