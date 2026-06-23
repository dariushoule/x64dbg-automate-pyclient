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
    assert event.event_data.message == "hello from x64dbg"


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
        assert event.event_data.message == "buffered line"
        assert len(received) == 1
        assert received[0].event_data.message == "buffered line"
    finally:
        q.unwatch_debug_event(EventType.EVENT_LOG_MESSAGE, callback)
