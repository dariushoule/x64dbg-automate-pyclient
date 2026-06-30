from collections import deque
from enum import StrEnum
import time

from pydantic import BaseModel


# Default ring-buffer caps for the client-side event queues.
DEFAULT_EVENT_QUEUE_MAXLEN = 100        # all events except EVENT_LOG_MESSAGE
DEFAULT_LOG_EVENT_QUEUE_MAXLEN = 1000   # EVENT_LOG_MESSAGE only (higher volume)


class EventType(StrEnum):
    EVENT_BREAKPOINT = "EVENT_BREAKPOINT"
    EVENT_SYSTEMBREAKPOINT = "EVENT_SYSTEMBREAKPOINT"
    EVENT_CREATE_THREAD = "EVENT_CREATE_THREAD"
    EVENT_EXIT_THREAD = "EVENT_EXIT_THREAD"
    EVENT_LOAD_DLL = "EVENT_LOAD_DLL"
    EVENT_UNLOAD_DLL = "EVENT_UNLOAD_DLL"
    EVENT_OUTPUT_DEBUG_STRING = "EVENT_OUTPUT_DEBUG_STRING"
    EVENT_EXCEPTION = "EVENT_EXCEPTION"
    EVENT_STEPPED = "EVENT_STEPPED"
    EVENT_RESUME_DEBUG = "EVENT_RESUME_DEBUG"
    EVENT_PAUSE_DEBUG = "EVENT_PAUSE_DEBUG"
    EVENT_ATTACH = "EVENT_ATTACH"
    EVENT_DETACH = "EVENT_DETACH"
    EVENT_INIT_DEBUG = "EVENT_INIT_DEBUG"
    EVENT_STOP_DEBUG = "EVENT_STOP_DEBUG"
    EVENT_CREATE_PROCESS = "EVENT_CREATE_PROCESS"
    EVENT_EXIT_PROCESS = "EVENT_EXIT_PROCESS"
    EVENT_LOG_MESSAGE = "EVENT_LOG_MESSAGE"


class BreakpointEventData(BaseModel):
    type: int
    addr: int
    enabled: bool
    singleshoot: bool
    active: bool
    name: str
    mod: str
    slot: int
    typeEx: int
    hwSize: int
    hitCount: int
    fastResume: bool
    silent: bool
    breakCondition: str
    logText: str
    logCondition: str
    commandText: str
    commandCondition: str


class SysBreakpointEventData(BaseModel):
    reserved: int


class CreateThreadEventData(BaseModel):
    dwThreadId: int
    lpThreadLocalBase: int
    lpStartAddress: int


class ExitThreadEventData(BaseModel):
    dwThreadId: int
    dwExitCode: int


class LoadDllEventData(BaseModel):
    modname: str
    lpBaseOfDll: int


class UnloadDllEventData(BaseModel):
    lpBaseOfDll: int


class OutputDebugStringEventData(BaseModel):
    lpDebugStringData: bytes


class ExceptionEventData(BaseModel):
    ExceptionCode: int
    ExceptionFlags: int
    ExceptionRecord: int
    ExceptionAddress: int
    NumberParameters: int
    ExceptionInformation: list[int]
    dwFirstChance: bool


class AttachEventData(BaseModel):
    dwProcessId: int


class DetachEventData(BaseModel):
    dwProcessId: int


class InitDebugEventData(BaseModel):
    filename: str


class CreateProcessEventData(BaseModel):
    dwProcessId: int
    dwThreadId: int
    lpStartAddress: int
    debugFileName: str


class ExitProcessEventData(BaseModel):
    dwExitCode: int


class LogMessageEventData(BaseModel):
    """
    Payload of an `EVENT_LOG_MESSAGE` event: a single line written to the x64dbg
    log, captured by the plugin's log hook and published as it occurs. The same
    lines are also retrievable on demand via `X64DbgClient.get_log`.
    """
    message: str


EventTypes = BreakpointEventData | SysBreakpointEventData | CreateThreadEventData | ExitThreadEventData | \
    LoadDllEventData | UnloadDllEventData | OutputDebugStringEventData | ExceptionEventData | AttachEventData | \
    DetachEventData | InitDebugEventData | CreateProcessEventData | ExitProcessEventData | LogMessageEventData | None


class DbgEvent():
    event_type: EventType
    event_data: EventTypes

    def __init__(self, event_type: str, event_data: list[any]):
        self.event_type = EventType(event_type)
        self.event_data = None

        if event_type == EventType.EVENT_BREAKPOINT:
            self.event_data = BreakpointEventData(
                type=event_data[0],
                addr=event_data[1],
                enabled=event_data[2],
                singleshoot=event_data[3],
                active=event_data[4],
                name=event_data[5],
                mod=event_data[6],
                slot=event_data[7],
                typeEx=event_data[8],
                hwSize=event_data[9],
                hitCount=event_data[10],
                fastResume=event_data[11],
                silent=event_data[12],
                breakCondition=event_data[13],
                logText=event_data[14],
                logCondition=event_data[15],
                commandText=event_data[16],
                commandCondition=event_data[17]
            )
        elif event_type == EventType.EVENT_SYSTEMBREAKPOINT:
            self.event_data = SysBreakpointEventData(
                reserved=event_data[0]
            )
        elif event_type == EventType.EVENT_CREATE_THREAD:
            self.event_data = CreateThreadEventData(
                dwThreadId=event_data[0],
                lpThreadLocalBase=event_data[1],
                lpStartAddress=event_data[2]
            )
        elif event_type == EventType.EVENT_EXIT_THREAD:
            self.event_data = ExitThreadEventData(
                dwThreadId=event_data[0],
                dwExitCode=event_data[1]
            )
        elif event_type == EventType.EVENT_LOAD_DLL:
            self.event_data = LoadDllEventData(
                modname=event_data[0],
                lpBaseOfDll=event_data[1]
            )
        elif event_type == EventType.EVENT_UNLOAD_DLL:
            self.event_data = UnloadDllEventData(
                lpBaseOfDll=event_data[0]
            )
        elif event_type == EventType.EVENT_OUTPUT_DEBUG_STRING:
            self.event_data = OutputDebugStringEventData(
                lpDebugStringData=event_data[0]
            )
        elif event_type == EventType.EVENT_STEPPED:
            pass
        elif event_type == EventType.EVENT_RESUME_DEBUG:
            pass
        elif event_type == EventType.EVENT_PAUSE_DEBUG:
            pass
        elif event_type == EventType.EVENT_ATTACH:
            self.event_data = AttachEventData(
                dwProcessId=event_data[0]
            )
        elif event_type == EventType.EVENT_DETACH:
            self.event_data = DetachEventData(
                dwProcessId=event_data[0]
            )
        elif event_type == EventType.EVENT_INIT_DEBUG:
            self.event_data = InitDebugEventData(
                filename=event_data[0]
            )
        elif event_type == EventType.EVENT_STOP_DEBUG:
            pass
        elif event_type == EventType.EVENT_CREATE_PROCESS:
            self.event_data = CreateProcessEventData(
                dwProcessId=event_data[0],
                dwThreadId=event_data[1],
                lpStartAddress=event_data[2],
                debugFileName=event_data[3]
            )
        elif event_type == EventType.EVENT_EXIT_PROCESS:
            self.event_data = ExitProcessEventData(
                dwExitCode=event_data[0]
            )
        elif event_type == EventType.EVENT_LOG_MESSAGE:
            self.event_data = LogMessageEventData(
                message=event_data[0]
            )
        elif event_type == EventType.EVENT_EXCEPTION:
            self.event_data = ExceptionEventData(
                ExceptionCode=event_data[0],
                ExceptionFlags=event_data[1],
                ExceptionRecord=event_data[2],
                ExceptionAddress=event_data[3],
                NumberParameters=event_data[4],
                ExceptionInformation=event_data[5],
                dwFirstChance=event_data[6]
            )
        else:
            raise ValueError(f"Unknown event type: {event_type}")


class DebugEventQueueMixin():
    """
    Receives debug events published by the plugin over the PUB/SUB channel and
    exposes them via polling (`get_latest_debug_event`, `wait_for_debug_event`)
    and callbacks (`watch_debug_event`).

    `EVENT_LOG_MESSAGE` events are held in a SEPARATE bounded queue from all other
    debug events. A verbose log stream (e.g. a long trace) can produce far more
    log events than the main queue would hold; keeping them apart guarantees they
    can never evict breakpoint / step / other control events that a caller is
    waiting on. Both queues are bounded ring buffers — the oldest entry is dropped
    once the cap is reached. The log-queue cap is configurable
    (`log_event_queue_maxlen`); the main queue uses `DEFAULT_EVENT_QUEUE_MAXLEN`.
    """
    _debug_events_q: deque   # all events EXCEPT EVENT_LOG_MESSAGE
    _log_events_q: deque     # EVENT_LOG_MESSAGE only
    listeners: dict

    def __init__(self):
        # Direct instantiation (e.g. tests). X64DbgClient initializes via
        # _init_fields -> _init_event_queues instead.
        self._init_event_queues()

    def _init_event_queues(self, log_event_queue_maxlen: int = DEFAULT_LOG_EVENT_QUEUE_MAXLEN) -> None:
        """(Re)create the per-instance event queues. Instance-level so separate
        clients never share queue state."""
        self._debug_events_q = deque(maxlen=DEFAULT_EVENT_QUEUE_MAXLEN)
        self._log_events_q = deque(maxlen=log_event_queue_maxlen)
        self.listeners = {}

    @property
    def log_event_queue_maxlen(self) -> int:
        """Maximum number of `EVENT_LOG_MESSAGE` events retained in the log queue.

        Assigning a new value resizes the queue in place, keeping the most recent
        events when the new cap is smaller.

        Memory footprint is roughly ``maxlen x average payload size``. Most log
        lines are small, but x64dbg batches trace output into large multi-line
        chunks (tens of KB each), so a sustained trace can approach
        ``maxlen x ~tens-of-KB``. Lower this cap if that ceiling matters; the
        pull-based `get_log` buffer is the preferred way to consume bulk trace log.
        """
        return self._log_events_q.maxlen

    @log_event_queue_maxlen.setter
    def log_event_queue_maxlen(self, maxlen: int) -> None:
        self._log_events_q = deque(self._log_events_q, maxlen=maxlen)

    def _queue_for(self, event_type: EventType) -> deque:
        if event_type == EventType.EVENT_LOG_MESSAGE:
            return self._log_events_q
        return self._debug_events_q

    def debug_event_publish(self, raw_event_data: list[any]):
        event = DbgEvent(raw_event_data[0], raw_event_data[1:])
        # deque(maxlen=...) drops the oldest entry automatically once full.
        self._queue_for(event.event_type).append(event)
        for listener in self.listeners.get(event.event_type, []):
            listener(event)
        return event

    def get_latest_debug_event(self) -> DbgEvent | None:
        """
        Get the latest debug event that occurred in the debugee. The event is removed from the queue.

        Note: `EVENT_LOG_MESSAGE` events are kept in a separate queue and are not
        returned here. Retrieve them with `wait_for_debug_event(EventType.EVENT_LOG_MESSAGE)`,
        a `watch_debug_event` callback, or the `get_log` buffer.
        """
        if len(self._debug_events_q) == 0:
            return None
        return self._debug_events_q.pop()

    def peek_latest_debug_event(self) -> DbgEvent | None:
        """
        Get the latest debug event that occurred in the debugee. The event is not removed from the queue.

        Note: `EVENT_LOG_MESSAGE` events are kept in a separate queue and are not returned here (see `get_latest_debug_event`).
        """
        if len(self._debug_events_q) == 0:
            return None
        return self._debug_events_q[-1]

    def clear_debug_events(self, event_type: EventType | None = None) -> None:
        """
        Clear buffered debug events. If `event_type` is specified, only events of that
        type are removed (from whichever queue holds them); otherwise both the main
        event queue and the `EVENT_LOG_MESSAGE` queue are cleared.

        Args:
            event_type: The type of event to clear. If None, all events will be cleared.
        """
        if event_type is None:
            self._debug_events_q.clear()
            self._log_events_q.clear()
            return
        q = self._queue_for(event_type)
        kept = [e for e in list(q) if e.event_type != event_type]
        q.clear()
        q.extend(kept)

    def wait_for_debug_event(self, event_type: EventType, timeout: int = 5) -> DbgEvent | None:
        """
        Wait for a debug event of a specific type to occur. This method returns the latest event of the specified type, which may have occurred before the method was called.

        Returned events are removed from the queue. If the event has not occurred within the timeout, None is returned.

        `clear_debug_events` can be used to ensure an empty debug event queue before calling this method.

        Args:
            event_type: The type of event to wait for
            timeout: The maximum time to wait for the event in seconds

        Returns:
            DbgEvent | None: The latest event of the specified type, or None if the event did not occur within the timeout.
        """
        q = self._queue_for(event_type)
        while timeout > 0:
            # Iterate a snapshot: the SUB thread may append/evict concurrently.
            for event in list(q):
                if event.event_type == event_type:
                    try:
                        q.remove(event)
                    except ValueError:
                        pass  # already evicted by the cap between snapshot and removal
                    return event
            time.sleep(0.25)
            timeout -= 0.25
        return None

    def watch_debug_event(self, event_type: EventType, callback: callable):
        """
        Register a callback to be invoked when a debug event of a specific type occurs.

        Args:
            event_type: The type of event to watch
            callback: The callback to invoke when the event occurs. The callback should accept a single argument of type `DbgEvent`.
        """
        self.listeners[event_type] = self.listeners.get(event_type, []) + [callback]

    def unwatch_debug_event(self, event_type: EventType, callback: callable):
        """
        Remove a callback registered with `watch_debug_event`

        Args:
            event_type: The type of event to unwatch
            callback: The callback instance to remove
        """
        self.listeners[event_type] = [x for x in self.listeners.get(event_type, []) if x != callback]
