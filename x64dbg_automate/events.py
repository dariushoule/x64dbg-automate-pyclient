from enum import StrEnum
import time

from pydantic import BaseModel


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


EventTypes = BreakpointEventData | SysBreakpointEventData | CreateThreadEventData | ExitThreadEventData | \
    LoadDllEventData | UnloadDllEventData | OutputDebugStringEventData | ExceptionEventData | AttachEventData | \
    DetachEventData | InitDebugEventData | CreateProcessEventData | ExitProcessEventData | None


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
    _debug_events_q: list[DbgEvent] = []
    listeners: dict[EventType, list[callable]] = {}

    def debug_event_publish(self, raw_event_data: list[any]):
        event = DbgEvent(raw_event_data[0], raw_event_data[1:])
        while len(self._debug_events_q) > 100:
            self._debug_events_q.pop(0)
        self._debug_events_q.append(event)
        for listener in self.listeners.get(event.event_type, []):
            listener(event)
        return event
    
    def get_latest_debug_event(self) -> DbgEvent | None:
        """
        Get the latest debug event that occurred in the debugee. The event is removed from the queue.
        """
        if len(self._debug_events_q) == 0:
            return None
        return self._debug_events_q.pop()
    
    def peek_latest_debug_event(self) -> DbgEvent | None:
        """
        Get the latest debug event that occurred in the debugee. The event is not removed from the queue.
        """
        if len(self._debug_events_q) == 0:
            return None
        return self._debug_events_q[-1]
    
    def clear_debug_events(self, event_type: EventType | None = None) -> None:
        """
        Clear the debug event queue. If `event_type` is specified, only events of that type will be removed.
        
        Args:
            event_type: The type of event to clear. If None, all events will be cleared.
        """
        filtered = []
        for _ in range(len(self._debug_events_q)):
            event = self._debug_events_q.pop(0)
            if event.event_type != event_type and event_type is not None:
                filtered.append(event)
        self._debug_events_q = filtered
    
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
        while timeout > 0:
            for ix, event in enumerate(self._debug_events_q):
                if event.event_type == event_type:
                    return self._debug_events_q.pop(ix)
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
