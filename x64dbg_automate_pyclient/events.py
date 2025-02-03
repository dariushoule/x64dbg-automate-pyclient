from collections import deque
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


class BreakpointEventData(BaseModel):
    type: int
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


EventTypes = BreakpointEventData | SysBreakpointEventData | CreateThreadEventData | ExitThreadEventData | \
    LoadDllEventData | UnloadDllEventData | OutputDebugStringEventData | ExceptionEventData


class DbgEvent():
    def __init__(self, event_type: str, event_data: list[any]):
        self.event_type = event_type

        if event_type == EventType.EVENT_BREAKPOINT:
            self.event_data = BreakpointEventData(
                type=event_data[0],
                enabled=event_data[1],
                singleshoot=event_data[2],
                active=event_data[3],
                name=event_data[4],
                mod=event_data[5],
                slot=event_data[6],
                typeEx=event_data[7],
                hwSize=event_data[8],
                hitCount=event_data[9],
                fastResume=event_data[10],
                silent=event_data[11],
                breakCondition=event_data[12],
                logText=event_data[13],
                logCondition=event_data[14],
                commandText=event_data[15],
                commandCondition=event_data[16]
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
    _debug_events_q: deque[DbgEvent] = deque()
    listeners: dict[EventType, list[callable]] = {}

    def debug_event_publish(self, raw_event_data: list[any]):
        event = DbgEvent(raw_event_data[0], raw_event_data[1:])
        while len(self._debug_events_q) > 100:
            self._debug_events_q.popleft()
        self._debug_events_q.append(event)
        for listener in self.listeners.get(event.event_type, []):
            listener(event)
        return event
    
    def get_latest_debug_event(self) -> DbgEvent | None:
        if len(self._debug_events_q) == 0:
            return None
        return self._debug_events_q.pop()
    
    def peek_latest_debug_event(self) -> DbgEvent | None:
        if len(self._debug_events_q) == 0:
            return None
        return self._debug_events_q[-1]
    
    def wait_for_debug_event(self, event_type: EventType, timeout: int = 5) -> DbgEvent | None:
        while timeout > 0:
            latest = self.peek_latest_debug_event()
            if latest and latest.event_type == event_type:
                return self.get_latest_debug_event()
            time.sleep(0.25)
            timeout -= 0.25
        return None
    
    def watch_debug_event(self, event_type: EventType, callback: callable):
        self.listeners[event_type] = self.listeners.get(event_type, []) + [callback]

    def unwatch_debug_event(self, event_type: EventType, callback: callable):
        self.listeners[event_type] = [x for x in self.listeners.get(event_type, []) if x != callback]
