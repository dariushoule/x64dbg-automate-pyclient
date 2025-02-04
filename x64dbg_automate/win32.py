import ctypes


K32 = ctypes.windll.kernel32
U32 = ctypes.windll.user32

CloseHandle = K32.CloseHandle
CloseHandle.argtypes = [ctypes.c_void_p]

OpenProcess = K32.OpenProcess
OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_bool, ctypes.c_uint32]

CreateRemoteThread = K32.CreateRemoteThread
CreateRemoteThread.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p]

WaitForSingleObject = K32.WaitForSingleObject
WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]

SetConsoleCtrlHandler = K32.SetConsoleCtrlHandler
SetConsoleCtrlHandler.argtypes = [ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int), ctypes.c_bool]

GetTempPathW = K32.GetTempPathW
GetTempPathW.argtypes = [ctypes.c_uint32, ctypes.c_wchar_p]

EnumWindows = U32.EnumWindows
EnumWindows.argtypes = [ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p), ctypes.c_void_p]

GetWindowTextW = U32.GetWindowTextW
GetWindowTextW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_int]

GetWindowThreadProcessId = U32.GetWindowThreadProcessId
GetWindowThreadProcessId.argtypes = [ctypes.c_void_p, ctypes.c_void_p]