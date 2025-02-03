import ctypes


K32 = ctypes.windll.kernel32
SYNCHRONIZE = 0x00100000


OpenMutexW = K32.OpenMutexW
OpenMutexW.argtypes = [ctypes.c_uint32, ctypes.c_bool, ctypes.c_wchar_p]

CloseHandle = K32.CloseHandle
CloseHandle.argtypes = [ctypes.c_void_p]

OpenProcess = K32.OpenProcess
OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_bool, ctypes.c_uint32]

CreateRemoteThread = K32.CreateRemoteThread
CreateRemoteThread.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p]

WaitForSingleObject = K32.WaitForSingleObject
WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
