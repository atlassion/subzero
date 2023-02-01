import os 
import sys
#Subzero version 1: Linux Only, no PE detection or anything
# --OFFSETS
INITIAL_LICENSE_CHECK = {
    "offset": 0x003A31F2,
    "value": b"\x55\x41\x57\x41",
    "patch": b"\x48\x31\xC0\xC3",
    "cmp": 0x4
}
PERSISTENT_LICENSE_CHECK = {
    "offset": 0x00399387,
    "value": b"\xE8\x08\x0E\x12\x00",
    "patch": b"\x90\x90\x90\x90\x90",
    "cmp": 0x5
}
PERSISTENT_LICENSE_CHECK_2 = {
    "offset": 0x0039939D,
    "value": b"\xE8\xF2\x0D\x12\x00",
    "patch": b"\x90\x90\x90\x90\x90",
    "cmp": 0x5
}
SERVER_VALIDATION_THREAD_OFF = {
    "offset": 0x003A4E30,
    "value": b"\x55\x41\x56\x53\x41\x89\xF6",
    "patch": b"\x48\x31\xC0\x48\xFF\xC0\xC3",
    "cmp": 0x7
}
LICENSE_NOTIFY_THREAD_OFF = {
    "offset": 0x003A2E82,
    "value": b"\x41",
    "patch": b"\xC3",
    "cmp": 0x1
}
DISABLE_CRASH_REPORTER_OFF = {
    "offset": 0x0038C9F0,
    "value": b"\x55",
    "patch": b"\xC3",
    "cmp": 0x1
}
def check_binary(path):
    is_file_read = os.access(path, os.R_OK)
    if not is_file_read:
        print(f"[+] ERROR: File {path} is not readable. Exit!")
        exit(1)
    is_file_write = os.access(path, os.W_OK)
    if not is_file_write:
        print(f"[+] ERROR: File {path} is not writable. Only check information")
    patcher(path)
def patcher(binary):
    F = open(binary, "rb+")
    F.seek(INITIAL_LICENSE_CHECK["offset"])
    data = F.read(INITIAL_LICENSE_CHECK["cmp"])
    if data == INITIAL_LICENSE_CHECK["value"]:
        print(f"[+] Found unpatched value at 0x{INITIAL_LICENSE_CHECK['offset']:x}")
        F.seek(INITIAL_LICENSE_CHECK["offset"])
        F.write(INITIAL_LICENSE_CHECK["patch"])
        print(f"[+] Writing patch ---")
    F.seek(PERSISTENT_LICENSE_CHECK["offset"])
    data = F.read(PERSISTENT_LICENSE_CHECK["cmp"])
    if data == PERSISTENT_LICENSE_CHECK["value"]:
        print(f"[+] Found unpatched value at 0x{PERSISTENT_LICENSE_CHECK['offset']:x}")
        F.seek(PERSISTENT_LICENSE_CHECK["offset"])
        F.write(PERSISTENT_LICENSE_CHECK["patch"])
        print(f"[+] Writing patch ---")
    F.seek(PERSISTENT_LICENSE_CHECK_2["offset"])
    data = F.read(PERSISTENT_LICENSE_CHECK_2["cmp"])
    if data == PERSISTENT_LICENSE_CHECK_2["value"]:
        print(f"[+] Found unpatched value at 0x{PERSISTENT_LICENSE_CHECK_2['offset']:x}")
        F.seek(PERSISTENT_LICENSE_CHECK_2["offset"])
        F.write(PERSISTENT_LICENSE_CHECK_2["patch"])
        print(f"[+] Writing patch ---")
    F.seek(SERVER_VALIDATION_THREAD_OFF["offset"])
    data = F.read(SERVER_VALIDATION_THREAD_OFF["cmp"])
    if data == SERVER_VALIDATION_THREAD_OFF["value"]:
        print(f"[+] Found unpatched value at 0x{SERVER_VALIDATION_THREAD_OFF['offset']:x}")
        F.seek(SERVER_VALIDATION_THREAD_OFF["offset"])
        F.write(SERVER_VALIDATION_THREAD_OFF["patch"])
        print(f"[+] Writing patch ---")
    F.seek(LICENSE_NOTIFY_THREAD_OFF["offset"])
    data = F.read(LICENSE_NOTIFY_THREAD_OFF["cmp"])
    if data == LICENSE_NOTIFY_THREAD_OFF["value"]:
        print(f"[+] Found unpatched value at 0x{LICENSE_NOTIFY_THREAD_OFF['offset']:x}")
        F.seek(LICENSE_NOTIFY_THREAD_OFF["offset"])
        F.write(LICENSE_NOTIFY_THREAD_OFF["patch"])
        print(f"[+] Writing patch ---")
    F.seek(DISABLE_CRASH_REPORTER_OFF["offset"])
    data = F.read(DISABLE_CRASH_REPORTER_OFF["cmp"])
    if data == DISABLE_CRASH_REPORTER_OFF["value"]:
        print(f"[+] Found unpatched value at 0x{DISABLE_CRASH_REPORTER_OFF['offset']:x}")
        F.seek(DISABLE_CRASH_REPORTER_OFF["offset"])
        F.write(DISABLE_CRASH_REPORTER_OFF["patch"])
        print(f"[+] Writing patch ---")
    print(f"[=] Saving file to {binary}")
    F.close()
    print(f"[+] DONE =]")

if __name__ == "__main__":
    print("[-] sublime patch for 4143 linux x64, python port")
    if len(sys.argv) < 2:
        print(f"[=] Arguments not set, use: {__file__} [path_to_sublime_text]")
        exit(1)
    check_binary(sys.argv[1])
