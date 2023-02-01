import os 
import sys
import platform
#SubZero v2, written by socialfright on github
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
#-- OFFSETS WINDOWS
INITIAL_LICENSE_CHECK_WINDOWS = {
    "offset": 0x000A9864,
    "value": b"\x55\x41\x57\x41",
    "patch": b"\x48\x31\xC0\xC3",
    "cmp": 0x4
}
PERSISTENT_LICENSE_CHECK_WINDOWS = {
    "offset": 0x000071FE,
    "value": b"\xE8\x71\x8B\x20\x00",
    "patch": b"\x90\x90\x90\x90\x90",
    "cmp": 0x5
}
PERSISTENT_LICENSE_CHECK_2_WINDOWS = {
    "offset": 0x00007217,
    "value": b"\xE8\x58\x8B\x20\x00",
    "patch": b"\x90\x90\x90\x90\x90",
    "cmp": 0x5
}
SERVER_VALIDATION_THREAD_OFF_WINDOWS = {
    "offset": 0x000AB682,
    "value": b"\x55\x56\x57\x48\x83\xEC\x30",
    "patch": b"\x48\x31\xC0\x48\xFF\xC0\xC3",
    "cmp": 0x7
}
LICENSE_NOTIFY_THREAD_OFF_WINDOWS = {
    "offset": 0x000A940F,
    "value": b"\x55",
    "patch": b"\xC3",
    "cmp": 0x1
}
DISABLE_CRASH_REPORTER_OFF_WINDOWS = {
    "offset": 0x00000400,
    "value": b"\x41",
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
    pe = platform.architecture(path)
    if pe[1] == "ELF":
        print(f"[>] Linux ELF: Detected -> {os.path.getsize(path)}")
        patcher_linux(path)
    elif pe[1] == "WindowsPE":
        print(f"[>] Windows PE: Detected -> {os.path.getsize(path)}")
        patch_windows(path)
    else:
        print("[+] Unsupported Version or Binary")
        exit()
def patcher_linux(binary):
    con_l = input("Continue? Y/N")
    if con_l.upper() == 'Y':
        F = open(binary, "rb+")
        F.seek(INITIAL_LICENSE_CHECK["offset"])
        data = F.read(INITIAL_LICENSE_CHECK["cmp"])
        if data == INITIAL_LICENSE_CHECK["value"]:
            print(f"[+] Found unpatched value for 'isValidLicense'at 0x{INITIAL_LICENSE_CHECK['offset']:x}")
            F.seek(INITIAL_LICENSE_CHECK["offset"])
            F.write(INITIAL_LICENSE_CHECK["patch"])
            print(f"[+] Writing patch --- {INITIAL_LICENSE_CHECK['value']} --> {INITIAL_LICENSE_CHECK['patch']}")
        F.seek(PERSISTENT_LICENSE_CHECK["offset"])
        data = F.read(PERSISTENT_LICENSE_CHECK["cmp"])
        if data == PERSISTENT_LICENSE_CHECK["value"]:
            print(f"[+] Found unpatched value for 'invalidationFunction'at 0x{PERSISTENT_LICENSE_CHECK['offset']:x}")
            F.seek(PERSISTENT_LICENSE_CHECK["offset"])
            F.write(PERSISTENT_LICENSE_CHECK["patch"])
            print(f"[+] Writing patch --- {PERSISTENT_LICENSE_CHECK['value']} --> {PERSISTENT_LICENSE_CHECK['patch']}")
        F.seek(PERSISTENT_LICENSE_CHECK_2["offset"])
        data = F.read(PERSISTENT_LICENSE_CHECK_2["cmp"])
        if data == PERSISTENT_LICENSE_CHECK_2["value"]:
            print(f"[+] Found unpatched value for 'validationFunction' at 0x{PERSISTENT_LICENSE_CHECK_2['offset']:x}")
            F.seek(PERSISTENT_LICENSE_CHECK_2["offset"])
            F.write(PERSISTENT_LICENSE_CHECK_2["patch"])
            print(f"[+] Writing patch --- {PERSISTENT_LICENSE_CHECK_2['value']} --> {PERSISTENT_LICENSE_CHECK_2['patch']}")
        F.seek(SERVER_VALIDATION_THREAD_OFF["offset"])
        data = F.read(SERVER_VALIDATION_THREAD_OFF["cmp"])
        if data == SERVER_VALIDATION_THREAD_OFF["value"]:
            print(f"[+] Found unpatched value for 'serverThread' at 0x{SERVER_VALIDATION_THREAD_OFF['offset']:x}")
            F.seek(SERVER_VALIDATION_THREAD_OFF["offset"])
            F.write(SERVER_VALIDATION_THREAD_OFF["patch"])
            print(f"[+] Writing patch --- {SERVER_VALIDATION_THREAD_OFF['value']} --> {SERVER_VALIDATION_THREAD_OFF['patch']}")
        F.seek(LICENSE_NOTIFY_THREAD_OFF["offset"])
        data = F.read(LICENSE_NOTIFY_THREAD_OFF["cmp"])
        if data == LICENSE_NOTIFY_THREAD_OFF["value"]:
            print(f"[+] Found unpatched value for 'licenseNotifyThread' at 0x{LICENSE_NOTIFY_THREAD_OFF['offset']:x}")
            F.seek(LICENSE_NOTIFY_THREAD_OFF["offset"])
            F.write(LICENSE_NOTIFY_THREAD_OFF["patch"])
            print(f"[+] Writing patch --- {LICENSE_NOTIFY_THREAD_OFF['value']} --> {LICENSE_NOTIFY_THREAD_OFF['patch']}")
        F.seek(DISABLE_CRASH_REPORTER_OFF["offset"])
        data = F.read(DISABLE_CRASH_REPORTER_OFF["cmp"])
        if data == DISABLE_CRASH_REPORTER_OFF["value"]:
            print(f"[+] Found unpatched value for 'crashReporter' at 0x{DISABLE_CRASH_REPORTER_OFF['offset']:x}")
            F.seek(DISABLE_CRASH_REPORTER_OFF["offset"])
            F.write(DISABLE_CRASH_REPORTER_OFF["patch"])
            print(f"[+] Writing patch --- {DISABLE_CRASH_REPORTER_OFF['value']} --> {DISABLE_CRASH_REPORTER_OFF['patch']}")
        print(f"[=] Saving file to {binary}")
        F.close()
        print(f"[+] DONE =]")
    elif con_l.upper() == 'N':
        print("Exiting...")
        exit()
    else:
        print("No Input ")
        exit()
def patch_windows(binary):
    con_l = input("Continue? Y/N")
    if con_l.upper() == 'Y':
        F = open(binary, "rb+")
        F.seek(INITIAL_LICENSE_CHECK_WINDOWS["offset"])
        data = F.read(INITIAL_LICENSE_CHECK_WINDOWS["cmp"])
        if data == INITIAL_LICENSE_CHECK_WINDOWS["value"]:
            print(f"[+] Found unpatched value for 'isValidLicense' at 0x{INITIAL_LICENSE_CHECK_WINDOWS['offset']:x}")
            F.seek(INITIAL_LICENSE_CHECK_WINDOWS["offset"])
            F.write(INITIAL_LICENSE_CHECK_WINDOWS["patch"])
            print(f"[+] Writing patch --- {INITIAL_LICENSE_CHECK_WINDOWS['value']} --> {INITIAL_LICENSE_CHECK_WINDOWS['patch']}")
        F.seek(PERSISTENT_LICENSE_CHECK_WINDOWS["offset"])
        data = F.read(PERSISTENT_LICENSE_CHECK_WINDOWS["cmp"])
        if data == PERSISTENT_LICENSE_CHECK_WINDOWS["value"]:
            print(f"[+] Found unpatched value for 'invalidationFunction' at 0x{PERSISTENT_LICENSE_CHECK_WINDOWS['offset']:x}")
            F.seek(PERSISTENT_LICENSE_CHECK_WINDOWS["offset"])
            F.write(PERSISTENT_LICENSE_CHECK_WINDOWS["patch"])
            print(f"[+] Writing patch --- {PERSISTENT_LICENSE_CHECK_WINDOWS['value']} --> {PERSISTENT_LICENSE_CHECK_WINDOWS['patch']}")
        F.seek(PERSISTENT_LICENSE_CHECK_2_WINDOWS["offset"])
        data = F.read(PERSISTENT_LICENSE_CHECK_2_WINDOWS["cmp"])
        if data == PERSISTENT_LICENSE_CHECK_2_WINDOWS["value"]:
            print(f"[+] Found unpatched value for 'validationFunction' at 0x{PERSISTENT_LICENSE_CHECK_2_WINDOWS['offset']:x}")
            F.seek(PERSISTENT_LICENSE_CHECK_2_WINDOWS["offset"])
            F.write(PERSISTENT_LICENSE_CHECK_2_WINDOWS["patch"])
            print(f"[+] Writing patch --- {PERSISTENT_LICENSE_CHECK_2_WINDOWS['value']} --> {PERSISTENT_LICENSE_CHECK_2_WINDOWS['patch']}")
        F.seek(SERVER_VALIDATION_THREAD_OFF_WINDOWS["offset"])
        data = F.read(SERVER_VALIDATION_THREAD_OFF_WINDOWS["cmp"])
        if data == SERVER_VALIDATION_THREAD_OFF_WINDOWS["value"]:
            print(f"[+] Found unpatched value for 'serverThread' at 0x{SERVER_VALIDATION_THREAD_OFF_WINDOWS['offset']:x}")
            F.seek(SERVER_VALIDATION_THREAD_OFF_WINDOWS["offset"])
            F.write(SERVER_VALIDATION_THREAD_OFF_WINDOWS["patch"])
            print(f"[+] Writing patch --- {SERVER_VALIDATION_THREAD_OFF_WINDOWS['value']} --> {SERVER_VALIDATION_THREAD_OFF_WINDOWS['patch']}")
        F.seek(LICENSE_NOTIFY_THREAD_OFF_WINDOWS["offset"])
        data = F.read(LICENSE_NOTIFY_THREAD_OFF_WINDOWS["cmp"])
        if data == LICENSE_NOTIFY_THREAD_OFF_WINDOWS["value"]:
            print(f"[+] Found unpatched value for 'licenseNotifyThread' at 0x{LICENSE_NOTIFY_THREAD_OFF_WINDOWS['offset']:x}")
            F.seek(LICENSE_NOTIFY_THREAD_OFF_WINDOWS["offset"])
            F.write(LICENSE_NOTIFY_THREAD_OFF_WINDOWS["patch"])
            print(f"[+] Writing patch --- {LICENSE_NOTIFY_THREAD_OFF_WINDOWS['value']} --> {LICENSE_NOTIFY_THREAD_OFF_WINDOWS['patch']}")
        F.seek(DISABLE_CRASH_REPORTER_OFF_WINDOWS["offset"])
        data = F.read(DISABLE_CRASH_REPORTER_OFF_WINDOWS["cmp"])
        if data == DISABLE_CRASH_REPORTER_OFF_WINDOWS["value"]:
            print(f"[+] Found unpatched value for 'crashReporter' at 0x{DISABLE_CRASH_REPORTER_OFF_WINDOWS['offset']:x}")
            F.seek(DISABLE_CRASH_REPORTER_OFF_WINDOWS["offset"])
            F.write(DISABLE_CRASH_REPORTER_OFF_WINDOWS["patch"])
            print(f"[+] Writing patch --- {DISABLE_CRASH_REPORTER_OFF_WINDOWS['value']} --> {DISABLE_CRASH_REPORTER_OFF_WINDOWS['patch']}")
        print(f"[=] Saving file to {binary}")
        F.close()
        print(f"[+] DONE =]")
    elif con_l.upper() == 'N':
        print("Exiting...")
        exit()
    else:
        print("No Input ")
        exit()

if __name__ == "__main__":
    print("[-] sublime patch for 4143 linux and windows x64, python port")
    if len(sys.argv) < 2:
        print(f"[=] Arguments not set, use: {__file__} [path_to_sublime_text]")
        exit(1)
    check_binary(sys.argv[1])

