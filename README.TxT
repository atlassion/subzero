                SubZero - A simple sublime patcher script
--START of output
[-] sublime patch for 4143 linux and windows x64, python port
[>] Linux ELF: Detected -> 9055008
Continue? Y/Ny
[+] Found unpatched value for 'isValidLicense'at 0x3a31f2
[+] Writing patch --- b'UAWA' --> b'H1\xc0\xc3'
[+] Found unpatched value for 'invalidationFunction'at 0x399387
[+] Writing patch --- b'\xe8\x08\x0e\x12\x00' --> b'\x90\x90\x90\x90\x90'
[+] Found unpatched value for 'validationFunction' at 0x39939d
[+] Writing patch --- b'\xe8\xf2\r\x12\x00' --> b'\x90\x90\x90\x90\x90'
[+] Found unpatched value for 'serverThread' at 0x3a4e30
[+] Writing patch --- b'UAVSA\x89\xf6' --> b'H1\xc0H\xff\xc0\xc3'
[+] Found unpatched value for 'licenseNotifyThread' at 0x3a2e82
[+] Writing patch --- b'A' --> b'\xc3'
[+] Found unpatched value for 'crashReporter' at 0x38c9f0
[+] Writing patch --- b'U' --> b'\xc3'
[=] Saving file to /home/kennedy/Downloads/sublime_text/sublime_text
[+] DONE =]

--END

This is a patcher for Sublime Text 4143 on Linux 64bit.
I took the offsets from a random github gist. The original code
was written by someone in C but I ported it to python and added 
some things. I also took some code from another patcher.
This is my first python program. Thanks =] - socialfright

V2:
Added automatic binary detection
Added offsets for windows
support for sublime 4143
IT MIGHT NOT WORK ON WINDOWS, if so add a issue or message me at socialfright@pm.me
Credits -
https://github.com/CodigoCristo/sublimepatch - C code
https://gist.github.com/lugrus2000/1fc55158b87f94d799392a6dd1ac0ce2 - Offsets and Hex for patch
https://gist.github.com/dmknght/1fe4673ef08e9d89160e57ae19cadc53 - Code taken and reused for patching
Thanks to all.