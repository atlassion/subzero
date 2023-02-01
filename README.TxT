                SubZero - A simple sublime patcher script
--START of output
[+] Found unpatched value at 0x3a31f2
[+] Writing patch ---
[+] Found unpatched value at 0x399387
[+] Writing patch ---
[+] Found unpatched value at 0x39939d
[+] Writing patch ---
[+] Found unpatched value at 0x3a4e30
[+] Writing patch ---
[+] Found unpatched value at 0x3a2e82
[+] Writing patch ---
[+] Found unpatched value at 0x38c9f0
[+] Writing patch ---
[=] Saving file to ./dump/sublime_text/sublime_text
[+] DONE
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