The program reads in the flag, then reads in some input from us. It then reads
in two numbers, and prints the substring of our input from the first number to
the second. C doesn't check bounds on arrays. This means that if you have two
arrays next to each other, a negative index to the second array can end up in
the first array. Here is a diagram that might make that simpler

```
          Array 1's end | Array 2's beginning
       Index| 98| 99|100|  0|  1|  2|
Array2[-1] goes here ^
```

We can use this to print out the flag instead of our input. However, this only
works if the two arrays are next to each other in memory.  Stuff like this can
be hard to predict, as the compiler can put variables in any order they want.
However, you can normally find the memory layout by looking at the dissasembly.
We know that the first argument to fgets is the address of the buffer to put the
data into. We can generate dissasembly using a lot of tools, but for this
writeup I'll be using `objdump -d`. Here is the relevant disassembly for fgets.

```
  40076d:       48 8d 85 20 ff ff ff    lea    rax,[rbp-0xe0]
  400774:       be 64 00 00 00          mov    esi,0x64
  400779:       48 89 c7                mov    rdi,rax
  40077c:       e8 5f fe ff ff          call   4005e0 <fgets@plt>
```

We know that `rdi`, the first argument to fgets, is the location of the buffer.
That means the flag buffer starts at `rbp-0xe0`. The length of the buffer is
the second argument, in `esi`. Therefore, the buffer goes from `[rbp-0xe0,
rbp-0xe0+0x64] = [rbp-0xe0,rbp-0x7c]`. You might notice that the start of the
buffer is numerically less than the end. With arrays, the first element is
always stored at the numerically smallest address. Next, we can find the address
of our input.

```
  4007a8:       48 8d 45 90             lea    rax,[rbp-0x70]
  4007ac:       48 89 c6                mov    rsi,rax
  4007af:       bf 1f 09 40 00          mov    edi,0x40091f
  4007b4:       b8 00 00 00 00          mov    eax,0x0
  4007b9:       e8 42 fe ff ff          call   400600 <__isoc99_scanf@plt>
```

Again, `edi` is our first parameter (If you are confused why the parameter is
`edi` instead of `rdi`, just remember that `edi` is the lower 32 bits of `rdi`.
That means if we know our value will fit in 32 bits, there is no difference
between using `edi` and `rdi`). This is the address of our format string. The
one we care about this time is the second parameter, or `rsi`. We see that `rsi`
is set to `rbp-0x70`. This is the start of our buffer. We don't actually know
the length of the second buffer, but from earlier in the assembly we can find
that its 100 again. That means that our second buffer is
`[rbp-0x70,rbp-0x70+0x64] = [rbp-0x70,rbp-0xc]` We can summarize our findings in
the diagram before.

```
rbp-0xc: Last byte of input
rbp-0xd: Second to last byte of input
...
rbp-0x6f: Second byte of input
rbp-0x70: Start of our input
rbp-0x71: Who knows
...
rbp-0x7b: More random stuff 
rbp-0x7c: Last byte of the flag
rbp-0x7d: Second to last byte of flag
...
rbp-0xdf: Second byte of flag
rbp-0xe0: First byte of flag
```

We can see that the difference between the first byte of our input and the first
byte of the flag is `0x70 - 0xe0 = -112`. This means that if we input `-112,-12`
to the program, it will print out the flag.
