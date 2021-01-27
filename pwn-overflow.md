To start with, we can dissasemble the program using the tool of your choice.
Then, we can try to analyze main to see what it does. The dissasembly shown will
be edited to only show the important parts. We see from the below line that the
code sets some stack value at `[rbp-0x4]` to 0.

`  4011bc:       c7 45 fc 00 00 00 00    mov    DWORD PTR [rbp-0x4],0x0`

We also see that the code branches on this value later on. Since it compares the
value to zero, and skips `get_flag` if it is zero, we can assume that we want to
change the stack value at `[rbp-0x4]` to some non zero value.

```
  4011e0:       83 7d fc 00             cmp    DWORD PTR [rbp-0x4],0x0
  4011e4:       74 0a                   je     4011f0 <main+0x40>

```

```
  4011cf:       48 8d 45 90             lea    rax,[rbp-0x70]
  4011d3:       48 89 c7                mov    rdi,rax
  4011db:       e8 a0 fe ff ff          call   401080 <gets@plt>
```

We can see from this code that `gets` is called on a stack address of
`[rbp-0x70]`. `gets` is a function that reads in user input from standard in to
the memory address given until it hits a newline. However, this function is very
unsafe. Thats because if we give it more data than the size of the buffer can
hold, it will start overwriting other information. We can see that the buffer
ranges from `[rbp-0x70]` inclusive to `[rbp-0x4]` exclusive. We know this
because the parameter passed to `gets` is the start of the buffer, and it
continues upwards until it gets to some other variable.

```
rbp-0x4: Integer variable
rbp-0x5: Last byte of buffer
rbp-0x6: Second to last byte of buffer
...
rbp-0x6f: Second byte of buffer
rbp-0x70: First byte of buffer
```

We then know that the buffer is `0x70 - 0x4 = 0x6c = 108` bytes long. That means
that if we give it any more bytes than that it will overwrite `[rbp-0x4]`. If we
send the program 109 bytes, it will overflow the integer variable and give us a
shell. The simple way to do this is just give it a bunch of "A"s. Just connect
to the netcat, and type in more than 108 letters, then press enter. It will
change the value of the integer, causing the code to call `get_flag` and give
you a shell.

