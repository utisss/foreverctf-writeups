We will start by inspecting the assembly of our binary. 

Condensed, commented output of `objdump -d -M intel leak`

```
0000000000401236 <main>:
  401236:       f3 0f 1e fa             endbr64 
  40123a:       55                      push   rbp
  40123b:       48 89 e5                mov    rbp,rsp

# Our stack frame is 0x10 bytes long
  40123e:       48 83 ec 10             sub    rsp,0x10
  401242:       bf 00 00 00 00          mov    edi,0x0

# Seeding rand() with system time
  401247:       e8 d4 fe ff ff          call   401120 <time@plt>
  40124c:       89 c7                   mov    edi,eax
  40124e:       e8 ad fe ff ff          call   401100 <srand@plt>

# Generates a random number and stores it at [rbp-0x4]
  401253:       e8 e8 fe ff ff          call   401140 <rand@plt>
  401258:       89 45 fc                mov    DWORD PTR [rbp-0x4],eax

# Print prompts
  40125b:       48 8d 3d a6 0d 00 00    lea    rdi,[rip+0xda6]        # 402008 <_IO_stdin_used+0x8>
  401262:       e8 69 fe ff ff          call   4010d0 <puts@plt>
  401267:       48 8d 3d af 0d 00 00    lea    rdi,[rip+0xdaf]        # 40201d <_IO_stdin_used+0x1d>
  40126e:       e8 5d fe ff ff          call   4010d0 <puts@plt>

# Read out input into the buffer
  401273:       48 8b 05 06 2e 00 00    mov    rax,QWORD PTR [rip+0x2e06]        # 404080 <stdin@@GLIBC_2.2.5>
  40127a:       48 89 c2                mov    rdx,rax
  40127d:       be 64 00 00 00          mov    esi,0x64
  401282:       48 8d 3d 17 2e 00 00    lea    rdi,[rip+0x2e17]        # 4040a0 <buffer>
  401289:       e8 82 fe ff ff          call   401110 <fgets@plt>

# Print more prompt
  40128e:       48 8d 3d 99 0d 00 00    lea    rdi,[rip+0xd99]        # 40202e <_IO_stdin_used+0x2e>
  401295:       e8 36 fe ff ff          call   4010d0 <puts@plt>

# Calls printf(buffer)
  40129a:       48 8d 3d ff 2d 00 00    lea    rdi,[rip+0x2dff]        # 4040a0 <buffer>
  4012a1:       b8 00 00 00 00          mov    eax,0x0
  4012a6:       e8 45 fe ff ff          call   4010f0 <printf@plt>

# Prints a newline
  4012ab:       bf 0a 00 00 00          mov    edi,0xa
  4012b0:       e8 0b fe ff ff          call   4010c0 <putchar@plt>

# Compare the number we typed into buffer to the random number
  4012b5:       48 8d 3d e4 2d 00 00    lea    rdi,[rip+0x2de4]        # 4040a0 <buffer>
  4012bc:       e8 6f fe ff ff          call   401130 <atoi@plt>
  4012c1:       39 45 fc                cmp    DWORD PTR [rbp-0x4],eax
  4012c4:       75 18                   jne    4012de <main+0xa8>

# If they're equal give a shell
  4012c6:       48 8d 3d 6f 0d 00 00    lea    rdi,[rip+0xd6f]        # 40203c <_IO_stdin_used+0x3c>
  4012cd:       e8 fe fd ff ff          call   4010d0 <puts@plt>
  4012d2:       48 8d 3d 75 0d 00 00    lea    rdi,[rip+0xd75]        # 40204e <_IO_stdin_used+0x4e>
  4012d9:       e8 02 fe ff ff          call   4010e0 <system@plt>

# If they're not equal keep going
  4012de:       48 8d 3d 71 0d 00 00    lea    rdi,[rip+0xd71]        # 402056 <_IO_stdin_used+0x56>
  4012e5:       e8 e6 fd ff ff          call   4010d0 <puts@plt>

# Read to buffer again
  4012ea:       48 8b 05 8f 2d 00 00    mov    rax,QWORD PTR [rip+0x2d8f]        # 404080 <stdin@@GLIBC_2.2.5>
  4012f1:       48 89 c2                mov    rdx,rax
  4012f4:       be 64 00 00 00          mov    esi,0x64
  4012f9:       48 8d 3d a0 2d 00 00    lea    rdi,[rip+0x2da0]        # 4040a0 <buffer>
  401300:       e8 0b fe ff ff          call   401110 <fgets@plt>

# Check if they're equal again
  401305:       48 8d 3d 94 2d 00 00    lea    rdi,[rip+0x2d94]        # 4040a0 <buffer>
  40130c:       e8 1f fe ff ff          call   401130 <atoi@plt>
  401311:       39 45 fc                cmp    DWORD PTR [rbp-0x4],eax
  401314:       75 18                   jne    40132e <main+0xf8>

# If they're equal give a shell
  401316:       48 8d 3d 1f 0d 00 00    lea    rdi,[rip+0xd1f]        # 40203c <_IO_stdin_used+0x3c>
  40131d:       e8 ae fd ff ff          call   4010d0 <puts@plt>
  401322:       48 8d 3d 25 0d 00 00    lea    rdi,[rip+0xd25]        # 40204e <_IO_stdin_used+0x4e>
  401329:       e8 b2 fd ff ff          call   4010e0 <system@plt>

# If they're not equal keep going
  40132e:       48 8d 3d 43 0d 00 00    lea    rdi,[rip+0xd43]        # 402078 <_IO_stdin_used+0x78>
  401335:       e8 96 fd ff ff          call   4010d0 <puts@plt>
  40133a:       b8 00 00 00 00          mov    eax,0x0
  40133f:       c9                      leave  
  401340:       c3                      ret    
  401341:       66 2e 0f 1f 84 00 00    nop    WORD PTR cs:[rax+rax*1+0x0]
  401348:       00 00 00 
  40134b:       0f 1f 44 00 00          nop    DWORD PTR [rax+rax*1+0x0]

```

We can see that the basic flow of our program is to generate a random number and
ask the user to guess it.  The critical bug is caused `printf(buffer)`. If the
user inputs a format string such as "%d", this line will attempt to print some
number. 

If we recall x86-64 calling convention, we know that the first 6 arguments will
be passed through rdi, rsi, rdx, rcx, r8 and r9 respectively. Any additional
arguments are pushed onto the stack in reverse order. Printf just assumes that
we've correctly passed enough arguments. If we pass less arguments than the
format specifies, we'll begin printing registers and stack values.

So a call to `printf("%d")` is going to print the value of esi (bottom 32 bits
of rsi).  The key insight from the calling convention is to notice that printing
more than 5 values is going to leak stack values.

If we were to call `printf("%p %p %p %p %p %p %p")`, we will print the following
values `rsi rdx rcx r8 r9 [rsp] [rsp+8]`. It may also be worth noting that
printf considers every value passed to be 8 bytes long. So even if we print an
int with `%d`, printf still expects 8 bytes, not 4 bytes.

In this program the stack frame of main looks like:

```
Note: Zeroes are unreferenced memory, their value may be non-zero at runtime.

rsp (rbp-0x10):   00000000    00000000
rbp-0x8           00000000    rrrrrrrr <=== This is the random number
rbp:             [saved rbp] [saved rip]
```

So we will be interested in the 7th value to be printed. We can use the format
`%7$p` to only print the 7th value as a 64-bit hex integer. Notice that due to
endianness we will actually print `0xrrrrrrrr00000000`. If we right shift this
number by 32 and convert to an int we will have the random value.
