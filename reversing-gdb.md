# reversing-gdb
* **Event:** ForeverCTF
* **Problem Type:** Crypto
* **Point Value / Difficulty:** Easy
* **(Optional) Tools Required / Used:**  pwndbg

## Steps
#### Step 1
Log into a linux box and download the challenge. 

#### Step 2
Open the program in gdb: `gdb gdb`
#### Step 3
To see actually readable syntax instead of AT&T (which is really annoying and counterintuitive imo) type this: `set disassembly-flavor intel`
#### Step 4
Disassemble the main function: `disas main`
#### Step 5
Scroll down to the part where you see a call to `strlen` followed by a `cmp` instruction and `strncmp` (@addresses main+378, main+576)
#### Step 6
Set a breakpoint: `break *main+378`. Run the program and look at the value in rax. (0x25). This tells us that we need to input a 36 character string to get by the length check (off by one because of the add instruction before cmp)
               
#### Step 7
Run pwndbg again, but set a breakpoint at `break *main+576`. type out a 36 character string to get past the length check.
The breakpoint should trigger and yield you the flag.
