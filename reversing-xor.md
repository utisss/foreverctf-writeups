# reversing-xor
* **Event:** ForeverCTF
* **Problem Type:** Crypto
* **Point Value / Difficulty:** Easy
* **(Optional) Tools Required / Used:**  pwndbg

## Steps
#### Step 1
Log into a linux box and download the challenge. 
#### Step 2
Open the program in gdb: `gdb xor`
#### Step 3
To see actually readable syntax instead of AT&T (which is really annoying and counterintuitive imo) type this: `set disassembly-flavor intel`
#### Step 4
Disassemble the main function: `disas main`
#### Step 5
Scroll down to the part where you see a `xor eax, 0x41`. If you look closely at the instructions, you will see that this piece of code is called repeatedly in a loop which means that we probably found the "encrpytion" loop.
#### Step 6
So now that we know that our encryption key is "0x41", we need to dump the encrypted flag and xor each byte with 0x41 to get the flag.       
#### Step 7
We could try to extract the encrypted flag, but it is much easier to trash the binary and just xor the whole file with 0x41 and then run strings on the "decrypted" binary

I used this python2 script modified from (here)[https://www.megabeets.net/xor-files-python/]: 

```
import sys

file1_b = bytearray(open(sys.argv[1], 'rb').read())
size = len(file1_b)

# XOR between the files
for i in range(size):
	file1_b[i] = file1_b[i] ^ 0x41

# Write the XORd bytes to the output file	
open(sys.argv[2], 'wb').write(file1_b)
```

#### Step 8
Run strings on the output of the script `strings out.bin`. Scroll up and find the flag.
