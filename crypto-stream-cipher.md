Firstly, when we connect to the netcat, we are able to encrypt whatever messages we want provided we follow the length limit. Upon inspecting the source code, we see that our message is read and xor’ed by some bytes given by a function named “rc4”.

rc4 is a type of stream cipher. Stream ciphers take a secret key and generate an infinite stream of pseudorandom bytes; this is usually used to create a symmetric encryption scheme by xoring messages with these bytes, similar to a one-time pad. In both of these, only people who have the original key can decrypt by xoring out the right bytes.

However, note the part of the source that is marked by the comment. If you look up any standard implementation of rc4, you can notice that the initial state of the array is used in the xor bytes. This is bad, since it leaks all the information necessary to simulate the pseudorandom byte generation ourselves and recover the flag.

Thus, we can encrypt a known message (all “A”s for example), and recover the first 255 bytes of the array. For the last byte, there are only 256 possible values of those, so we can feasibly try all of them and simulate what the resulting bytes would be. 

```
from pwn import *

enchex = open('message.txt', 'r').read()
enc = []
for i in range(len(enchex)//2):
    enc.append(int(enchex[2*i:2*i+2], 16))

conn = remote('localhost', '9001')

conn.recvline()
conn.sendline('A'*255)
s = conn.recvline()
s = s[:-1]

init_bytes = []
for i in range(255):
    init_bytes.append(ord('A') ^ int(s[2*i:2*i+2], 16))

def new_rc4(init, length):
    S = init
    out = []

    for i in range(256):
        out.append(S[i])

    i = j = 0
    while len(out) < length:
        i = ( i + 1 ) % 256
        j = ( j + S[i] ) % 256
        S[i] , S[j] = S[j] , S[i]
        out.append(S[(S[i] + S[j]) % 256])

    return out

for final_byte in range(256):
     rc4 = new_rc4(init_bytes + [final_byte], len(enc))
     s = ''.join([chr(rc4[i] ^ enc[i]) for i in range(len(enc))])
     if 'utflag' in s:
        print(s)
        break
```

