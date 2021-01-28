Although it’s impossible to take the output of the AES and directly decrypt it, we can notice in the source code that they are using ECB. ECB encrypts each block separately, without any use of the previous encryptions. However, since equal blocks will give the same output, this can be used to bruteforce the flag in this case.

Since we are allowed to encrypt whatever message we want, suppose we encrypted 15 As. The message would look like this [spaces added to separate the blocks]:

`AAAAAAAAAAAAAAA? ????????????????`

Now, let’s say we encrypted 15 As, followed by a “guess” (marked by a *), followed by another 15 As:

`AAAAAAAAAAAAAAA* AAAAAAAAAAAAAAA? ????????????????`

By changing the guess to different characters, and checking if the resulting AES output has 2 matching blocks, we can successfully determine whether our guess was correct. 

As an example, let’s say the unknown message at the end is “Hello_World”, and we had our guess character as B. The two blocks would look like:

`AAAAAAAAAAAAAAAB AAAAAAAAAAAAAAAH ello_World`

Once encrypted, the blocks won’t match - signifying that our guess was incorrect. However, had we guessed H instead, we would have:

`AAAAAAAAAAAAAAAH AAAAAAAAAAAAAAAH ello_World`

Since these would encrypt to the same value, we would know our guess is correct. We could continue this process to the next letter by guessing 14 A’s, followed by H, the guess, and then another 14 A’s, yielding:

`AAAAAAAAAAAAAAH* AAAAAAAAAAAAAAHe llo_World`
Using this same strategy for the challenge, we can retrieve the flag:

```
from pwn import *

flag = ''
poss_chars = 'abcdefghijklmnopqrstuvwxyz0123456789_{}'
conn = remote('localhost', '9001')
while True:
    alen = (15-len(flag)%16)%16
    for guess in poss_chars:
        conn.recvline()
        guess_str = 'A'*alen+flag+guess+'A'*alen
        conn.sendline(guess_str)
        conn.recvline()
        s = conn.recvline()
        
        ind = (alen+len(flag))//16
        tar = s[ind*32: ind*32+32]
        matches = False
        for i in range(len(s)//32):
            if i != ind and tar == s[32*i:32*i+32]:
                matches = True

        if matches:
            flag += guess
            break
    print('Current Flag:', flag)
    if flag[-1] == '}':
        break
print(flag)
```
