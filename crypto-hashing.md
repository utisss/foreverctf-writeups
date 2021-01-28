Looking at the source code, the hash looks relatively simplistic and reversible. In fact, this is a polynomial hash - which, although a hash, is not a cryptographic hash function (and thus not secure).

Let’s look at what the hash will equal at each step in the for loop when we encrypt the bytes [1, 2, 3, 4, 5]:

i=0:      hash = 1

i=1:      hash = b\*(1)+2 = 1\*b + 2

i=2:      hash = b\*(1\*b + 2) + 3 = 1\*b^2 + 2\*b + 3

i=3:      hash = b\*(1\*b^2 + 2\*b + 3) + 4 = 1\*b^3 + 2\*b^2 + 3\*b + 4

i=4:      hash = b\*(1\*b^3 + 2\*b^2 + 3\*b + 4) + 5 = 1\*b^4 + 2\*b^3 + 3\*b^2 + 4b + 5

(Notice how the coefficients are just the origiinal data values - his is why it is known as polynomial hash, and not cryptographically secure by any means.)

Note that at any step, we have:

new_hash = b*old_hash + flag[i]

And thus, we can derive the following values, assuming we know b:

flag[i] = new_hash%b
old_hash = new_hash//b

However, obviously we need to find which b was used to create the hash. If any message was hashed, this would be pretty hard. Fortunately, we know that flags always end in }, which has ascii code 125. Thus, we know that hash%b = 125. We can try values of b until one yields hash%b = 125, and attempt to reverse the hash that way. Since the flag also must start with utflag{, we can easily tell if the b we chose was correct.

```
h = 166645345105115875393235904068874575697290968472744761803553957459594486753568319
b = 1
while True:
    if h % b == 125:
        temp_h = h
        s = ''
        while temp_h > 0:
            if temp_h % b > 256:
                break
            s = chr(temp_h % b) + s
            temp_h //= b
        if 'utflag' in s:
            print(s)
            break
    b += 1
```

For those of you wondering why searching for b is feasible, notice that the hash is roughly proprtional to b^l, where l is the length of the flag. utflag{} is already 8 characters, and there’s definitely at least 2 characters in the flag, meaning the hash should be at least b^10. Taking hash^(1/10) yields roughly 100,000,000, which is a reasonable number of possible b’s to check (considering most can’t even pass the hash%b = 125 check). 
