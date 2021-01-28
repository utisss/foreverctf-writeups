Since the prime is very small, we can simply brute force to find the secret values for Alice and Bob:

```
>>> def find_secret(base, pub, mod):
...     priv = 0
...     cur = 1
...     while cur != pub:
...         cur  = cur * base % mod
...         priv += 1
...     return priv
... 
>>> a = find_secret(69, 2609, 3457)
>>> b = find_secret(69, 1252, 3457)
>>> print(a,b)
191 7
```

Alice’s secret is 191, while Bob’s is 7. Their secret can be computed in multiple ways: g^(ab), A^b, and B^a are all equivalent.

