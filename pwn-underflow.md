# Doge
# Binary Exploitation: Easy

Using static analysis tools such as radare2 or Ghidra and reading through the 
assembly or decompiled source code, we can see that when the user requests the
"doge" item, their balance is not checked for an integer underflow.    

https://en.wikipedia.org/wiki/Arithmetic_underflow   

What this means is that when we subtract 3 (the cost of the item) from the 
user's balance, their balance will "wrap around" close to the largest possible 
value that an integer can take on. So we can keep purchasing the doge item
until the balance becomes less than 3, then purchase the item again to get a 
crazy large balance. 

Finally, we have enough bityen to purchase the win, so we get a shell and
```cat flag.txt```.