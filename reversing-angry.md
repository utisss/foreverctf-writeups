You should watch huck's talk to learn how angr works (linked in the problem
hint). The script below can be used for pretty much any basic angr problem. Just
change the numbers to what you want for the problem.

```python
#!/usr/bin/python3
import angr
import claripy
from pwn import *

# Our input is 100 ints, 4 bytes each
FLAG_LEN = 4 * 100
# Our binary is PIE, which means it can be loaded in at any base address
# Use the same base address as whatever you are using for disassembly
# So you can copy paste addresses
base_addr = 0x4000000
proj = angr.Project('./build/angry', main_opts={'base_addr': base_addr})
# We create a list of symbolic bytes, the same number as the length of our input
# Ignore the 'flag_%d', we just have to name the symbolic bytes for debugging
# purposes. It doesn't do anything
flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(FLAG_LEN)]
# We then concatenate the symbolic bytes into a single symbolic variable
flag = claripy.Concat( *flag_chars)
# Use this if your input has to be a null terminated string
#flag = claripy.Concat( *flag_chars + [claripy.BVV(b'\x00')])
# Use this if your input must end with a newline
#flag = claripy.Concat( *flag_chars + [claripy.BVV(b'\n')])
# We then create our starting state
state = proj.factory.full_init_state(
        add_options=angr.options.unicorn,
        args=['./build/angry'],
        # If you want your symbolic variable to be standard in
        stdin=flag,
        # If you want the symbolic variable to be a argument
        #args=['./a',flag],
)
# When the file tries to print out the flag, angr will complain that the file
#doesn't exist. We can create a symbolic file to stop this. It doesn't actually
#matter in the end though, it just stops the warning
simfile = angr.SimFile('flag.txt', content='utflag{test_test_test}\n')
state.fs.insert('flag.txt', simfile)
# Sometimes it is useful to constrain the symbolic variables, like if we know
#they are ascii
#for k in flag_chars:
#    state.solver.add(k >= ord('!'))
#    state.solver.add(k <= ord('~'))
# Start the simulation
simgr = proj.factory.simulation_manager(state)
# Address of where we want to find (the bit where it prints the flag)
find_addr  = 0x04002661
# Address of what we want to avoid (exit)
avoid_addr = 0x040010f0
# both find and avoid can be lists if you want to find/avoid multiple places
# Let angr try to find our find_addr
simgr.explore(find=find_addr, avoid=avoid_addr)
# simgr.found is a list of states that got to where we wanted
# if it is empty then angr couldn't find a way to get to the place we asked for
if (len(simgr.found) > 0):
    for found in simgr.found:
        # print standard in so we can see what our solution is
        print(found.posix.dumps(0))
        # If we were using command line args:
        #print(found.solver.eval(flag,cast_to=bytes))
```
