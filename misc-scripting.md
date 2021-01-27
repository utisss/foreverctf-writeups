To solve this problem we need to be able to read and write to a connection and some scripting. We can use [pwntools](https://docs.pwntools.com/en/stable/intro.html) to read and to write to a connection.


    from pwn import *
    # create remote connection to problem
    conn = remote("forever.isss.io",3003)

The pwntool function `recvline` allows us to read a single line from the connection. The recvline function returns a byte string. To skip the first line of instructions we can just call recvline and do nothing with the results

    conn.recvline()

To parse the number of required glasses we can split the next read line into chunks split by spaces.

    chunks = conn.recvline().split(b" ")
    no_glasses = int(chunk[3])
    
Then we can read the next two line and discard them so we can send text.

    for _ in range(2):
        conn.recvline()
        
We can then use the `send` function to interact with a remote connection and send the required number of lines.

    for _ in range(no_glasses):
        conn.send("1\n")
        #discard the tree grew line
        conn.recvline()

Once we've sent the required number of glasses we can print the flag.

   print(conn.recvline())
