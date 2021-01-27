# Web: Command Injection

## Prompt
Are you too lazy to ping websites? 
Then just use this convenient cloud service to ping sites for you!

`http://forever.isss.io:4222`

_by mattyp_

(attach app.py)

## Hint
Based on the output or the source code, you might recognize that this webapp is 
running the command line utility `ping`. In the source code, you can see that the 
variable `command` is formed by directly concatenating user input with the ping 
command. Thus, you can use different command line metacharacters to run other 
commands. For instance, you could exploit the `;` metacharacter by entering this: 
`google.com; echo hello`

The flag is stored at `/flag.txt`. You just need to figure out how to read the file 
by injecting a command!
