# Web: Server-Side Request Forgery
In this challenge, you are initially pointed to the resource `/flag`, 
which appears to be unavailable to computers outside the server's 
network. However, the denial page sends you to a "resource getter", in 
which the server will fetch resources for you. In this case, you can get 
the server to fetch the page on your behalf and reveal the flag.
For example, the payload "http://forever.isss.io:4225/flag" should work.

## Prompt
I found this URL where the flag is supposed to be, but it looks it can't 
be accessed remotely! Maybe only computers on the server's network can 
access the page...

`http://forever.isss.io:4225/flag`

_by mattyp_

## Hint
Often times, server resources such as admin pages, databases, and 
metadata services are not available remotely, meaning you must be on 
the server's network to interact with them. However, if there was some 
way to get the server to request those resources, you might be able to 
access them...

