# Web: Local File Inclusion
In this challenge, the website appears to request any URL that you give it, and return the result.
Using this, you can use a file:// URL to recover the flag at /flag.txt.

## Prompt
I'm usually too lazy to fetch my own URLs, so I made this cool webapp to do it for me.
My flag is stored locally on my computer, so you shouldn't be able to find it.
In fact I'm so sure that you can't find it, that I'll tell you the filepath: `/flag.txt`

`http://forever.isss.io:4224`

_by mattyp_

## Hint
Many times webapps will accidentally include functionality that lets you 
view the content of local files, such as secret keys or sensitive data. 

In this case, the webapp allows you to request any URL you want. However,
websites aren't the only thing you can put in a URL...
