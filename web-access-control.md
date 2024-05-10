# WEB: Access Control
In this problem, the website has a page to create and login into
accounts. The purpose is to show how if pages aren't properly secured,
any user can access other account's pages without proper authentication.
When an account is logged in, look at the URL. The page is /account/pages/{username}{id}.
The id increments for each account created and initially started at 2. The idea here is 
figuring out the full URL for the admin's home page as there is no actual authentication
for going to other accounts' home page. 
This will lead to the users accessing the admin's account and getting
the flag.

# PROMPT
I only trust code that I wrote, so I completely implemented my own authentication for my new website!
Try to break in if you can!

`http://forever.isss.io:1234`

_by danny @danny_