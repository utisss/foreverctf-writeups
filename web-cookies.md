# Web: Cookies
In this problem the website serves an access denied page. 
The theme is supposed to inspire checking the site's cookies, which reveals a
cookie `isCookieMonster` that is set to false. Modifying the cookie to be true 
opens the jar and reveals the flag.

## Prompt
I'm trying to open this jar of cookies, but the website doesn't recognize me.
Can you open the jar for me and inspect the cookies?

`http://forever.isss.io:4222`

_by mattyp_

## Hint
Websites recognize its users through the use of "cookies". Cookies are just 
an HTTP header that your browser will repeatedly send if a website sets. Cookies 
are often used for authentication because they persist when you vist many different 
pages on a website. You can check what cookies by opening developer tools in your 
browser (usually with F12 or by right-clicking and selecting "inspect element"), then 
looking in the "Storage" tab. Safari is a literally different, but in Chrome and 
Firefox, you can then modify your cookies to be whatever value you want.
