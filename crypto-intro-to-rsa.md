This challenge involves simply calculating what is requested by the netcat using various modular arithmetic operations. Obviously, there are a ton of ways to do this - use whatever tools you prefer!


For me, I used a python shell and the crypto library. Obviously, your specific values will be different since it generates new values every time, but here’s an example of what I did:
```
>>> p = 180039729219889518763401376769218399333
>>> q = 184714024085145129092775960597319977259
>>> N = p*q
>>> print(N)
33255862879405679832467293495096808739983550585715098578061259860791940768247

>>> e = 65537
>>> pow(100, e, N)
14789535486896253816228897823278862615422875129523355217474988764221662919513

>>> from Crypto.Util.number import inverse
>>> tot = (p-1)*(q-1)
>>> d = inverse(e, tot)
>>> print(d)
1209728506103470417025527987126520775062197104665541486635166649920596904065

>>> from Crypto.Util.number import long_to_bytes
>>> c = 2188209470549364153417089961345946636046212970760621347054084263017092649489
>>> m = pow(c, d, N)
>>> long_to_bytes(m)
```
