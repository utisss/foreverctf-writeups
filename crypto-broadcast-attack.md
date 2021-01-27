This is susceptible to Hastad’s Broadcasting Attack, which occurs when the same message is sent to multiple people under the same small e. The basic idea is that m^e can be reconstructed using Chinese Remainder Theorem (CRT).

For those of you who aren’t familiar with CRT, basically it solves a series of modular equations that look like this:

x mod m1 = r1
x mod m2 = r2
x mod m3 = r3
x mod m4 = r4
etc.

Obviously, multiple x exist, but they all differ by a factor of lcm(m1, m2, m3, …). CRT simply finds one such solution.

In our case, we have m^e mod Ni = ci for all i. Since e is 3 instead of 65537, however, we can reasonably assume that the m^3 is also quite small, and we won’t have to try too many values after getting a solution from CRT.
We can do CRT in Sage:
```
sage: N1=92654857070767571890017042106637703986449117869087364338047922606069735162919
sage: c1=74597365847504917912916866838569123286395165031450770943853702985527537374325
sage: N2=98572474388371800971130449337009030864118807314878868777502700832091542642841
sage: c2=7392488009685177703766329111985085924328495872306844961776805115046085005730
sage: N3=51501476121983355743052534942567218556170618226963749616587274414221577824191
sage: c3=21070202880950860480001393449893080177749578386435659153510821967923393222435
sage: crt([c1, c2, c3], [N1, N2, N3])
5058351256155409529406238144471341438552104952261535456571653484803218406916802750051840009570104142357477131218431156591217085367440280037879937259877
```

The value returned by the crt function should be m^3. We can cube root it to get m (this is done in Sage since Sage will find the integer cube root if there is one; python will turn it into a float which has slight imprecision):
```
sage: 5058351256155409529406238144471341438552104952261535456571653484803218406916802750051840009570104142357477131218431156591217085367440280037879937259877^(1/3)
171660218614413278717581163768910141292412151293053
```

Then, we convert to a string in Python:
```
>>> from Crypto.Util.number import long_to_bytes
>>> long_to_bytes(171660218614413278717581163768910141292412151293053)
```
