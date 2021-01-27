There’s a ton of resources about how Wiener’s Attack works if you’re interested in that, but for most CTFs you won’t be required to know the math details by heart. However, knowing when Wiener’s attack is applicable is a must.

In this problem, e is not one of the standard choices (3, 65537, etc.), which hints at the fact that d was chosen first (to ensure it is small and coprime with totient) and e was calculated after, instead of the other way around.

I used the python library owiener, which is just an existing implementation of Wiener’s Attack that takes e and n to try and find d. Using it on this problem gives us d, which we can just use to decrypt.

```
>>> from Crypto.Util.number import long_to_bytes
>>> import owiener
>>> n = 7905286789307969689444446776834572488342512871216373118384351052597353752148252310391459022650178558362015804623969796116224090070495774849456791367306113
>>> e = 7643051815477072240601011354205548264016458535771900604241689972774556751107899980617931557990173091671691627792054236018529523960796319660703000489116673
>>> c = 132621323207928347135772813311861732966074971533922909954361816541744489303464435189913426388248693256452873362487042859679296755153038110489878189377547
>>> owiener.attack(e, n)
65537
>>> m = pow(c, 65537, n)
>>> long_to_bytes(m)
```

Note: for an attack that works on slightly larger (but still small) d’s, check out Boneh Durfee.
