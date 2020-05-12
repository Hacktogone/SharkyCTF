<p align="center" width="500">
  <img src="../sharky_ctf_logo.png">
</p>

# Beware my big exponent

![team](https://img.shields.io/static/v1?label=Team&message=Hack%27togone&color=E22244&style=for-the-badge)
![CTF](https://img.shields.io/static/v1?label=CTF%20name&message=SharkyCTF&color=blue&style=for-the-badge)
![CTF category](https://img.shields.io/static/v1?label=Catégorie&message=Crypto&color=orange&style=for-the-badge)

## Statement

<p align="center">
  <img src="./files/beware_my_big_exponent.png" width="500">
</p>

## The Provided File

[beware_my_big_exponent.pcapng](./files/beware_my_big_exponent.pcapng)

## TL;DR

This challenge is about decrypting a network communication capture, encrypted using a weak server's SSL certificate.

## Let's st3p 1n the challenge resolution

We start by opening our beloved wireshark, to check the protocols' hierarchy.
This is a must to do when you have to handle a network packet capture, in order to have a first quick insight of what was going on that network.

<p align="center">
  <img src="./files/protocol_hierarchy_ssl_enc.png" width="800">
</p>


We have mostly SSL packets.
According to this challenge statement, it seems like the user did not follow the NIST Recommendation, for Cryptographic Key Generation, for his self generated certificate.

#### Certificate's public key extraction

Let's extract this communication server's certificate and it's public key informations :

```shell
Subject Public Key Info:
    Public Key Algorithm: rsaEncryption
        RSA Public-Key: (2048 bit)
        Modulus:
            00:de:50:82:37:65:9b:f9:dd:fe:a3:17:1e:51:b7:
            ba:b7:be:61:ca:6f:c8:84:2d:60:70:30:f2:b8:36:
            fb:2f:e9:ad:33:c4:e8:8d:96:36:2a:69:ce:ba:a0:
            c5:e3:64:64:47:a0:51:ce:15:e6:f8:12:22:f3:7e:
            02:65:5b:ed:04:1f:21:ac:e1:2c:69:0d:50:ca:ad:
            1c:1a:2d:42:9d:1b:15:d8:50:16:d5:1b:cd:58:16:
            c1:57:a2:0c:e5:17:14:28:58:f1:c8:a8:3d:84:c5:
            46:4e:b1:b4:d5:de:e0:fc:61:89:24:b9:57:69:71:
            7e:10:e6:0e:ad:93:41:45:46:98:36:0b:88:c2:3b:
            ee:8b:5c:19:e2:cb:3f:81:cc:80:20:c2:36:02:43:
            39:ac:2d:74:04:2b:94:76:4d:df:d0:dc:e6:c1:da:
            29:1d:2b:28:b1:87:5d:9e:0c:35:a1:88:39:62:bc:
            17:8b:69:7a:37:13:a1:33:72:9a:45:10:51:0a:48:
            f0:cb:d8:78:0c:78:18:f2:55:71:07:3b:2d:39:24:
            ae:1c:67:c5:be:21:7b:68:29:f4:ff:6c:f3:dc:be:
            63:19:5d:7a:e9:bc:86:18:ae:2a:b4:74:9b:e5:4b:
            0d:b5:59:15:2d:02:5f:b1:4d:13:65:75:c0:d8:4a:
            fd:9d
        Exponent:
            00:92:cb:d9:20:05:56:3d:ae:d0:6c:4b:01:0f:bc:
            53:dd:98:c6:37:11:da:d7:b4:71:2b:ad:8b:a6:be:
            c3:8a:ce:7f:3e:f4:8e:49:1c:88:e4:6f:38:b4:b3:
            c4:43:d6:80:99:76:83:8f:dd:aa:02:37:24:04:5c:
            f0:42:b2:13:25:be:66:93:98:40:06:8b:56:9a:73:
            66:ce:c0:13:ce:ec:fe:9d:3b:63:b6:81:7b:cf:e6:
            d1:4d:72:a8:69:92:18:98:80:aa:13:92:37:36:6d:
            d7:6b:19:7a:d1:30:ae:c9:80:60:56:e7:55:b6:c7:
            ea:97:c4:12:dc:82:26:8c:f6:cb:95:b6:87:49:77:
            8b:79:e6:76:d8:df:ea:67:f7:9b:eb:f9:50:b1:18:
            d6:1a:ca:71:8e:57:64:44:62:65:90:71:c2:ee:f9:
            a7:5f:bf:2d:6f:ea:2d:54:b4:c6:58:65:15:68:a9:
            58:ee:9c:2a:c1:54:2f:0b:02:a0:07:87:af:1e:cf:
            bc:f8:b5:ca:c1:f2:f3:42:15:fe:af:67:4c:55:ea:
            b4:f9:d2:89:fc:fa:09:89:47:af:3c:17:e1:e1:ae:
            a3:f0:28:ca:07:7c:a3:5b:82:19:95:30:1f:fd:e7:
            13:36:4d:9a:ac:9a:3c:9e:e4:81:a8:fc:b5:d5:98:
            b6:c1
```

We can notice that the public key has a really big exponent. That is where the challenge's name comes from.
We should not use an exponent that big because it makes the private key vulnerable.

#### RSA reminder

How? Let's have a quick reminder of how [RSA cryptosystem](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) works.
So basically,
(e, n) is the public key and (d, n) is the private key where n is the modulus, e is the public exponent and d the private exponent.

=> to get the ciphertext : c ≡ (m<sup>e</sup>) mod n   
=> to get the plaintext : m ≡ (c<sup>d</sup>) mod n

n = p*q <br>
λ(n) = lcm(p−1,q−1)<br>
d ≡ e<sup>−1</sup> (mod λ(n))<br>

Now, it's time for quick small maths, like [s01den](https://s01den.github.io/WriteUp_SSEcret_S01den) did.
> Two plus two is four, minus one that's three, quick maths.
>
> -- <cite>Big Shaq, 2017</cite> --

So basically, the greater is e, the less d will be.
Which could lead us to a case where **d < n<sup>0.292</sup>** with our given e.<br>
And that charateristic makes the Boneh Durfee attack possible.
This attack is a method possible on the public key when the private exponent d is too small compared to the modulus n.

Which means that we will just have to perform a Boneh Durfee attack on the public key to try to find d.

#### The Boneh Durfee Method attack

Fortunately, this attack has already been implemented for us by a great CTF tool, the [RsaCtfTool](https://github.com/Ganapati/RsaCtfTool). So this step won't last that long, check the code for the documentation :wink:

```shell
[ndako] (~/SharkyCTF) >>> RsaCtfTool.py --attack boneh_durfee --private -n 28064604001271556129820014593941766966871719060402186685619579092610207886439261672117113431862166609887206266118374701449465484489402253005016113922508067024380066234016246442417929334819285097069654802451548277481455326113050978349702149820594734620094917112796187443136766175643700321937640200838084362809065343412611621805161203752516153558451261082927961291710314933567581414097935518214992109365201598652095643901833066347701880046692998935119067272695270563422087426256745123597533999483207478371090360792810302693360403488254164643916989888513014545793976054466420758036190478585164286540685378716135550811549 -e 18531313791748691217668182004380384706960875031739170444937357234903630805405157773603533893273701769094937129046860776392248099512075805933130254418481344816358723533906241954848284386576867670796464765936597151920719744024080336278919678935839370263228326376735883509546313342081564531619645881649686682523060176833121176144557980595803904646899010258383440094226851760803657102349392975623297154061695041569419920219234437373108673297898755794868228680112329395292450215415345222693053588500482504309427817298852492235949838297400266322189108072070736948436844997938917688895952187056009196413155284647170432087745
-----BEGIN RSA PRIVATE KEY-----
MIIEYgIBAAKCAQEA3lCCN2Wb+d3+oxceUbe6t75hym/IhC1gcDDyuDb7L+mtM8To
jZY2KmnOuqDF42RkR6BRzhXm+BIi834CZVvtBB8hrOEsaQ1Qyq0cGi1CnRsV2FAW
1RvNWBbBV6IM5RcUKFjxyKg9hMVGTrG01d7g/GGJJLlXaXF+EOYOrZNBRUaYNguI
wjvui1wZ4ss/gcyAIMI2AkM5rC10BCuUdk3f0NzmwdopHSsosYddngw1oYg5YrwX
i2l6NxOhM3KaRRBRCkjwy9h4DHgY8lVxBzstOSSuHGfFviF7aCn0/2zz3L5jGV16
6byGGK4qtHSb5UsNtVkVLQJfsU0TZXXA2Er9nQKCAQEAksvZIAVWPa7QbEsBD7xT
3ZjGNxHa17RxK62Lpr7Dis5/PvSOSRyI5G84tLPEQ9aAmXaDj92qAjckBFzwQrIT
Jb5mk5hABotWmnNmzsATzuz+nTtjtoF7z+bRTXKoaZIYmICqE5I3Nm3Xaxl60TCu
yYBgVudVtsfql8QS3IImjPbLlbaHSXeLeeZ22N/qZ/eb6/lQsRjWGspxjldkRGJl
kHHC7vmnX78tb+otVLTGWGUVaKlY7pwqwVQvCwKgB4evHs+8+LXKwfLzQhX+r2dM
Veq0+dKJ/PoJiUevPBfh4a6j8CjKB3yjW4IZlTAf/ecTNk2arJo8nuSBqPy11Zi2
wQJBAPcgwyMCxwgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAECgYEA6iwH3JSUBvo35o28qp4NBcnxUqVA63ls
wzStLPaGJU9lK6MsUzNy1SptVlJ4SMWAVLCMxOEdd+kNIFUC3ZUbUTrtvnAXm/JZ
DJ4BECIQbEfQhjXVkRT+NRMttEPgYQYI2cXo14386blESJbrItZkt3VFL2OLDqag
EValexBZlikCgYEA8wmGsMQpLWvtwzNj31gX3e5BWEGIdKYkeod8HFGeN/acAFKz
xLDauFhOoxCD3MeaMug9rBtz/KqKIpGuhVtC0tdW37ZseRCPa4Joi4hv5vyK1CoH
KSvaodSH0jkLfYceHbW+KoM6/H/JcfrdgBkXRTT7MrkH0mQ9or3nwtU7UlUCQQD3
IMMjAscIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAABAkEA9yDDIwLHCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQKBgQDgTuMGPFR7csWQ
/MD1Px/4Rm9bIyhZWJWICA4hVF6R4EJKK+bY//B+oqrwVvlwqcc3ITGcIu16ZesC
vtuO7eEy+9w+dFAa0MD1wEWbl6d/46sMupPxeFyEZsCbUMWhgk2ao63H9FDRsgQH
UyA5/+/0o2nrIFZyFtKT7IgbxrmmOw==
-----END RSA PRIVATE KEY-----
```

Boom! We've obtained the precious private key as the output.  That we can happily add to wireshark's RSA keys list to decrypt the TLS conversation.

#### The network communication decrypted

A quick check again on the protocols' hierarchy and we can see that there is an email sent via SMTPS over that network.


<p align="center">
  <img src="./files/protocol_hierarchy_ssl_dec.png" width="800">
</p>


Now, let's simply follow that ssl stream.

## Flag

The flag was indeed sent by email :

```shell
--5e9df797_0_8d650ec7
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 7bit
Content-Disposition: inline

Remember that we should use 65537 as the public exponent, not something too big.

Here is your flag: shkCTF{Publ1c_3xp_t0o_b1G_6a8eaf56ab89cb}

--5e9df797_0_8d650ec7
```

```shell
shkCTF{Publ1c_3xp_t0o_b1G_6a8eaf56ab89cb}
```

By : [st3p1n](https://www.root-me.org/st3p1n)

## Ressources

* [Recommendation for Cryptographic Key Generation](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-133r1.pdf)
* [Interisting write-up with a similar Attack](https://www.cryptologie.net/article/265/small-rsa-private-key-problem/)


<p align="center">
  <img src="../hack_togone.svg" alt="Hack'togone emblem" width="700">
</p>
