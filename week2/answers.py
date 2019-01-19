'''
#code
>>> import ecc, helper

#endcode
#code
>>> # Verify curve Example
>>> prime = 137
>>> x, y = 73, 128
>>> print(y**2 % prime == (x**3 + 7) % prime)
True

#endcode
#exercise
Find out which points are valid on the curve \\( y^2 = x^3 + 7: F_{223} \\)
```
(192,105), (17,56), (200,119), (1,193), (42,99)
```
---
>>> from ecc import FieldElement, Point
>>> prime = 223
>>> a = FieldElement(0, prime)
>>> b = FieldElement(7, prime)
>>> points = ((192,105), (17,56), (200,119), (1,193), (42,99))
>>> # iterate over points
>>> for x_raw, y_raw in points:  #/
...     # Initialize points this way:
...     # x = FieldElement(x_raw, prime)
...     # y = FieldElement(y_raw, prime)
...     x = FieldElement(x_raw, prime)  #/
...     y = FieldElement(y_raw, prime)  #/
...     # try initializing, ValueError means not on curve
...     # p = Point(x, y, a, b)
...     # print whether it's on the curve or not
...     try:  #/
...         p = Point(x, y, a, b)  #/
...         print('({},{}) is on the curve'.format(x_raw, y_raw))  #/
...     except ValueError:  #/
...         print('({},{}) is not on the curve'.format(x_raw, y_raw))  #/
(192,105) is on the curve
(17,56) is on the curve
(200,119) is not on the curve
(1,193) is on the curve
(42,99) is not on the curve

#endexercise
#unittest
ecc:ECCTest:test_on_curve:
#endunittest
#code
>>> # Example where x1 != x2
>>> from ecc import FieldElement, Point
>>> prime = 137
>>> a = FieldElement(0, prime)
>>> b = FieldElement(7, prime)
>>> p1 = Point(FieldElement(73, prime), FieldElement(128, prime), a, b)
>>> p2 = Point(FieldElement(46, prime), FieldElement(22, prime), a, b)
>>> print(p1+p2)
Point(99,49)_137

#endcode
#exercise
Find the following point additions on the curve  \\( y^2 = x^3 + 7: F_{223} \\)
```
(192,105) + (17,56), (47,71) + (117,141), (143,98) + (76,66)
```
---
>>> from ecc import FieldElement, Point
>>> prime = 223
>>> a = FieldElement(0, prime)
>>> b = FieldElement(7, prime)
>>> additions = ((192, 105, 17, 56), (47, 71, 117, 141), (143, 98, 76, 66))
>>> # iterate over the additions to be done
>>> for x1_raw, y1_raw, x2_raw, y2_raw in additions:  #/
...    # Initialize points this way:
...    # x1 = FieldElement(x1_raw, prime)
...    # y1 = FieldElement(y1_raw, prime)
...    # p1 = Point(x1, y1, a, b)
...    # x2 = FieldElement(x2_raw, prime)
...    # y2 = FieldElement(y2_raw, prime)
...    # p2 = Point(x2, y2, a, b)
...    x1 = FieldElement(x1_raw, prime)  #/
...    y1 = FieldElement(y1_raw, prime)  #/
...    p1 = Point(x1, y1, a, b)  #/
...    x2 = FieldElement(x2_raw, prime)  #/
...    y2 = FieldElement(y2_raw, prime)  #/
...    p2 = Point(x2, y2, a, b)  #/
...    # print p1+p2
...    print('{} + {} = {}'.format(p1, p2, p1+p2))  #/
Point(192,105)_223 + Point(17,56)_223 = Point(170,142)_223
Point(47,71)_223 + Point(117,141)_223 = Point(60,139)_223
Point(143,98)_223 + Point(76,66)_223 = Point(47,71)_223

#endexercise
#unittest
ecc:ECCTest:test_add:
#endunittest
#code
>>> # Example where x1 == x2
>>> from ecc import FieldElement, Point
>>> prime = 137
>>> a = FieldElement(0, prime)
>>> b = FieldElement(7, prime)
>>> p = Point(FieldElement(73, prime), FieldElement(128, prime), a, b)
>>> print(p+p)
Point(103,76)_137

#endcode
#exercise
Find the following scalar multiplications on the curve  \\( y^2 = x^3 + 7: F_{223} \\)

* 2*(192,105)
* 2*(143,98)
* 2*(47,71)
* 4*(47,71)
* 8*(47,71)
* 21*(47,71)

#### Hint: add the point to itself n times
---
>>> from ecc import FieldElement, Point
>>> prime = 223
>>> a = FieldElement(0, prime)
>>> b = FieldElement(7, prime)
>>> multiplications = ((2, 192, 105), (2, 143, 98), (2, 47, 71), (4, 47, 71), (8, 47, 71), (21, 47, 71))
>>> # iterate over the multiplications
>>> for n, x_raw, y_raw in multiplications:  #/
...     # Initialize points this way:
...     # x = FieldElement(x_raw, prime)
...     # y = FieldElement(y_raw, prime)
...     # p = Point(x, y, a, b)
...     x = FieldElement(x_raw, prime)  #/
...     y = FieldElement(y_raw, prime)  #/
...     p = Point(x, y, a, b)  #/
...     # start product at 0 (point at infinity)
...     product = Point(None, None, a, b)  #/
...     # loop over n times (n is 2, 4, 8 or 21 in the above examples)
...     for _ in range(n):  #/
...         # add the point to the product
...         product = product + p  #/
...     # print product    
...     print(product)  #/
Point(49,71)_223
Point(64,168)_223
Point(36,111)_223
Point(194,51)_223
Point(116,55)_223
Point(infinity)

#endexercise
#code
>>> # Group Example
>>> from ecc import FieldElement, Point
>>> prime = 223
>>> a = FieldElement(0, prime)
>>> b = FieldElement(7, prime)
>>> g = Point(FieldElement(47, prime), FieldElement(71, prime), a, b)
>>> inf = Point(None, None, a, b)
>>> total = g
>>> count = 1
>>> while total != inf:
...     print('{}:{}'.format(count, total))
...     total += g
...     count += 1
1:Point(47,71)_223
2:Point(36,111)_223
3:Point(15,137)_223
4:Point(194,51)_223
5:Point(126,96)_223
6:Point(139,137)_223
7:Point(92,47)_223
8:Point(116,55)_223
9:Point(69,86)_223
10:Point(154,150)_223
11:Point(154,73)_223
12:Point(69,137)_223
13:Point(116,168)_223
14:Point(92,176)_223
15:Point(139,86)_223
16:Point(126,127)_223
17:Point(194,172)_223
18:Point(15,86)_223
19:Point(36,112)_223
20:Point(47,152)_223
>>> print('{}:{}'.format(count, total))
21:Point(infinity)

#endcode
#exercise
Find out what the order of the group generated by (15, 86) is on  \\( y^2 = x^3 + 7: F_{223} \\)

#### Hint: add the point to itself until you get the point at infinity
---
>>> from ecc import FieldElement, Point
>>> prime = 223
>>> a = FieldElement(0, prime)
>>> b = FieldElement(7, prime)
>>> x = FieldElement(15, prime)
>>> y = FieldElement(86, prime)
>>> p = Point(x, y, a, b)
>>> inf = Point(None, None, a, b)
>>> # start product at point
>>> product = p  #/
>>> # start counter at 1
>>> counter = 1  #/
>>> # loop until you get point at infinity (0)
>>> while product != inf:  #/
...     # add the point to the product
...     product += p  #/
...     # increment counter
...     counter += 1  #/
>>> # print counter
>>> print(counter)  #/
7

#endexercise
#unittest
ecc:ECCTest:test_rmul:
#endunittest
#code
>>> # Confirming G is on the curve
>>> p = 2**256 - 2**32 - 977
>>> x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
>>> y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
>>> print(y**2 % p == (x**3 + 7) % p)
True

#endcode
#code
>>> # Confirming order of G is n
>>> from ecc import G
>>> n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
>>> print(n*G)
S256Point(infinity)

#endcode
#code
>>> # Getting the public point from a secret
>>> from ecc import G
>>> secret = 999
>>> point = secret*G
>>> print(point)
S256Point(0x9680241112d370b56da22eb535745d9e314380e568229e09f7241066003bc471,0xddac2d377f03c201ffa0419d6596d10327d6c70313bb492ff495f946285d8f38)

#endcode
#exercise
Get the public point where the scalar is the following:

* 7
* 1485
* \\(2^{128}\\)
* \\(2^{240}+2^{31}\\)
---
>>> from ecc import G
>>> secrets = (7, 1485, 2**128, 2**240+2**31)
>>> # iterate over secrets
>>> for secret in secrets:  #/
...     # get the public point
...     print(secret*G)  #/
S256Point(0x5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc,0x6aebca40ba255960a3178d6d861a54dba813d0b813fde7b5a5082628087264da)
S256Point(0xc982196a7466fbbbb0e27a940b6af926c1a74d5ad07128c82824a11b5398afda,0x7a91f9eae64438afb9ce6448a1c133db2d8fb9254e4546b6f001637d50901f55)
S256Point(0x8f68b9d2f63b5f339239c1ad981f162ee88c5678723ea3351b7b444c9ec4c0da,0x662a9f2dba063986de1d90c2b6be215dbbea2cfe95510bfdf23cbf79501fff82)
S256Point(0x9577ff57c8234558f293df502ca4f09cbc65a6572c842b39b366f21717945116,0x10b49c67fa9365ad7b90dab070be339a1daf9052373ec30ffae4f72d5e66d053)

#endexercise
#unittest
ecc:S256Test:test_pubpoint:
#endunittest
#code
>>> # SEC Example
>>> from ecc import S256Point
>>> point = S256Point(0x5CBDF0646E5DB4EAA398F365F2EA7A0E3D419B7E0330E39CE92BDDEDCAC4F9BC, 0x6AEBCA40BA255960A3178D6D861A54DBA813D0B813FDE7B5A5082628087264DA)
>>> uncompressed = b'\\x04' + point.x.num.to_bytes(32, 'big') + point.y.num.to_bytes(32, 'big')
>>> print(uncompressed.hex())
045cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc6aebca40ba255960a3178d6d861a54dba813d0b813fde7b5a5082628087264da
>>> if point.y.num % 2 == 1:
...     compressed = b'\\x03' + point.x.num.to_bytes(32, 'big')
... else:
...     compressed = b'\\x02' + point.x.num.to_bytes(32, 'big')
>>> print(compressed.hex())
025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc

#endcode
#exercise
Find the compressed and uncompressed SEC format for pub keys where the private keys are:
```
999**3, 123, 42424242
```
---
>>> from ecc import G
>>> secrets = (999**3, 123, 42424242)
>>> # iterate through secrets
>>> for secret in secrets:  #/
...     # get public point
...     point = secret * G  #/
...     # uncompressed - b'\\x04' followed by x coord, then y coord
...     # here's how you express a coordinate in bytes: some_integer.to_bytes(32, 'big')
...     uncompressed = b'\\x04' + point.x.num.to_bytes(32, 'big') + point.y.num.to_bytes(32, 'big')  #/
...     # compressed - b'\\x02'/b'\\x03' follewed by x coord. 02 if y is even, 03 otherwise
...     if point.y.num % 2 == 1:  #/
...         compressed = b'\\x03' + point.x.num.to_bytes(32, 'big')  #/
...     else:  #/
...         compressed = b'\\x02' + point.x.num.to_bytes(32, 'big')  #/
...     # print the .hex() of both
...     print(uncompressed.hex())  #/
...     print(compressed.hex())  #/
049d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d56fa15cc7f3d38cda98dee2419f415b7513dde1301f8643cd9245aea7f3f911f9
039d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d5
04a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5204b5d6f84822c307e4b4a7140737aec23fc63b65b35f86a10026dbd2d864e6b
03a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5
04aee2e7d843f7430097859e2bc603abcc3274ff8169c1a469fee0f20614066f8e21ec53f40efac47ac1c5211b2123527e0e9b57ede790c4da1e72c91fb7da54a3
03aee2e7d843f7430097859e2bc603abcc3274ff8169c1a469fee0f20614066f8e

#endexercise
#unittest
ecc:S256Test:test_sec:
#endunittest
#code
>>> # Address Example
>>> from helper import encode_base58, hash160, hash256
>>> sec = bytes.fromhex('025CBDF0646E5DB4EAA398F365F2EA7A0E3D419B7E0330E39CE92BDDEDCAC4F9BC')
>>> h160 = hash160(sec)
>>> raw = b'\\x00' + h160
>>> raw = raw + hash256(raw)[:4]
>>> addr = encode_base58(raw)
>>> print(addr)
19ZewH8Kk1PDbSNdJ97FP4EiCjTRaZMZQA

#endcode
#exercise
Find the mainnet and testnet addresses corresponding to the private keys:

* \\(888^3\\), compressed
* 321, uncompressed
* 4242424242, uncompressed
---
>>> from ecc import G
>>> components = (
...     # (secret, compressed)
...     (888**3, True),
...     (321, False),
...     (4242424242, False),
... )
>>> # iterate through components
>>> for secret, compressed in components:  #/
...     # get the public point
...     point = secret * G  #/
...     # get the sec format
...     sec = point.sec(compressed)  #/
...     # hash160 the result
...     h160 = hash160(sec)  #/
...     # prepend b'\\x00' for mainnet b'\\x6f' for testnet
...     for prefix in (b'\\x00', b'\\x6f'):  #/
...         # raw is the prefix + h160
...         raw = prefix + h160  #/
...         # get the hash256 of the raw, first 4 bytes are the checksum
...         checksum = hash256(raw)[:4]  #/
...         # append checksum
...         total = raw + checksum  #/
...         # encode_base58 the whole thing
...         print(encode_base58(total))  #/
148dY81A9BmdpMhvYEVznrM45kWN32vSCN
mieaqB68xDCtbUBYFoUNcmZNwk74xcBfTP
1S6g2xBJSED7Qr9CYZib5f4PYVhHZiVfj
mfx3y63A7TfTtXKkv7Y6QzsPFY6QCBCXiP
1226JSptcStqn4Yq9aAmNXdwdc2ixuH9nb
mgY3bVusRUL6ZB2Ss999CSrGVbdRwVpM8s

#endexercise
#unittest
helper:HelperTest:test_encode_base58_checksum:
#endunittest
#unittest
ecc:S256Test:test_address:
#endunittest
#exercise
Create a testnet address using your own secret key (use your name and email as the password if you can't think of anything). Record this secret key for tomorrow!
---
>>> from ecc import G
>>> from helper import hash256, little_endian_to_int
>>> # use a passphrase
>>> passphrase = b'Jimmy Song'  #/passphrase = b'<fill this in with your name and email>'
>>> secret = little_endian_to_int(hash256(passphrase))
>>> # get the public point
>>> point = secret*G  #/
>>> # if you completed 7.2, just do the .address(testnet=True) method on the public point
>>> print(point.address(testnet=True))  #/
mseRGXB89UTFVkWJhTRTzzZ9Ujj4ZPbGK5

#endexercise
#code
>>> # Signing Example
>>> from ecc import N, G
>>> from helper import hash256
>>> secret = 1800555555518005555555
>>> z = int.from_bytes(hash256(b'ECDSA is awesome!'), 'big')
>>> k = 12345
>>> r = (k*G).x.num
>>> s = (z+r*secret) * pow(k, N-2, N) % N
>>> print(hex(z), hex(r), hex(s))
0xcf6304e0ed625dc13713ad8b330ca764325f013fe7a3057dbe6a2053135abeb4 0xf01d6b9018ab421dd410404cb869072065522bf85734008f105cf385a023a80f 0xf10c07e197e8b0e717108d0703d874357424ece31237c864621ac7acb0b9394c
>>> print(secret*G)
S256Point(0x4519fac3d910ca7e7138f7013706f619fa8f033e6ec6e09370ea38cee6a7574,0x82b51eab8c27c66e26c858a079bcdf4f1ada34cec420cafc7eac1a42216fb6c4)

#endcode
#code
>>> # Verification Example
>>> from ecc import G, N, S256Point
>>> z = 0xbc62d4b80d9e36da29c16c5d4d9f11731f36052c72401a76c23c0fb5a9b74423
>>> r = 0x37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6
>>> s = 0x8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec
>>> point = S256Point(0x04519fac3d910ca7e7138f7013706f619fa8f033e6ec6e09370ea38cee6a7574,
...                   0x82b51eab8c27c66e26c858a079bcdf4f1ada34cec420cafc7eac1a42216fb6c4)
>>> u = z * pow(s, N-2, N) % N
>>> v = r * pow(s, N-2, N) % N
>>> print((u*G + v*point).x.num == r)
True

#endcode
#exercise
Which sigs are valid?

```
P = (887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c, 
     61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34)
z, r, s = ec208baa0fc1c19f708a9ca96fdeff3ac3f230bb4a7ba4aede4942ad003c0f60,
          ac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395,
          68342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4
z, r, s = 7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d,
          eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c,
          c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6
```
---
>>> from ecc import G, N, S256Point
>>> px = 0x887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c
>>> py = 0x61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34
>>> signatures = (
...     # (z, r, s)
...     (0xec208baa0fc1c19f708a9ca96fdeff3ac3f230bb4a7ba4aede4942ad003c0f60,
...      0xac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395,
...      0x68342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4),
...     (0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d,
...      0xeff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c,
...      0xc7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6),
... )
>>> # initialize the public point
>>> # use: S256Point(x-coordinate, y-coordinate)
>>> point = S256Point(px, py)  #/
>>> # iterate over signatures
>>> for z, r, s in signatures:  #/
...     # u = z / s, v = r / s
...     u = z * pow(s, N-2, N) % N  #/
...     v = r * pow(s, N-2, N) % N  #/
...     # finally, uG+vP should have the x-coordinate equal to r
...     print((u*G+v*point).x.num == r)  #/
True
True

#endexercise
#unittest
ecc:S256Test:test_verify:
#endunittest
#unittest
ecc:PrivateKeyTest:test_sign:
#endunittest
#exercise
Verify the DER signature for the hash of "ECDSA is awesome!" for the given SEC pubkey

`z = int.from_bytes(hash256('ECDSA is awesome!'), 'big')`

Public Key in SEC Format: 
0204519fac3d910ca7e7138f7013706f619fa8f033e6ec6e09370ea38cee6a7574

Signature in DER Format: 304402201f62993ee03fca342fcb45929993fa6ee885e00ddad8de154f268d98f083991402201e1ca12ad140c04e0e022c38f7ce31da426b8009d02832f0b44f39a6b178b7a1
---
>>> from ecc import S256Point, Signature
>>> from helper import hash256
>>> der = bytes.fromhex('304402201f62993ee03fca342fcb45929993fa6ee885e00ddad8de154f268d98f083991402201e1ca12ad140c04e0e022c38f7ce31da426b8009d02832f0b44f39a6b178b7a1')
>>> sec = bytes.fromhex('0204519fac3d910ca7e7138f7013706f619fa8f033e6ec6e09370ea38cee6a7574')
>>> # message is the hash256 of the message "ECDSA is awesome!"
>>> z = int.from_bytes(hash256(b'ECDSA is awesome!'), 'big')
>>> # parse the der format to get the signature
>>> sig = Signature.parse(der)  #/
>>> # parse the sec format to get the public key
>>> point = S256Point.parse(sec)  #/
>>> # use the verify method on S256Point to validate the signature
>>> print(point.verify(z, sig))  #/
True

#endexercise
'''


from random import randint
from unittest import TestCase

import helper

from ecc import (
    FieldElement,
    G,
    N,
    Point,
    PrivateKey,
    S256Point,
    Signature,
)
from helper import (
    encode_base58,
    hash160,
    hash256,
    little_endian_to_int,
)


def t_on_curve(self):
    prime = 223
    a = FieldElement(0, prime)
    b = FieldElement(7, prime)
    valid_points = ((192, 105), (17, 56), (1, 193))
    invalid_points = ((200, 119), (42, 99))
    for x_raw, y_raw in valid_points:
        x = FieldElement(x_raw, prime)
        y = FieldElement(y_raw, prime)
        Point(x, y, a, b)
    for x_raw, y_raw in invalid_points:
        x = FieldElement(x_raw, prime)
        y = FieldElement(y_raw, prime)
        with self.assertRaises(ValueError):
            Point(x, y, a, b)


def t_add(self):
    prime = 223
    a = FieldElement(0, prime)
    b = FieldElement(7, prime)
    additions = (
        (192, 105, 17, 56, 170, 142),
        (47, 71, 117, 141, 60, 139),
        (143, 98, 76, 66, 47, 71),
    )
    for x1_raw, y1_raw, x2_raw, y2_raw, x3_raw, y3_raw in additions:
        x1 = FieldElement(x1_raw, prime)
        y1 = FieldElement(y1_raw, prime)
        p1 = Point(x1, y1, a, b)
        x2 = FieldElement(x2_raw, prime)
        y2 = FieldElement(y2_raw, prime)
        p2 = Point(x2, y2, a, b)
        x3 = FieldElement(x3_raw, prime)
        y3 = FieldElement(y3_raw, prime)
        p3 = Point(x3, y3, a, b)
        self.assertEqual(p1 + p2, p3)


def t_rmul(self):
    prime = 223
    a = FieldElement(0, prime)
    b = FieldElement(7, prime)
    multiplications = (
        (2, 192, 105, 49, 71),
        (2, 143, 98, 64, 168),
        (2, 47, 71, 36, 111),
        (4, 47, 71, 194, 51),
        (8, 47, 71, 116, 55),
        (21, 47, 71, None, None),
    )
    for s, x1_raw, y1_raw, x2_raw, y2_raw in multiplications:
        x1 = FieldElement(x1_raw, prime)
        y1 = FieldElement(y1_raw, prime)
        p1 = Point(x1, y1, a, b)
        if x2_raw is None:
            p2 = Point(None, None, a, b)
        else:
            x2 = FieldElement(x2_raw, prime)
            y2 = FieldElement(y2_raw, prime)
            p2 = Point(x2, y2, a, b)
        self.assertEqual(s * p1, p2)


def t_pubpoint(self):
    points = (
        (7, 0x5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc, 0x6aebca40ba255960a3178d6d861a54dba813d0b813fde7b5a5082628087264da),
        (1485, 0xc982196a7466fbbbb0e27a940b6af926c1a74d5ad07128c82824a11b5398afda, 0x7a91f9eae64438afb9ce6448a1c133db2d8fb9254e4546b6f001637d50901f55),
        (2**128, 0x8f68b9d2f63b5f339239c1ad981f162ee88c5678723ea3351b7b444c9ec4c0da, 0x662a9f2dba063986de1d90c2b6be215dbbea2cfe95510bfdf23cbf79501fff82),
        (2**240 + 2**31, 0x9577ff57c8234558f293df502ca4f09cbc65a6572c842b39b366f21717945116, 0x10b49c67fa9365ad7b90dab070be339a1daf9052373ec30ffae4f72d5e66d053),
    )
    for secret, x, y in points:
        point = S256Point(x, y)
        self.assertEqual(secret * G, point)


def sec(self, compressed=True):
    if compressed:
        if self.y.num % 2 == 0:
            return b'\x02' + self.x.num.to_bytes(32, 'big')
        else:
            return b'\x03' + self.x.num.to_bytes(32, 'big')
    else:
        return b'\x04' + self.x.num.to_bytes(32, 'big') + self.y.num.to_bytes(32, 'big')


def encode_base58_checksum(raw):
    checksum = hash256(raw)[:4]
    return encode_base58(raw + checksum)


def address(self, compressed=True, testnet=False):
    sec = self.sec(compressed)
    h160 = hash160(sec)
    if testnet:
        prefix = b'\x6f'
    else:
        prefix = b'\x00'
    return encode_base58_checksum(prefix + h160)


def verify(self, z, sig):
    s_inv = pow(sig.s, N - 2, N)
    u = z * s_inv % N
    v = sig.r * s_inv % N
    total = u * G + v * self
    return total.x.num == sig.r


def sign(self, z):
    k = randint(0, N)
    r = (k * G).x.num
    k_inv = pow(k, N - 2, N)
    s = (z + r * self.secret) * k_inv % N
    if s > N / 2:
        s = N - s
    return Signature(r, s)


class SessionTest(TestCase):

    def test_apply(self):
        from ecc import ECCTest, S256Test
        ECCTest.test_on_curve = t_on_curve
        ECCTest.test_add = t_add
        ECCTest.test_rmul = t_rmul
        S256Test.test_pubpoint = t_pubpoint
        S256Point.sec = sec
        helper.encode_base58_checksum = encode_base58_checksum
        S256Point.address = address
        S256Point.verify = verify
        PrivateKey.sign = sign
