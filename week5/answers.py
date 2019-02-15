'''
#code
>>> import block, op, helper, script, tx

#endcode
#code
>>> # op_checkmultisig
>>> def op_checkmultisig(stack, z):
...     if len(stack) < 1:
...         return False
...     n = decode_num(stack.pop())
...     if len(stack) < n + 1:
...         return False
...     sec_pubkeys = []
...     for _ in range(n):
...         sec_pubkeys.append(stack.pop())
...     m = decode_num(stack.pop())
...     if len(stack) < m + 1:
...         return False
...     der_signatures = []
...     for _ in range(m):
...         # signature is assumed to be using SIGHASH_ALL
...         der_signatures.append(stack.pop()[:-1])
...     # OP_CHECKMULTISIG bug
...     stack.pop()
...     try:
...         raise NotImplementedError
...     except (ValueError, SyntaxError):
...         return False
...     return True

#endcode
#unittest
op:OpTest:test_op_checkmultisig:
#endunittest
#exercise
Find the hash160 of the RedeemScript
```
5221022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb702103b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb7152ae
```
---
>>> from helper import hash160
>>> hex_redeem_script = '5221022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb702103b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb7152ae'
>>> # bytes.fromhex script
>>> redeem_script = bytes.fromhex(hex_redeem_script)  #/
>>> # hash160 result
>>> h160 = hash160(redeem_script)  #/
>>> # hex() to display
>>> print(h160.hex())  #/
74d691da1574e6b3c192ecfb52cc8984ee7b6c56

#endexercise
#code
>>> # P2SH address construction example
>>> from helper import encode_base58_checksum
>>> print(encode_base58_checksum(b'\x05'+bytes.fromhex('74d691da1574e6b3c192ecfb52cc8984ee7b6c56')))
3CLoMMyuoDQTPRD3XYZtCvgvkadrAdvdXh

#endcode
#unittest
helper:HelperTest:test_p2pkh_address:
#endunittest
#unittest
helper:HelperTest:test_p2sh_address:
#endunittest
#unittest
script:ScriptTest:test_address:
#endunittest
#code
>>> # z for p2sh example
>>> from helper import hash256
>>> h256 = hash256(bytes.fromhex('0100000001868278ed6ddfb6c1ed3ad5f8181eb0c7a385aa0836f01d5e4789e6bd304d87221a000000475221022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb702103b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb7152aeffffffff04d3b11400000000001976a914904a49878c0adfc3aa05de7afad2cc15f483a56a88ac7f400900000000001976a914418327e3f3dda4cf5b9089325a4b95abdfa0334088ac722c0c00000000001976a914ba35042cfe9fc66fd35ac2224eebdafd1028ad2788acdc4ace020000000017a91474d691da1574e6b3c192ecfb52cc8984ee7b6c56870000000001000000'))
>>> z = int.from_bytes(h256, 'big')
>>> print(hex(z))
0xe71bfa115715d6fd33796948126f40a8cdd39f187e4afb03896795189fe1423c

#endcode
#code
>>> # p2sh verification example
>>> from ecc import S256Point, Signature
>>> from helper import hash256
>>> h256 = hash256(bytes.fromhex('0100000001868278ed6ddfb6c1ed3ad5f8181eb0c7a385aa0836f01d5e4789e6bd304d87221a000000475221022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb702103b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb7152aeffffffff04d3b11400000000001976a914904a49878c0adfc3aa05de7afad2cc15f483a56a88ac7f400900000000001976a914418327e3f3dda4cf5b9089325a4b95abdfa0334088ac722c0c00000000001976a914ba35042cfe9fc66fd35ac2224eebdafd1028ad2788acdc4ace020000000017a91474d691da1574e6b3c192ecfb52cc8984ee7b6c56870000000001000000'))
>>> z = int.from_bytes(h256, 'big')
>>> point = S256Point.parse(bytes.fromhex('022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb70'))
>>> sig = Signature.parse(bytes.fromhex('3045022100dc92655fe37036f47756db8102e0d7d5e28b3beb83a8fef4f5dc0559bddfb94e02205a36d4e4e6c7fcd16658c50783e00c341609977aed3ad00937bf4ee942a89937'))
>>> print(point.verify(z, sig))
True

#endcode
#exercise
Validate the second signature of the first input

```
0100000001868278ed6ddfb6c1ed3ad5f8181eb0c7a385aa0836f01d5e4789e6bd304d87221a000000db00483045022100dc92655fe37036f47756db8102e0d7d5e28b3beb83a8fef4f5dc0559bddfb94e02205a36d4e4e6c7fcd16658c50783e00c341609977aed3ad00937bf4ee942a8993701483045022100da6bee3c93766232079a01639d07fa869598749729ae323eab8eef53577d611b02207bef15429dcadce2121ea07f233115c6f09034c0be68db99980b9a6c5e75402201475221022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb702103b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb7152aeffffffff04d3b11400000000001976a914904a49878c0adfc3aa05de7afad2cc15f483a56a88ac7f400900000000001976a914418327e3f3dda4cf5b9089325a4b95abdfa0334088ac722c0c00000000001976a914ba35042cfe9fc66fd35ac2224eebdafd1028ad2788acdc4ace020000000017a91474d691da1574e6b3c192ecfb52cc8984ee7b6c568700000000
```

The sec pubkey of the second signature is:
```
03b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb71
```

The der signature of the second signature is:
```
3045022100da6bee3c93766232079a01639d07fa869598749729ae323eab8eef53577d611b02207bef15429dcadce2121ea07f233115c6f09034c0be68db99980b9a6c5e75402201475221022
```

The redeemScript is:
```
475221022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb702103b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb7152ae
```
---
>>> from io import BytesIO
>>> from ecc import S256Point, Signature
>>> from helper import int_to_little_endian, SIGHASH_ALL
>>> from script import Script
>>> from tx import Tx
>>> hex_sec = '03b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb71'
>>> hex_der = '3045022100da6bee3c93766232079a01639d07fa869598749729ae323eab8eef53577d611b02207bef15429dcadce2121ea07f233115c6f09034c0be68db99980b9a6c5e754022'
>>> hex_redeem_script = '475221022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb702103b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb7152ae'
>>> sec = bytes.fromhex(hex_sec)
>>> der = bytes.fromhex(hex_der)
>>> redeem_script_stream = BytesIO(bytes.fromhex(hex_redeem_script))
>>> hex_tx = '0100000001868278ed6ddfb6c1ed3ad5f8181eb0c7a385aa0836f01d5e4789e6bd304d87221a000000db00483045022100dc92655fe37036f47756db8102e0d7d5e28b3beb83a8fef4f5dc0559bddfb94e02205a36d4e4e6c7fcd16658c50783e00c341609977aed3ad00937bf4ee942a8993701483045022100da6bee3c93766232079a01639d07fa869598749729ae323eab8eef53577d611b02207bef15429dcadce2121ea07f233115c6f09034c0be68db99980b9a6c5e75402201475221022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb702103b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb7152aeffffffff04d3b11400000000001976a914904a49878c0adfc3aa05de7afad2cc15f483a56a88ac7f400900000000001976a914418327e3f3dda4cf5b9089325a4b95abdfa0334088ac722c0c00000000001976a914ba35042cfe9fc66fd35ac2224eebdafd1028ad2788acdc4ace020000000017a91474d691da1574e6b3c192ecfb52cc8984ee7b6c568700000000'
>>> stream = BytesIO(bytes.fromhex(hex_tx))
>>> # parse the S256Point and Signature
>>> point = S256Point.parse(sec)  #/
>>> sig = Signature.parse(der)  #/
>>> # parse the Tx
>>> t = Tx.parse(stream)  #/
>>> # change the first input's scriptSig to redeemScript
>>> # use Script.parse on the redeem_script_stream
>>> t.tx_ins[0].script_sig = Script.parse(redeem_script_stream)  #/
>>> # get the serialization
>>> ser = t.serialize()  #/
>>> # add the sighash (4 bytes, little-endian of SIGHASH_ALL)
>>> ser += int_to_little_endian(SIGHASH_ALL, 4)  #/
>>> # hash256 the result
>>> h256 = hash256(ser)  #/
>>> # this interpreted is a big-endian number is your z
>>> z = int.from_bytes(h256, 'big')  #/
>>> # now verify the signature using point.verify
>>> print(point.verify(z, sig))  #/
True

#endexercise
#unittest
tx:TxTest:test_is_coinbase:
#endunittest
#exercise
Parse the Genesis Block Coinbase Transaction and print out the scriptSig's third item

```
01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000
```
---
>>> from io import BytesIO
>>> from tx import Tx
>>> hex_tx = '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000'
>>> # create stream with BytesIO and bytes.fromhex
>>> stream = BytesIO(bytes.fromhex(hex_tx))  #/
>>> # parse the coinbase transaction
>>> coinbase = Tx.parse(stream)  #/
>>> # print the first input's script_sig's third command
>>> print(coinbase.tx_ins[0].script_sig.commands[2])  #/
b'The Times 03/Jan/2009 Chancellor on brink of second bailout for banks'

#endexercise
#unittest
tx:TxTest:test_coinbase_height:
#endunittest
#exercise
Find the output address corresponding to this ScriptPubKey
```
1976a914338c84849423992471bffb1a54a8d9b1d69dc28a88ac
```

Remember the structure of pay-to-pubkey-hash (p2pkh) which has `OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG`.

You need to grab the hash160 and turn that into an address.
---
>>> from io import BytesIO
>>> from script import Script
>>> hex_script_pubkey = '1976a914338c84849423992471bffb1a54a8d9b1d69dc28a88ac'
>>> # BytesIO(bytes.fromhex) to get the stream
>>> stream = BytesIO(bytes.fromhex(hex_script_pubkey))  #/
>>> # parse with Script
>>> script_pubkey = Script.parse(stream)  #/
>>> # get the address using address() on the script_pubkey
>>> print(script_pubkey.address())  #/
15hZo812Lx266Dot6T52krxpnhrNiaqHya

#endexercise
#exercise
What is the hash256 of this block? Notice anything?
```
020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d
```
---
>>> from helper import hash256
>>> hex_block = '020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d'
>>> # bytes.fromhex to get the binary
>>> bin_block = bytes.fromhex(hex_block)  #/
>>> # hash256 the result
>>> result = hash256(bin_block)  #/
>>> # hex() to see what it looks like
>>> print(result.hex())  #/
2375044d646ad73594dd0b37b113becdb03964584c9e7e000000000000000000

#endexercise
#unittest
block:BlockTest:test_parse:
#endunittest
#unittest
block:BlockTest:test_serialize:
#endunittest
#unittest
block:BlockTest:test_hash:
#endunittest
#code
>>> # Version Signaling Example
>>> from block import Block
>>> from io import BytesIO
>>> hex_block = '020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d'
>>> bin_block = bytes.fromhex(hex_block)
>>> stream = BytesIO(bin_block)
>>> b = Block.parse(stream)
>>> version = b.version
>>> print('BIP9: {}'.format(version >> 29 == 0b001))
BIP9: True
>>> print('BIP91: {}'.format(version >> 4 & 1 == 1))
BIP91: False
>>> print('BIP141: {}'.format(version >> 1 & 1 == 1))
BIP141: True

#endcode
#unittest
block:BlockTest:test_bip9:
#endunittest
#unittest
block:BlockTest:test_bip91:
#endunittest
#unittest
block:BlockTest:test_bip141:
#endunittest
#code
>>> # Calculating Target from Bits Example
>>> from helper import little_endian_to_int
>>> bits = bytes.fromhex('e93c0118')
>>> exponent = bits[-1]
>>> coefficient = little_endian_to_int(bits[:-1])
>>> target = coefficient*256**(exponent-3)
>>> print('{:x}'.format(target).zfill(64))
0000000000000000013ce9000000000000000000000000000000000000000000

#endcode
#code
>>> # Calculating Difficulty from Target Example
>>> from helper import little_endian_to_int
>>> bits = bytes.fromhex('e93c0118')
>>> exponent = bits[-1]
>>> coefficient = little_endian_to_int(bits[:-1])
>>> target = coefficient * 256**(exponent - 3)
>>> min_target = 0xffff * 256**(0x1d - 3)
>>> difficulty = min_target // target
>>> print(difficulty)
888171856257

#endcode
#exercise
Calculate the target and difficulty for these bits:
```
f2881718
```

Bits to target formula is 

\\(\texttt{coefficient}\cdot256^{(\texttt{exponent}-3)}\\) 

where coefficient is the first three bytes in little endian and exponent is the last byte.

Target to Difficulty formula is 

\\(\texttt{difficulty} = \texttt{min} / \texttt{target}\\)

where \\(\texttt{min} = \texttt{0xffff}\cdot256^{(\texttt{0x1d}-3)}\\)
---
>>> hex_bits = 'f2881718'
>>> # bytes.fromhex to get the bits
>>> bits = bytes.fromhex(hex_bits)  #/
>>> # last byte is exponent
>>> exponent = bits[-1]  #/
>>> # first three bytes are the coefficient in little endian
>>> coefficient = little_endian_to_int(bits[:-1])  #/
>>> # plug into formula coefficient * 256^(exponent-3) to get the target
>>> target = coefficient * 256**(exponent-3)  #/
>>> # print target using print('{:x}'.format(target).zfill(64))
>>> print('{:x}'.format(target).zfill(64))  #/
00000000000000001788f2000000000000000000000000000000000000000000
>>> # difficulty formula is 0xffff * 256**(0x1d - 3) / target
>>> difficulty = 0xffff * 256**(0x1d - 3) // target  #/
>>> # print the difficulty
>>> print(difficulty)  #/
46717549644

#endexercise
#unittest
block:BlockTest:test_target:
#endunittest
#exercise
Validate the proof-of-work for this block
```
04000000fbedbbf0cfdaf278c094f187f2eb987c86a199da22bbb20400000000000000007b7697b29129648fa08b4bcd13c9d5e60abb973a1efac9c8d573c71c807c56c3d6213557faa80518c3737ec1
```

Check that the proof-of-work (hash256 interpreted as a little-endian number) is lower than the target.
---
>>> from block import Block
>>> hex_block = '04000000fbedbbf0cfdaf278c094f187f2eb987c86a199da22bbb20400000000000000007b7697b29129648fa08b4bcd13c9d5e60abb973a1efac9c8d573c71c807c56c3d6213557faa80518c3737ec1'
>>> # bytes.fromhex to get the binary block
>>> bin_block = bytes.fromhex(hex_block)  #/
>>> # make a stream using BytesIO
>>> stream = BytesIO(bin_block)  #/
>>> # parse the Block
>>> b = Block.parse(stream)  #/
>>> # hash256 the serialization
>>> h256 = hash256(b.serialize())  #/
>>> # interpret the result as a number in little endian
>>> proof = little_endian_to_int(h256)  #/
>>> # get the target
>>> target = b.target()  #/
>>> # check proof of work < target
>>> print(proof < target)  #/
True

#endexercise
#unittest
block:BlockTest:test_check_pow:
#endunittest
'''

from unittest import TestCase

import helper
import op

from block import Block
from ecc import S256Point, Signature
from helper import (
    encode_base58_checksum,
    hash256,
    int_to_little_endian,
    little_endian_to_int,
)
from op import (
    decode_num,
    encode_num,
)
from script import Script
from tx import Tx


def op_checkmultisig(stack, z):
    if len(stack) < 1:
        return False
    n = decode_num(stack.pop())
    if len(stack) < n + 1:
        return False
    sec_pubkeys = []
    for _ in range(n):
        sec_pubkeys.append(stack.pop())
    m = decode_num(stack.pop())
    if len(stack) < m + 1:
        return False
    der_signatures = []
    for _ in range(m):
        der_signatures.append(stack.pop()[:-1])
    stack.pop()
    try:
        points = [S256Point.parse(sec) for sec in sec_pubkeys]
        sigs = [Signature.parse(der) for der in der_signatures]
        for sig in sigs:
            if len(points) == 0:
                print("signatures no good or not in right order")
                return False
            while points:
                point = points.pop(0)
                if point.verify(z, sig):
                    break
        stack.append(encode_num(1))
    except (ValueError, SyntaxError):
        return False
    return True


def h160_to_p2pkh_address(h160, testnet=False):
    if testnet:
        prefix = b'\x6f'
    else:
        prefix = b'\x00'
    return encode_base58_checksum(prefix + h160)


def h160_to_p2sh_address(h160, testnet=False):
    if testnet:
        prefix = b'\xc4'
    else:
        prefix = b'\x05'
    return encode_base58_checksum(prefix + h160)


def is_p2pkh_script_pubkey(self):
    return len(self.commands) == 5 and self.commands[0] == 0x76 \
        and self.commands[1] == 0xa9 \
        and type(self.commands[2]) == bytes and len(self.commands[2]) == 20 \
        and self.commands[3] == 0x88 and self.commands[4] == 0xac


def is_p2sh_script_pubkey(self):
    return len(self.commands) == 3 and self.commands[0] == 0xa9 \
        and type(self.commands[1]) == bytes and len(self.commands[1]) == 20 \
        and self.commands[2] == 0x87


def address(self, testnet=False):
    if self.is_p2pkh_script_pubkey():
        h160 = self.commands[2]
        return h160_to_p2pkh_address(h160, testnet)
    elif self.is_p2sh_script_pubkey():
        h160 = self.commands[1]
        return h160_to_p2sh_address(h160, testnet)
    raise ValueError('Unknown ScriptPubKey')


def is_coinbase(self):
    if len(self.tx_ins) != 1:
        return False
    first_input = self.tx_ins[0]
    if first_input.prev_tx != b'\x00' * 32:
        return False
    if first_input.prev_index != 0xffffffff:
        return False
    return True


def coinbase_height(self):
    if not self.is_coinbase():
        return None
    first_input = self.tx_ins[0]
    first_element = first_input.script_sig.commands[0]
    return little_endian_to_int(first_element)


@classmethod
def parse(cls, s):
    version = little_endian_to_int(s.read(4))
    prev_block = s.read(32)[::-1]
    merkle_root = s.read(32)[::-1]
    timestamp = little_endian_to_int(s.read(4))
    bits = s.read(4)
    nonce = s.read(4)
    return cls(version, prev_block, merkle_root, timestamp, bits, nonce)


def serialize(self):
    result = int_to_little_endian(self.version, 4)
    result += self.prev_block[::-1]
    result += self.merkle_root[::-1]
    result += int_to_little_endian(self.timestamp, 4)
    result += self.bits
    result += self.nonce
    return result


def hash(self):
    s = self.serialize()
    h256 = hash256(s)
    return h256[::-1]


def bip9(self):
    return self.version >> 29 == 0b001


def bip91(self):
    return self.version >> 4 & 1 == 1


def bip141(self):
    return self.version >> 1 & 1 == 1


def target(self):
    exponent = self.bits[-1]
    coefficient = little_endian_to_int(self.bits[:-1])
    return coefficient * 256**(exponent - 3)


def difficulty(self):
    lowest = 0xffff * 256**(0x1d - 3)
    return lowest / self.target()


def check_pow(self):
    h256 = hash256(self.serialize())
    proof = little_endian_to_int(h256)
    return proof < self.target()


class Session6Test(TestCase):

    def test_apply(self):
        op.op_checkmultisig = op_checkmultisig
        op.OP_CODE_FUNCTIONS[0xae] = op_checkmultisig
        helper.h160_to_p2pkh_address = h160_to_p2pkh_address
        helper.h160_to_p2sh_address = h160_to_p2sh_address
        Script.is_p2pkh_script_pubkey = is_p2pkh_script_pubkey
        Script.is_p2sh_script_pubkey = is_p2sh_script_pubkey
        Script.address = address
        Tx.is_coinbase = is_coinbase
        Tx.coinbase_height = coinbase_height
        Block.parse = parse
        Block.serialize = serialize
        Block.hash = hash
        Block.bip9 = bip9
        Block.bip91 = bip91
        Block.bip141 = bip141
        Block.target = target
        Block.difficulty = difficulty
        Block.check_pow = check_pow
