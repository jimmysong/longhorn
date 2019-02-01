'''
#code
>>> import helper, op, script, tx

#endcode
#code
>>> from helper import hash256
>>> # hash256 example to get z
>>> modified_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000001976a914a802fc56c704ce87c42d7c92eb75e7896bdc41ae88acfeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac1943060001000000')
>>> h = hash256(modified_tx)
>>> z = int.from_bytes(h, 'big')
>>> print(hex(z))
0x27e0c5994dec7824e56dec6b2fcb342eb7cdb0d0957c2fce9882f715e85d81a6

#endcode
#unittest
tx:TxTest:test_sig_hash:
#endunittest
#code
>>> # Validation example
>>> from io import BytesIO
>>> from helper import hash256
>>> from tx import Tx
>>> modified_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000001976a914a802fc56c704ce87c42d7c92eb75e7896bdc41ae88acfeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac1943060001000000')
>>> h256 = hash256(modified_tx)
>>> z = int.from_bytes(h256, 'big')
>>> stream = BytesIO(bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600'))
>>> transaction = Tx.parse(stream)
>>> tx_in = transaction.tx_ins[0]
>>> combined_script = tx_in.script_sig + tx_in.script_pubkey()
>>> print(combined_script.evaluate(z))
True

#endcode
#exercise
Validate the signature for the first input in this transaction.
```
01000000012f5ab4d2666744a44864a63162060c2ae36ab0a2375b1c2b6b43077ed5dcbed6000000006a473044022034177d53fcb8e8cba62432c5f6cc3d11c16df1db0bce20b874cfc61128b529e1022040c2681a2845f5eb0c46adb89585604f7bf8397b82db3517afb63f8e3d609c990121035e8b10b675477614809f3dde7fd0e33fb898af6d86f51a65a54c838fddd417a5feffffff02c5872e00000000001976a91441b835c78fb1406305727d8925ff315d90f9bbc588acae2e1700000000001976a914c300e84d277c6c7bcf17190ebc4e7744609f8b0c88ac31470600
```
---
>>> from tx import Tx
>>> hex_tx = '01000000012f5ab4d2666744a44864a63162060c2ae36ab0a2375b1c2b6b43077ed5dcbed6000000006a473044022034177d53fcb8e8cba62432c5f6cc3d11c16df1db0bce20b874cfc61128b529e1022040c2681a2845f5eb0c46adb89585604f7bf8397b82db3517afb63f8e3d609c990121035e8b10b675477614809f3dde7fd0e33fb898af6d86f51a65a54c838fddd417a5feffffff02c5872e00000000001976a91441b835c78fb1406305727d8925ff315d90f9bbc588acae2e1700000000001976a914c300e84d277c6c7bcf17190ebc4e7744609f8b0c88ac31470600'
>>> stream = BytesIO(bytes.fromhex(hex_tx))
>>> index = 0
>>> # parse the transaction using Tx.parse
>>> t = Tx.parse(stream)  #/
>>> # grab the input at index
>>> tx_in = t.tx_ins[index]  #/
>>> # use the sig_hash method on index and hash_type to get z
>>> z = t.sig_hash(index)  #/
>>> # combine the script_sig and script_pubkey
>>> combined_script = tx_in.script_sig + tx_in.script_pubkey()  #/
>>> # evaluate the combined script
>>> print(combined_script.evaluate(z))  #/
True

#endexercise
#unittest
tx:TxTest:test_verify_p2pkh:
#endunittest
#code
>>> # Transaction Construction Example
>>> from ecc import PrivateKey
>>> from helper import decode_base58, SIGHASH_ALL
>>> from script import p2pkh_script, Script
>>> from tx import Tx, TxIn, TxOut
>>> # Step 1
>>> tx_ins = []
>>> prev_tx = bytes.fromhex('8be2f69037de71e3bc856a6627ed3e222a7a2d0ce81daeeb54a3aea8db274149')
>>> prev_index = 4
>>> tx_ins.append(TxIn(prev_tx, prev_index))
>>> # Step 2
>>> tx_outs = []
>>> h160 = decode_base58('mzx5YhAH9kNHtcN481u6WkjeHjYtVeKVh2')
>>> tx_outs.append(TxOut(
...     amount=int(0.38*100000000),
...     script_pubkey=p2pkh_script(h160),
... ))
>>> h160 = decode_base58('mnrVtF8DWjMu839VW3rBfgYaAfKk8983Xf')
>>> tx_outs.append(TxOut(
...     amount=int(0.1*100000000),
...     script_pubkey=p2pkh_script(h160),
... ))
>>> tx_obj = Tx(1, tx_ins, tx_outs, 0, testnet=True)
>>> # Step 3
>>> z = tx_obj.sig_hash(0)
>>> pk = PrivateKey(secret=8675309)
>>> der = pk.sign(z).der()
>>> sig = der + SIGHASH_ALL.to_bytes(1, 'big')
>>> sec = pk.point.sec()
>>> tx_obj.tx_ins[0].script_sig = Script([sig, sec])
>>> print(tx_obj.serialize().hex())
0100000001494127dba8aea354ebae1de80c2d7a2a223eed27666a85bce371de3790f6e28b040000006b483045022100fa3032607b50e8cb05bedc9d43f986f19dedc22e61320b9765061c5cd9c66946022072d514ef637988515bfa59a660596206de68f0ed4090d0a398e70f4d81370dfb012103935581e52c354cd2f484fe8ed83af7a3097005b2f9c60bff71d35bd795f54b67ffffffff0280d54302000000001976a914d52ad7ca9b3d096a38e752c2018e6fbc40cdf26f88ac80969800000000001976a914507b27411ccf7f16f10297de6cef3f291623eddf88ac00000000

#endcode
#unittest
tx:TxTest:test_sign_input:
#endunittest
#exercise
Send 0.04 TBTC to this address 

`mwJn1YPMq7y5F8J3LkC5Hxg9PHyZ5K4cFv`

#### Go here to send your transaction: https://live.blockcypher.com/btc-testnet/pushtx/
---
>>> from tx import Tx, TxIn, TxOut
>>> from helper import decode_base58, hash256, little_endian_to_int
>>> from script import p2pkh_script
>>> prev_tx = bytes.fromhex('0c024b9d3aa2ae8faae96603b8d40c88df2fc6bf50b3f446295206f70f3cf6ad')  #/prev_tx = bytes.fromhex('<transaction id here>')  # CHANGE
>>> prev_index = 0  #/prev_index = -1  # CHANGE
>>> target_address = 'mwJn1YPMq7y5F8J3LkC5Hxg9PHyZ5K4cFv'
>>> target_amount = 0.04
>>> fee = 50000
>>> passphrase = b'Jimmy Song'  #/passphrase = b'<your passphrase here>'  # CHANGE
>>> secret = little_endian_to_int(hash256(passphrase))
>>> private_key = PrivateKey(secret=secret)
>>> change_address = private_key.point.address(testnet=True)
>>> # initialize inputs
>>> tx_ins = []  #/
>>> # create a new tx input with prev_tx, prev_index
>>> tx_ins.append(TxIn(prev_tx, prev_index))  #/
>>> # initialize outputs
>>> tx_outs = []  #/
>>> # decode the hash160 from the target address
>>> h160 = decode_base58(target_address)  #/
>>> # convert hash160 to p2pkh script
>>> script_pubkey = p2pkh_script(h160)  #/
>>> # convert target amount to satoshis (multiply by 100 million)
>>> target_satoshis = int(target_amount*100000000)  #/
>>> # create a new tx output for target with amount and script_pubkey
>>> tx_outs.append(TxOut(target_satoshis, script_pubkey))  #/
>>> # decode the hash160 from the change address
>>> h160 = decode_base58(change_address)  #/
>>> # convert hash160 to p2pkh script
>>> script_pubkey = p2pkh_script(h160)  #/
>>> # get the value for the transaction input (remember testnet=True)
>>> prev_amount = tx_ins[0].value(testnet=True)  #/
>>> # calculate change_satoshis based on previous amount, target_satoshis & fee
>>> change_satoshis = prev_amount - target_satoshis - fee  #/
>>> # create a new tx output for target with amount and script_pubkey
>>> tx_outs.append(TxOut(change_satoshis, script_pubkey))  #/
>>> # create the transaction (name it tx_obj to not conflict)
>>> tx_obj = Tx(1, tx_ins, tx_outs, 0, testnet=True)  #/
>>> # now sign the 0th input with the private_key using sign_input
>>> tx_obj.sign_input(0, private_key)  #/
True
>>> # SANITY CHECK: change address corresponds to private key
>>> if private_key.point.address(testnet=True) != change_address:
...     raise RuntimeError('Private Key does not correspond to Change Address, check priv_key and change_address')
>>> # SANITY CHECK: output's script_pubkey is the same one as your address
>>> if tx_ins[0].script_pubkey(testnet=True).commands[2] != decode_base58(change_address):
...     raise RuntimeError('Output is not something you can spend with this private key. Check that the prev_tx and prev_index are correct')
>>> # SANITY CHECK: fee is reasonable
>>> if tx_obj.fee() > 0.05*100000000 or tx_obj.fee() <= 0:
...     raise RuntimeError('Check that the change amount is reasonable. Fee is {}'.format(tx_obj.fee()))
>>> # serialize and hex()
>>> print(tx_obj.serialize().hex())  #/
0100000001adf63c0ff706522946f4b350bfc62fdf880cd4b80366e9aa8faea23a9d4b020c000000006a47304402201967ab281d8d2b47cd36ae62022cb360d973fa97832edb97888d6b136196f23d022008dd3d8231e28429b61c92866a3e4394b067854b5d5fbc7fe3fc9b978522a298012103dc585d46cfca73f3a75ba1ef0c5756a21c1924587480700c6eb64e3f75d22083ffffffff0200093d00000000001976a914ad346f8eb57dee9a37981716e498120ae80e44f788ac30ca5a00000000001976a914850af0029eb376691c3eef244c25eceb4e50c50388ac00000000

#endexercise
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
'''


from unittest import TestCase

import helper
import op


from ecc import (
    PrivateKey,
    S256Point,
    Signature,
)
from helper import (
    decode_base58,
    encode_base58_checksum,
    encode_varint,
    hash160,
    hash256,
    int_to_little_endian,
    SIGHASH_ALL,
)
from op import (
    decode_num,
    encode_num,
)
from script import (
    p2pkh_script,
    Script,
)
from tx import (
    Tx,
    TxIn,
    TxOut,
)


def sig_hash(self, input_index):
    s = int_to_little_endian(self.version, 4)
    s += encode_varint(len(self.tx_ins))
    for i, tx_in in enumerate(self.tx_ins):
        if i == input_index:
            script_sig = tx_in.script_pubkey(self.testnet)
        else:
            script_sig = None
        s += TxIn(
            prev_tx=tx_in.prev_tx,
            prev_index=tx_in.prev_index,
            script_sig=script_sig,
            sequence=tx_in.sequence,
        ).serialize()
    s += encode_varint(len(self.tx_outs))
    for tx_out in self.tx_outs:
        s += tx_out.serialize()
    s += int_to_little_endian(self.locktime, 4)
    s += int_to_little_endian(SIGHASH_ALL, 4)
    h256 = hash256(s)
    return int.from_bytes(h256, 'big')


def verify_input(self, input_index):
    tx_in = self.tx_ins[input_index]
    z = self.sig_hash(input_index)
    combined_script = tx_in.script_sig + tx_in.script_pubkey(self.testnet)
    return combined_script.evaluate(z)


def sign_input(self, input_index, private_key):
    z = self.sig_hash(input_index)
    der = private_key.sign(z).der()
    sig = der + SIGHASH_ALL.to_bytes(1, 'big')
    sec = private_key.point.sec()
    script_sig = Script([sig, sec])
    self.tx_ins[input_index].script_sig = script_sig
    return self.verify_input(input_index)


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


class SessionTest(TestCase):

    def test_apply(self):
        Tx.sig_hash = sig_hash
        Tx.verify_input = verify_input
        Tx.sign_input = sign_input
        op.op_checkmultisig = op_checkmultisig
        op.OP_CODE_FUNCTIONS[0xae] = op_checkmultisig
        helper.h160_to_p2pkh_address = h160_to_p2pkh_address
        helper.h160_to_p2sh_address = h160_to_p2sh_address
        Script.is_p2pkh_script_pubkey = is_p2pkh_script_pubkey
        Script.is_p2sh_script_pubkey = is_p2sh_script_pubkey
        Script.address = address
