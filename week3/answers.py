'''
#code
>>> import ecc, helper, op, script, tx

#endcode
#example
>>> from ecc import PrivateKey
>>> from helper import little_endian_to_int, hash256
>>> passphrase = b'Jimmy Song'
>>> secret = little_endian_to_int(hash256(passphrase))
>>> z = little_endian_to_int(hash256(b'Some defunct economist'))
>>> private_key = PrivateKey(secret=secret)
>>> print(private_key.point.sec().hex())
03dc585d46cfca73f3a75ba1ef0c5756a21c1924587480700c6eb64e3f75d22083
>>> print(private_key.sign(z).der().hex())
30440220171c533f90349bb983eae749d2840b88516e61aceefd51b71a9cbd6a453b1b0a022039f371835be44f941cb0b832f1301b1089bc0b7b264646909bb5268e0e3b385a

#endexample
#unittest
tx:TxTest:test_parse_version:
#endunittest
#unittest
tx:TxTest:test_parse_inputs:
#endunittest
#unittest
tx:TxTest:test_parse_outputs:
#endunittest
#unittest
tx:TxTest:test_parse_locktime:
#endunittest
#exercise
What is the scriptSig from the second input in this tx? What is the scriptPubKey and amount of the first output in this tx? What is the amount for the second output?

```
010000000456919960ac691763688d3d3bcea9ad6ecaf875df5339e148a1fc61c6ed7a069e010000006a47304402204585bcdef85e6b1c6af5c2669d4830ff86e42dd205c0e089bc2a821657e951c002201024a10366077f87d6bce1f7100ad8cfa8a064b39d4e8fe4ea13a7b71aa8180f012102f0da57e85eec2934a82a585ea337ce2f4998b50ae699dd79f5880e253dafafb7feffffffeb8f51f4038dc17e6313cf831d4f02281c2a468bde0fafd37f1bf882729e7fd3000000006a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937feffffff567bf40595119d1bb8a3037c356efd56170b64cbcc160fb028fa10704b45d775000000006a47304402204c7c7818424c7f7911da6cddc59655a70af1cb5eaf17c69dadbfc74ffa0b662f02207599e08bc8023693ad4e9527dc42c34210f7a7d1d1ddfc8492b654a11e7620a0012102158b46fbdff65d0172b7989aec8850aa0dae49abfb84c81ae6e5b251a58ace5cfeffffffd63a5e6c16e620f86f375925b21cabaf736c779f88fd04dcad51d26690f7f345010000006a47304402200633ea0d3314bea0d95b3cd8dadb2ef79ea8331ffe1e61f762c0f6daea0fabde022029f23b3e9c30f080446150b23852028751635dcee2be669c2a1686a4b5edf304012103ffd6f4a67e94aba353a00882e563ff2722eb4cff0ad6006e86ee20dfe7520d55feffffff0251430f00000000001976a914ab0c0b2e98b1ab6dbf67d4750b0a56244948a87988ac005a6202000000001976a9143c82d7df364eb6c75be8c80df2b3eda8db57397088ac46430600
```
---
>>> from io import BytesIO
>>> from tx import Tx
>>> hex_transaction = '010000000456919960ac691763688d3d3bcea9ad6ecaf875df5339e148a1fc61c6ed7a069e010000006a47304402204585bcdef85e6b1c6af5c2669d4830ff86e42dd205c0e089bc2a821657e951c002201024a10366077f87d6bce1f7100ad8cfa8a064b39d4e8fe4ea13a7b71aa8180f012102f0da57e85eec2934a82a585ea337ce2f4998b50ae699dd79f5880e253dafafb7feffffffeb8f51f4038dc17e6313cf831d4f02281c2a468bde0fafd37f1bf882729e7fd3000000006a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937feffffff567bf40595119d1bb8a3037c356efd56170b64cbcc160fb028fa10704b45d775000000006a47304402204c7c7818424c7f7911da6cddc59655a70af1cb5eaf17c69dadbfc74ffa0b662f02207599e08bc8023693ad4e9527dc42c34210f7a7d1d1ddfc8492b654a11e7620a0012102158b46fbdff65d0172b7989aec8850aa0dae49abfb84c81ae6e5b251a58ace5cfeffffffd63a5e6c16e620f86f375925b21cabaf736c779f88fd04dcad51d26690f7f345010000006a47304402200633ea0d3314bea0d95b3cd8dadb2ef79ea8331ffe1e61f762c0f6daea0fabde022029f23b3e9c30f080446150b23852028751635dcee2be669c2a1686a4b5edf304012103ffd6f4a67e94aba353a00882e563ff2722eb4cff0ad6006e86ee20dfe7520d55feffffff0251430f00000000001976a914ab0c0b2e98b1ab6dbf67d4750b0a56244948a87988ac005a6202000000001976a9143c82d7df364eb6c75be8c80df2b3eda8db57397088ac46430600'
>>> # bytes.fromhex to get the binary representation
>>> bin_transaction = bytes.fromhex(hex_transaction)  #/
>>> # create a stream using BytesIO()
>>> stream = BytesIO(bin_transaction)  #/
>>> # Tx.parse() the stream
>>> tx_obj = Tx.parse(stream)  #/
>>> # print tx's second input's scriptSig
>>> print(tx_obj.tx_ins[1].script_sig)  #/
304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a71601 035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937 
>>> # print tx's first output's scriptPubKey
>>> print(tx_obj.tx_outs[0].script_pubkey)  #/
OP_DUP OP_HASH160 ab0c0b2e98b1ab6dbf67d4750b0a56244948a879 OP_EQUALVERIFY OP_CHECKSIG 
>>> # print tx's second output's amount
>>> print(tx_obj.tx_outs[1].amount)  #/
40000000

#endexercise
#code
>>> # Example opcode processing
>>> from helper import hash256
>>> def op_dup(stack):
...     if len(stack) < 1:
...         return False
...     stack.append(stack[-1])
...     return True
>>> 
>>> def op_hash256(stack):
...     if len(stack) < 1:
...         return False
...     element = stack.pop()
...     stack.append(hash256(element))
...     return True

#endcode
#unittest
op:OpTest:test_op_hash160:
#endunittest
#code
>>> # Example of evaluation
>>> from script import Script
>>> z = 0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d
>>> sec = bytes.fromhex('04887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34')
>>> sig = bytes.fromhex('3045022000eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c022100c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab601')
>>> script_pubkey = Script([sec, 0xac])
>>> script_sig = Script([sig])
>>> combined_script = script_sig + script_pubkey
>>> print(combined_script.evaluate(z))
True

#endcode
#unittest
op:OpTest:test_op_checksig:
#endunittest
#code
>>> # Example Script
>>> from io import BytesIO
>>> from script import Script
>>> script_pubkey = Script([0x55, 0x93, 0x59, 0x87])
>>> script_sig = Script([0x54])
>>> combined_script = script_sig + script_pubkey
>>> print(combined_script.evaluate(0))
True

#endcode
#exercise
Determine a ScriptSig that will satisfy this scriptPubKey:
```
767695935687
```
---
>>> from io import BytesIO
>>> from script import Script
>>> script_pubkey = Script([0x76, 0x76, 0x95, 0x93, 0x56, 0x87])
>>> # print the script_pubkey
>>> print(script_pubkey)  #/
OP_DUP OP_DUP OP_MUL OP_ADD OP_6 OP_EQUAL 
>>> # Find the right scriptSig
>>> script_sig = Script([0x52])  #/
>>> # combine the scripts
>>> combined_script = script_sig + script_pubkey  #/
>>> # evaluate combined script
>>> print(combined_script.evaluate(0))  #/
True

#endexercise
#exercise
Determine what this ScriptPubKey is doing:
```
6e879169a77ca787
```

* 69 = OP_VERIFY (exits if top element not true)
* 6e = OP_2DUP (duplicates top 2 elements)
* 7c = OP_SWAP (swaps top 2 elements)
* 87 = OP_EQUAL
* 91 = OP_NOT (inverts top element)
* a7 = OP_SHA1 (sha1 of top element)
---
>>> script_pubkey = Script([0x6e, 0x87, 0x91, 0x69, 0xa7, 0x7c, 0xa7, 0x87])
>>> # print the script_pubkey
>>> print(script_pubkey)  #/
OP_2DUP OP_EQUAL OP_NOT OP_VERIFY OP_SHA1 OP_SWAP OP_SHA1 OP_EQUAL 
>>> # SOLUTION  #/
>>> hex_script_sig = 'fd86024d4001255044462d312e330a25e2e3cfd30a0a0a312030206f626a0a3c3c2f57696474682032203020522f4865696768742033203020522f547970652034203020522f537562747970652035203020522f46696c7465722036203020522f436f6c6f7253706163652037203020522f4c656e6774682038203020522f42697473506572436f6d706f6e656e7420383e3e0a73747265616d0affd8fffe00245348412d3120697320646561642121212121852fec092339759c39b1a1c63c4c97e1fffe017f46dc93a6b67e013b029aaa1db2560b45ca67d688c7f84b8c4c791fe02b3df614f86db1690901c56b45c1530afedfb76038e972722fe7ad728f0e4904e046c230570fe9d41398abe12ef5bc942be33542a4802d98b5d70f2a332ec37fac3514e74ddc0f2cc1a874cd0c78305a21566461309789606bd0bf3f98cda8044629a14d4001255044462d312e330a25e2e3cfd30a0a0a312030206f626a0a3c3c2f57696474682032203020522f4865696768742033203020522f547970652034203020522f537562747970652035203020522f46696c7465722036203020522f436f6c6f7253706163652037203020522f4c656e6774682038203020522f42697473506572436f6d706f6e656e7420383e3e0a73747265616d0affd8fffe00245348412d3120697320646561642121212121852fec092339759c39b1a1c63c4c97e1fffe017346dc9166b67e118f029ab621b2560ff9ca67cca8c7f85ba84c79030c2b3de218f86db3a90901d5df45c14f26fedfb3dc38e96ac22fe7bd728f0e45bce046d23c570feb141398bb552ef5a0a82be331fea48037b8b5d71f0e332edf93ac3500eb4ddc0decc1a864790c782c76215660dd309791d06bd0af3f98cda4bc4629b1'  #/
>>> script_sig = Script.parse(BytesIO(bytes.fromhex(hex_script_sig)))  #/
>>> combined_script = script_sig + script_pubkey  #/
>>> print(combined_script.evaluate(0))  #/
True

#endexercise
#unittest
tx:TxTest:test_serialize:
#endunittest
#code
>>> # Example of how to look up a transaction using fetch_tx() method
>>> from tx import TxIn
>>> prev_tx = bytes.fromhex('d1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81') 
>>> tx_in = TxIn(prev_tx, 0)
>>> print(tx_in.fetch_tx().tx_ins)
[cbf43825e0b92ba3bfabaec509e14ee9132df1e92ffdfc6636f848fbf0537c13:0, 590133d8ac653229dfd8d72d2a81564502051f21554f919ae59ac27be7727451:1]

#endcode
#exercise
What is the value and ScriptPubKey of the 0th output of this transaction?
```
d1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81
```
---
>>> from tx import TxIn
>>> prev_tx = bytes.fromhex('d1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81') 
>>> prev_index = 0
>>> # create the transaction input
>>> tx_in = TxIn(prev_tx, 0)  #/
>>> # fetch the transaction (call this tx_obj to not conflict)
>>> tx_obj = tx_in.fetch_tx()  #/
>>> # grab the output at the index
>>> prev_output = tx_obj.tx_outs[prev_index]  #/
>>> # show the amount
>>> print(prev_output.amount)  #/
42505594
>>> # show the script_pubkey
>>> print(prev_output.script_pubkey)  #/
OP_DUP OP_HASH160 a802fc56c704ce87c42d7c92eb75e7896bdc41ae OP_EQUALVERIFY OP_CHECKSIG 

#endexercise
#unittest
tx:TxTest:test_input_value:
#endunittest
#unittest
tx:TxTest:test_input_pubkey:
#endunittest
#exercise
How much is the transaction fee of this transaction?
```
010000000456919960ac691763688d3d3bcea9ad6ecaf875df5339e148a1fc61c6ed7a069e010000006a47304402204585bcdef85e6b1c6af5c2669d4830ff86e42dd205c0e089bc2a821657e951c002201024a10366077f87d6bce1f7100ad8cfa8a064b39d4e8fe4ea13a7b71aa8180f012102f0da57e85eec2934a82a585ea337ce2f4998b50ae699dd79f5880e253dafafb7feffffffeb8f51f4038dc17e6313cf831d4f02281c2a468bde0fafd37f1bf882729e7fd3000000006a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937feffffff567bf40595119d1bb8a3037c356efd56170b64cbcc160fb028fa10704b45d775000000006a47304402204c7c7818424c7f7911da6cddc59655a70af1cb5eaf17c69dadbfc74ffa0b662f02207599e08bc8023693ad4e9527dc42c34210f7a7d1d1ddfc8492b654a11e7620a0012102158b46fbdff65d0172b7989aec8850aa0dae49abfb84c81ae6e5b251a58ace5cfeffffffd63a5e6c16e620f86f375925b21cabaf736c779f88fd04dcad51d26690f7f345010000006a47304402200633ea0d3314bea0d95b3cd8dadb2ef79ea8331ffe1e61f762c0f6daea0fabde022029f23b3e9c30f080446150b23852028751635dcee2be669c2a1686a4b5edf304012103ffd6f4a67e94aba353a00882e563ff2722eb4cff0ad6006e86ee20dfe7520d55feffffff0251430f00000000001976a914ab0c0b2e98b1ab6dbf67d4750b0a56244948a87988ac005a6202000000001976a9143c82d7df364eb6c75be8c80df2b3eda8db57397088ac46430600
```

Fee is simply the sum of the inputs (use the value() method) minus the outputs (use the amount property)
---
>>> from io import BytesIO
>>> from tx import Tx
>>> hex_tx = '010000000456919960ac691763688d3d3bcea9ad6ecaf875df5339e148a1fc61c6ed7a069e010000006a47304402204585bcdef85e6b1c6af5c2669d4830ff86e42dd205c0e089bc2a821657e951c002201024a10366077f87d6bce1f7100ad8cfa8a064b39d4e8fe4ea13a7b71aa8180f012102f0da57e85eec2934a82a585ea337ce2f4998b50ae699dd79f5880e253dafafb7feffffffeb8f51f4038dc17e6313cf831d4f02281c2a468bde0fafd37f1bf882729e7fd3000000006a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937feffffff567bf40595119d1bb8a3037c356efd56170b64cbcc160fb028fa10704b45d775000000006a47304402204c7c7818424c7f7911da6cddc59655a70af1cb5eaf17c69dadbfc74ffa0b662f02207599e08bc8023693ad4e9527dc42c34210f7a7d1d1ddfc8492b654a11e7620a0012102158b46fbdff65d0172b7989aec8850aa0dae49abfb84c81ae6e5b251a58ace5cfeffffffd63a5e6c16e620f86f375925b21cabaf736c779f88fd04dcad51d26690f7f345010000006a47304402200633ea0d3314bea0d95b3cd8dadb2ef79ea8331ffe1e61f762c0f6daea0fabde022029f23b3e9c30f080446150b23852028751635dcee2be669c2a1686a4b5edf304012103ffd6f4a67e94aba353a00882e563ff2722eb4cff0ad6006e86ee20dfe7520d55feffffff0251430f00000000001976a914ab0c0b2e98b1ab6dbf67d4750b0a56244948a87988ac005a6202000000001976a9143c82d7df364eb6c75be8c80df2b3eda8db57397088ac46430600'
>>> # bytes.fromhex the tx, make stream
>>> stream = BytesIO(bytes.fromhex(hex_tx))
>>> # parse the tx (call this tx_obj to not conflict with anything)
>>> tx_obj = Tx.parse(stream)  #/
>>> # initialize input sum
>>> input_sum = 0  #/
>>> # iterate over all inputs (tx_obj.tx_ins)
>>> for tx_in in tx_obj.tx_ins:  #/
...     # get the values from the TxIn.value method you wrote in 4.2
...     value = tx_in.value()  #/
...     # add to input sum
...     input_sum += value  #/
>>> # initialize output sum
>>> output_sum = 0  #/
>>> # iterate over all outputs (tx_obj.tx_outs)
>>> for tx_out in tx_obj.tx_outs:  #/
...     # get the amounts from the TxOut.amount property
...     value = tx_out.amount  #/
...     # add to output sum
...     output_sum += value  #/
>>> # fee is input sum - output sum
>>> fee = input_sum - output_sum  #/
>>> # print the fee
>>> print(fee)  #/
140500

#endexercise
#unittest
tx:TxTest:test_fee:
#endunittest
'''


from unittest import TestCase

import op

from ecc import S256Point, Signature
from helper import (
    encode_varint,
    hash160,
    hash256,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
)
from op import encode_num
from script import Script
from tx import Tx, TxIn, TxOut


@classmethod
def parse_tx(cls, s, testnet=False):
    '''Takes a byte stream and parses the transaction at the start
    return a Tx object
    '''
    version = little_endian_to_int(s.read(4))
    num_inputs = read_varint(s)
    inputs = []
    for _ in range(num_inputs):
        inputs.append(TxIn.parse(s))
    num_outputs = read_varint(s)
    outputs = []
    for _ in range(num_outputs):
        outputs.append(TxOut.parse(s))
    locktime = little_endian_to_int(s.read(4))
    return cls(version, inputs, outputs, locktime, testnet=testnet)


@classmethod
def parse_txin(cls, s):
    '''Takes a byte stream and parses the tx_input at the start
    return a TxIn object
    '''
    prev_tx = s.read(32)[::-1]
    prev_index = little_endian_to_int(s.read(4))
    script_sig = Script.parse(s)
    sequence = little_endian_to_int(s.read(4))
    return cls(prev_tx, prev_index, script_sig, sequence)


@classmethod
def parse_txout(cls, s):
    amount = little_endian_to_int(s.read(8))
    script_pubkey = Script.parse(s)
    return cls(amount, script_pubkey)


def op_hash160(stack):
    if len(stack) < 1:
        return False
    element = stack.pop()
    h160 = hash160(element)
    stack.append(h160)
    return True


def op_checksig(stack, z):
    if len(stack) < 2:
        return False
    sec_pubkey = stack.pop()
    der_signature = stack.pop()[:-1]
    point = S256Point.parse(sec_pubkey)
    sig = Signature.parse(der_signature)
    if point.verify(z, sig):
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def serialize_tx(self):
    result = int_to_little_endian(self.version, 4)
    result += encode_varint(len(self.tx_ins))
    for tx_in in self.tx_ins:
        result += tx_in.serialize()
    result += encode_varint(len(self.tx_outs))
    for tx_out in self.tx_outs:
        result += tx_out.serialize()
    result += int_to_little_endian(self.locktime, 4)
    return result


def serialize_txin(self):
    result = self.prev_tx[::-1]
    result += int_to_little_endian(self.prev_index, 4)
    result += self.script_sig.serialize()
    result += int_to_little_endian(self.sequence, 4)
    return result


def serialize_txout(self):
    result = int_to_little_endian(self.amount, 8)
    result += self.script_pubkey.serialize()
    return result


def value(self, testnet=False):
    tx = self.fetch_tx(testnet=testnet)
    return tx.tx_outs[self.prev_index].amount


def script_pubkey(self, testnet=False):
    tx = self.fetch_tx(testnet=testnet)
    return tx.tx_outs[self.prev_index].script_pubkey


def fee(self):
    input_sum, output_sum = 0, 0
    for tx_in in self.tx_ins:
        input_sum += tx_in.value(self.testnet)
    for tx_out in self.tx_outs:
        output_sum += tx_out.amount
    return input_sum - output_sum


class SessionTest(TestCase):

    def test_apply(self):
        op.op_hash160 = op_hash160
        op.OP_CODE_FUNCTIONS[0xa9] = op_hash160
        op.op_checksig = op_checksig
        op.OP_CODE_FUNCTIONS[0xac] = op_checksig
        Tx.parse = parse_tx
        TxIn.parse = parse_txin
        TxOut.parse = parse_txout
        Tx.serialize = serialize_tx
        TxIn.serialize = serialize_txin
        TxOut.serialize = serialize_txout
        TxIn.value = value
        TxIn.script_pubkey = script_pubkey
        Tx.fee = fee
