'''
#code
>>> import bloomfilter, network

#endcode
#code
>>> # Example Bloom Filter
>>> from helper import hash256
>>> bit_field_size = 10
>>> bit_field = [0] * bit_field_size
>>> h256 = hash256(b'hello world')
>>> bit = int.from_bytes(h256, 'big') % bit_field_size
>>> bit_field[bit] = 1
>>> print(bit_field)
[0, 0, 0, 0, 0, 0, 0, 0, 0, 1]

#endcode
#code
>>> # Example Bloom Filter 2
>>> from helper import hash256
>>> bit_field_size = 10
>>> bit_field = [0] * bit_field_size
>>> h = hash256(b'hello world')
>>> bit = int.from_bytes(h, 'big') % bit_field_size
>>> bit_field[bit] = 1
>>> h = hash256(b'goodbye')
>>> bit = int.from_bytes(h, 'big') % bit_field_size
>>> bit_field[bit] = 1
>>> print(bit_field)
[0, 0, 1, 0, 0, 0, 0, 0, 0, 1]

#endcode
#code
>>> # Example Bloom Filter 3
>>> from helper import hash160, hash256
>>> bit_field_size = 10
>>> bit_field = [0] * bit_field_size
>>> phrase1 = b'hello world'
>>> h1 = hash256(phrase1)
>>> bit1 = int.from_bytes(h1, 'big') % bit_field_size
>>> bit_field[bit1] = 1
>>> h2 = hash160(phrase1)
>>> bit2 = int.from_bytes(h2, 'big') % bit_field_size
>>> bit_field[bit2] = 1
>>> phrase2 = b'goodbye'
>>> h1 = hash256(phrase2)
>>> bit1 = int.from_bytes(h1, 'big') % bit_field_size
>>> bit_field[bit1] = 1
>>> h2 = hash160(phrase2)
>>> bit2 = int.from_bytes(h2, 'big') % bit_field_size
>>> bit_field[bit2] = 1
>>> print(bit_field)
[1, 1, 1, 0, 0, 0, 0, 0, 0, 1]

#endcode
#code
>>> # Example BIP0037 Bloom Filter
>>> from helper import murmur3
>>> from bloomfilter import BIP37_CONSTANT
>>> field_size = 2
>>> num_functions = 2
>>> tweak = 42
>>> bit_field_size = field_size * 8
>>> bit_field = [0] * bit_field_size
>>> for phrase in (b'hello world', b'goodbye'):
...     for i in range(num_functions):
...         seed = i * BIP37_CONSTANT + tweak
...         h = murmur3(phrase, seed=seed)
...         bit = h % bit_field_size
...         bit_field[bit] = 1
>>> print(bit_field)
[0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0]

#endcode
#exercise
Given a Bloom Filter with these parameters: size=10, function count=5, tweak=99, which bits are set after adding these items? 

 * `b'Hello World'`
 * `b'Goodbye!'`
---
>>> from bloomfilter import BIP37_CONSTANT
>>> from helper import murmur3, bit_field_to_bytes
>>> field_size = 10
>>> function_count = 5
>>> tweak = 99
>>> items = (b'Hello World',  b'Goodbye!')
>>> # bit_field_size is 8 * field_size
>>> bit_field_size = field_size * 8  #/
>>> # create a bit field with the appropriate size
>>> bit_field = [0] * bit_field_size  #/
>>> # for each item you want to add to the filter
>>> for item in items:  #/
...     # iterate function_count number of times
...     for i in range(function_count):  #/
...         # BIP0037 spec seed is i*BIP37_CONSTANT + tweak
...         seed = i * BIP37_CONSTANT + tweak  #/
...         # get the murmur3 hash given that seed
...         h = murmur3(item, seed=seed)  #/
...         # set the bit to be h mod the bit_field_size
...         bit = h % bit_field_size  #/
...         # set the bit_field at the index bit to be 1
...         bit_field[bit] = 1  #/
>>> # print the bit field converted to bytes using bit_field_to_bytes in hex
>>> print(bit_field_to_bytes(bit_field).hex())  #/
4000600a080000010940

#endexercise
#unittest
bloomfilter:BloomFilterTest:test_add:
#endunittest
#unittest
bloomfilter:BloomFilterTest:test_filterload:
#endunittest
#exercise
Do the following:

* Connect to a testnet node
* Load a filter for your testnet address
* Send a request for transactions from the block which had your previous testnet transaction
* Receive the merkleblock and tx messages.
---
>>> from bloomfilter import BloomFilter
>>> from ecc import PrivateKey
>>> from helper import decode_base58, hash256, little_endian_to_int
>>> from merkleblock import MerkleBlock
>>> from network import SimpleNode, GetDataMessage, FILTERED_BLOCK_DATA_TYPE
>>> from tx import Tx
>>> block_hash = bytes.fromhex('00000000000129fc37fde810db09f033014e501595f8560dcdb2e86756986ee3')  #/block_hash = bytes.fromhex('000000000000000062ee8cbb66a01827eaed3500bb1f9879b54e67724febef3c')  # CHANGE
>>> passphrase = b'Jimmy Song'  #/passphrase = b'<your passphrase here>'  # CHANGE
>>> secret = little_endian_to_int(hash256(passphrase))
>>> private_key = PrivateKey(secret=secret)
>>> addr = private_key.point.address(testnet=True)
>>> print(addr)
mseRGXB89UTFVkWJhTRTzzZ9Ujj4ZPbGK5
>>> filter_size = 30
>>> filter_num_functions = 5
>>> filter_tweak = 90210  #/filter_tweak = -1  # CHANGE
>>> # get the hash160 of the address using decode_base58
>>> h160 = decode_base58(addr)  #/
>>> # create a bloom filter using the filter_size, filter_num_functions and filter_tweak above
>>> bf = BloomFilter(filter_size, filter_num_functions, filter_tweak)  #/
>>> # add the h160 to the bloom filter
>>> bf.add(h160)  #/
>>> # connect to tbtc.programmingblockchain.com in testnet mode
>>> node = SimpleNode('tbtc.programmingblockchain.com', testnet=True)  #/
>>> # complete the handshake
>>> node.handshake()  #/
>>> # send the filterload message
>>> node.send(bf.filterload())  #/
>>> # create a getdata message
>>> getdata = GetDataMessage()  #/
>>> # use the add_data method of GetDataMessage with the parameters
>>> # (FILTERED_BLOCK_DATA_TYPE, block_hash) to request the block
>>> getdata.add_data(FILTERED_BLOCK_DATA_TYPE, block_hash)  #/
>>> # send the GetDataMessage
>>> node.send(getdata)  #/
>>> # wait for the merkleblock command
>>> mb = node.wait_for(MerkleBlock)  #/
>>> # check that the merkle block's hash is the same as the block hash
>>> if mb.hash() != block_hash:  #/
...     raise RuntimeError('Wrong Merkle Block')  #/
>>> # check that the merkle block is valid
>>> if not mb.is_valid():  #/
...     raise RuntimeError('Invalid Merkle Block')  #/
>>> # loop through the tx hashes we are expecting using proved_txs
>>> for tx_hash in mb.proved_txs():  #/
...     # wait for the tx command
...     tx_obj = node.wait_for(Tx)  #/
...     # check that the tx hash is the same
...     if tx_obj.hash() != tx_hash:  #/
...         raise RuntimeError('Wrong transaction')  #/
...     # print the transaction serialization in hex
...     print(tx_obj.serialize().hex())  #/
0100000001ca4683960a9c21c0fb6b1d284fc5fe86509c773adf912eee4692859304ce0fb0000000006a47304402200d4c054deca1e76347bd336fbc6bc0132aa2e4a2aafc0792c8a1aa23ec6ed1af0220720444626b807f7c77a89aad4bb0a78ae9c5d9adea296e8e22e66a1681393b480121031dbe3aff7b9ad64e2612b8b15e9f5e4a3130663a526df91abfb7b1bd16de5d6effffffff0280969800000000001976a914850af0029eb376691c3eef244c25eceb4e50c50388acefece184000000001976a9146e13971913b9aa89659a9f53d327baa8826f2d7588ac00000000

#endexercise
#unittest
network:SimpleNodeTest:test_get_filtered_txs:
#endunittest
'''


from unittest import TestCase

from bloomfilter import (
    BloomFilter,
    BIP37_CONSTANT,
)
from ecc import PrivateKey
from helper import (
    bit_field_to_bytes,
    bytes_to_bit_field,
    decode_base58,
    hash160,
    hash256,
    encode_varint,
    int_to_little_endian,
    little_endian_to_int,
    murmur3,
)
from merkleblock import (
    MerkleBlock,
    MerkleTree,
)
from network import (
    GenericMessage,
    GetDataMessage,
    GetHeadersMessage,
    HeadersMessage,
    SimpleNode,
    FILTERED_BLOCK_DATA_TYPE,
)
from script import p2pkh_script
from tx import (
    Tx,
    TxIn,
    TxOut,
)


def add(self, item):
    for i in range(self.function_count):
        seed = i * BIP37_CONSTANT + self.tweak
        h = murmur3(item, seed=seed)
        bit = h % (self.size * 8)
        self.bit_field[bit] = 1


def filterload(self, flag=1):
    payload = encode_varint(self.size)
    payload += self.filter_bytes()
    payload += int_to_little_endian(self.function_count, 4)
    payload += int_to_little_endian(self.tweak, 4)
    payload += int_to_little_endian(flag, 1)
    return GenericMessage(b'filterload', payload)


def serialize(self):
    result = encode_varint(len(self.data))
    for data_type, identifier in self.data:
        result += int_to_little_endian(data_type, 4)
        result += identifier[::-1]
    return result


def get_filtered_txs(self, block_hashes):
    getdata = GetDataMessage()
    for block_hash in block_hashes:
        getdata.add_data(FILTERED_BLOCK_DATA_TYPE, block_hash)
    self.send(getdata)
    results = []
    for block_hash in block_hashes:
        mb = self.wait_for(MerkleBlock)
        if mb.hash() != block_hash:
            raise RuntimeError('Wrong block sent')
        if not mb.is_valid():
            raise RuntimeError('Merkle Proof is invalid')
        for tx_hash in mb.proved_txs():
            tx_obj = self.wait_for(Tx)
            if tx_obj.hash() != tx_hash:
                raise RuntimeError('Wrong tx sent {} vs {}'.format(tx_hash.hex(), tx_obj.id()))
            results.append(tx_obj)
    return results


class Session8Test(TestCase):

    def test_apply(self):
        BloomFilter.add = add
        BloomFilter.filterload = filterload
        GetDataMessage.serialize = serialize
        SimpleNode.get_filtered_txs = get_filtered_txs


if __name__ == "__main__":
    import doctest
    doctest.testmod()
