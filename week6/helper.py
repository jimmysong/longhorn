from unittest import TestCase, TestSuite, TextTestRunner

import hashlib


SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def run(test):
    suite = TestSuite()
    suite.addTest(test)
    TextTestRunner().run(suite)


def bytes_to_str(b, encoding='ascii'):
    '''Returns a string version of the bytes'''
    return b.decode(encoding)


def str_to_bytes(s, encoding='ascii'):
    '''Returns a bytes version of the string'''
    return s.encode(encoding)


def little_endian_to_int(b):
    '''little_endian_to_int takes byte sequence as a little-endian number.
    Returns an integer'''
    # use the from_bytes method of int
    return int.from_bytes(b, 'little')


def int_to_little_endian(n, length):
    '''endian_to_little_endian takes an integer and returns the little-endian
    byte sequence of length'''
    # use the to_bytes method of n
    return n.to_bytes(length, 'little')


def hash160(s):
    return hashlib.new('ripemd160', hashlib.sha256(s).digest()).digest()


def hash256(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()


def encode_base58(s):
    # determine how many 0 bytes (b'\x00') s starts with
    count = 0
    for c in s:
        if c == 0:
            count += 1
        else:
            break
    # convert from binary to hex, then hex to integer
    num = int(s.hex(), 16)
    result = ''
    prefix = '1' * count
    while num > 0:
        num, mod = divmod(num, 58)
        result = BASE58_ALPHABET[mod] + result
    return prefix + result


def encode_base58_checksum(raw):
    '''Takes bytes and turns it into base58 encoding with checksum'''
    # checksum is the first 4 bytes of the hash256
    checksum = hash256(raw)[:4]
    # encode_base58 on the raw and the checksum
    return encode_base58(raw + checksum)


def decode_base58(s):
    num = 0
    for c in s:
        num *= 58
        num += BASE58_ALPHABET.index(c)
    combined = num.to_bytes(25, byteorder='big')
    checksum = combined[-4:]
    if hash256(combined[:-4])[:4] != checksum:
        raise RuntimeError('bad address: {} {}'.format(checksum, hash256(combined)[:4]))
    return combined[1:-4]


def read_varint(s):
    '''read_varint reads a variable integer from a stream'''
    i = s.read(1)[0]
    if i == 0xfd:
        # 0xfd means the next two bytes are the number
        return little_endian_to_int(s.read(2))
    elif i == 0xfe:
        # 0xfe means the next four bytes are the number
        return little_endian_to_int(s.read(4))
    elif i == 0xff:
        # 0xff means the next eight bytes are the number
        return little_endian_to_int(s.read(8))
    else:
        # anything else is just the integer
        return i


def encode_varint(i):
    '''encodes an integer as a varint'''
    if i < 0xfd:
        return bytes([i])
    elif i < 0x10000:
        return b'\xfd' + int_to_little_endian(i, 2)
    elif i < 0x100000000:
        return b'\xfe' + int_to_little_endian(i, 4)
    elif i < 0x10000000000000000:
        return b'\xff' + int_to_little_endian(i, 8)
    else:
        raise RuntimeError('integer too large: {}'.format(i))


def h160_to_p2pkh_address(h160, testnet=False):
    '''Takes a byte sequence hash160 and returns a p2pkh address string'''
    # p2pkh has a prefix of b'\x00' for mainnet, b'\x6f' for testnet
    if testnet:
        prefix = b'\x6f'
    else:
        prefix = b'\x00'
    # return the encode_base58_checksum the prefix and h160
    return encode_base58_checksum(prefix + h160)


def h160_to_p2sh_address(h160, testnet=False):
    '''Takes a byte sequence hash160 and returns a p2sh address string'''
    # p2sh has a prefix of b'\x05' for mainnet, b'\xc4' for testnet
    if testnet:
        prefix = b'\xc4'
    else:
        prefix = b'\x05'
    # return the encode_base58_checksum the prefix and h160
    return encode_base58_checksum(prefix + h160)


def merkle_parent(hash1, hash2):
    '''Takes the binary hashes and calculates the hash256'''
    # return the hash256 of hash1 + hash2
    raise NotImplementedError


def merkle_parent_level(hashes):
    '''Takes a list of binary hashes and returns a list that's half
    the length'''
    # if the list has exactly 1 element raise an error
    # if the list has an odd number of elements, duplicate the last one
    #       and put it at the end so it has an even number of elements
    # initialize next level
    # loop over every pair (use: for i in range(0, len(hashes), 2))
        # get the merkle parent of i and i+1 hashes
        # append parent to parent level
    # return parent level
    raise NotImplementedError


def merkle_root(hashes):
    '''Takes a list of binary hashes and returns the merkle root
    '''
    # current level starts as hashes
    # loop until there's exactly 1 element
        # current level becomes the merkle parent level
    # return the 1st item of current_level
    raise NotImplementedError


class HelperTest(TestCase):

    def test_bytes(self):
        b = b'hello world'
        s = 'hello world'
        self.assertEqual(b, str_to_bytes(s))
        self.assertEqual(s, bytes_to_str(b))

    def test_little_endian_to_int(self):
        h = bytes.fromhex('99c3980000000000')
        want = 10011545
        self.assertEqual(little_endian_to_int(h), want)
        h = bytes.fromhex('a135ef0100000000')
        want = 32454049
        self.assertEqual(little_endian_to_int(h), want)

    def test_int_to_little_endian(self):
        n = 1
        want = b'\x01\x00\x00\x00'
        self.assertEqual(int_to_little_endian(n, 4), want)
        n = 10011545
        want = b'\x99\xc3\x98\x00\x00\x00\x00\x00'
        self.assertEqual(int_to_little_endian(n, 8), want)

    def test_base58(self):
        addr = 'mnrVtF8DWjMu839VW3rBfgYaAfKk8983Xf'
        h160 = decode_base58(addr).hex()
        want = '507b27411ccf7f16f10297de6cef3f291623eddf'
        self.assertEqual(h160, want)
        got = encode_base58_checksum(b'\x6f' + bytes.fromhex(h160))
        self.assertEqual(got, addr)

    def test_encode_base58_checksum(self):
        raw = bytes.fromhex('005dedfbf9ea599dd4e3ca6a80b333c472fd0b3f69')
        want = '19ZewH8Kk1PDbSNdJ97FP4EiCjTRaZMZQA'
        self.assertEqual(encode_base58_checksum(raw), want)

    def test_p2pkh_address(self):
        h160 = bytes.fromhex('74d691da1574e6b3c192ecfb52cc8984ee7b6c56')
        want = '1BenRpVUFK65JFWcQSuHnJKzc4M8ZP8Eqa'
        self.assertEqual(h160_to_p2pkh_address(h160, testnet=False), want)
        want = 'mrAjisaT4LXL5MzE81sfcDYKU3wqWSvf9q'
        self.assertEqual(h160_to_p2pkh_address(h160, testnet=True), want)

    def test_p2sh_address(self):
        h160 = bytes.fromhex('74d691da1574e6b3c192ecfb52cc8984ee7b6c56')
        want = '3CLoMMyuoDQTPRD3XYZtCvgvkadrAdvdXh'
        self.assertEqual(h160_to_p2sh_address(h160, testnet=False), want)
        want = '2N3u1R6uwQfuobCqbCgBkpsgBxvr1tZpe7B'
        self.assertEqual(h160_to_p2sh_address(h160, testnet=True), want)

    def test_merkle_parent(self):
        tx_hash0 = bytes.fromhex('c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5')
        tx_hash1 = bytes.fromhex('c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5')
        want = bytes.fromhex('8b30c5ba100f6f2e5ad1e2a742e5020491240f8eb514fe97c713c31718ad7ecd')
        self.assertEqual(merkle_parent(tx_hash0, tx_hash1), want)

    def test_merkle_parent_level(self):
        hex_hashes = [
            'c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5',
            'c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5',
            'f391da6ecfeed1814efae39e7fcb3838ae0b02c02ae7d0a5848a66947c0727b0',
            '3d238a92a94532b946c90e19c49351c763696cff3db400485b813aecb8a13181',
            '10092f2633be5f3ce349bf9ddbde36caa3dd10dfa0ec8106bce23acbff637dae',
            '7d37b3d54fa6a64869084bfd2e831309118b9e833610e6228adacdbd1b4ba161',
            '8118a77e542892fe15ae3fc771a4abfd2f5d5d5997544c3487ac36b5c85170fc',
            'dff6879848c2c9b62fe652720b8df5272093acfaa45a43cdb3696fe2466a3877',
            'b825c0745f46ac58f7d3759e6dc535a1fec7820377f24d4c2c6ad2cc55c0cb59',
            '95513952a04bd8992721e9b7e2937f1c04ba31e0469fbe615a78197f68f52b7c',
            '2e6d722e5e4dbdf2447ddecc9f7dabb8e299bae921c99ad5b0184cd9eb8e5908',
        ]
        tx_hashes = [bytes.fromhex(x) for x in hex_hashes]
        want_hex_hashes = [
            '8b30c5ba100f6f2e5ad1e2a742e5020491240f8eb514fe97c713c31718ad7ecd',
            '7f4e6f9e224e20fda0ae4c44114237f97cd35aca38d83081c9bfd41feb907800',
            'ade48f2bbb57318cc79f3a8678febaa827599c509dce5940602e54c7733332e7',
            '68b3e2ab8182dfd646f13fdf01c335cf32476482d963f5cd94e934e6b3401069',
            '43e7274e77fbe8e5a42a8fb58f7decdb04d521f319f332d88e6b06f8e6c09e27',
            '1796cd3ca4fef00236e07b723d3ed88e1ac433acaaa21da64c4b33c946cf3d10',
        ]
        want_tx_hashes = [bytes.fromhex(x) for x in want_hex_hashes]
        self.assertEqual(merkle_parent_level(tx_hashes), want_tx_hashes)

    def test_merkle_root(self):
        hex_hashes = [
            'c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5',
            'c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5',
            'f391da6ecfeed1814efae39e7fcb3838ae0b02c02ae7d0a5848a66947c0727b0',
            '3d238a92a94532b946c90e19c49351c763696cff3db400485b813aecb8a13181',
            '10092f2633be5f3ce349bf9ddbde36caa3dd10dfa0ec8106bce23acbff637dae',
            '7d37b3d54fa6a64869084bfd2e831309118b9e833610e6228adacdbd1b4ba161',
            '8118a77e542892fe15ae3fc771a4abfd2f5d5d5997544c3487ac36b5c85170fc',
            'dff6879848c2c9b62fe652720b8df5272093acfaa45a43cdb3696fe2466a3877',
            'b825c0745f46ac58f7d3759e6dc535a1fec7820377f24d4c2c6ad2cc55c0cb59',
            '95513952a04bd8992721e9b7e2937f1c04ba31e0469fbe615a78197f68f52b7c',
            '2e6d722e5e4dbdf2447ddecc9f7dabb8e299bae921c99ad5b0184cd9eb8e5908',
            'b13a750047bc0bdceb2473e5fe488c2596d7a7124b4e716fdd29b046ef99bbf0',
        ]
        tx_hashes = [bytes.fromhex(x) for x in hex_hashes]
        want_hex_hash = 'acbcab8bcc1af95d8d563b77d24c3d19b18f1486383d75a5085c4e86c86beed6'
        want_hash = bytes.fromhex(want_hex_hash)
        self.assertEqual(merkle_root(tx_hashes), want_hash)
