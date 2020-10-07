# Makes a transaction from the inputs
# outputs is a list of [redemptionSatoshis, outputScript]
import hashlib
import struct
from codecs import decode, encode
import unittest

import ecdsa


def make_raw_transaction(output_transaction_hash, source_index, script_sig, outputs):
    def make_output(data):
        redemption_satoshis, output_script = data
        return (encode(struct.pack("<Q", redemption_satoshis), "hex").decode("utf-8") +
                "%02x" % len(decode(output_script, "hex")) + output_script)

    formatted_outputs = ''.join(map(make_output, outputs))
    return (
            "01000000" +  # 4 bytes version
            "01" +  # varint for number of inputs
            encode(decode(output_transaction_hash, "hex")[::-1], "hex").decode("utf-8") +  # reverse output_transaction_hash
            encode(struct.pack('<L', source_index), "hex").decode("utf-8") +
            "%02x" % len(decode(script_sig, "hex")) + script_sig +
            "ffffffff" +  # sequence
            "%02x" % len(outputs) +  # number of outputs
            formatted_outputs +
            "00000000"  # lock_time
    )


def privateKeyToPublicKey(s):
    sk = ecdsa.SigningKey.from_string(s.decode('hex'), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return ('\04' + sk.verifying_key.to_string()).encode('hex')


# Returns [first, sig, pub, rest]
def parseTxn(txn):
    first = txn[0:41 * 2]
    scriptLen = int(txn[41 * 2:42 * 2], 16)
    script = txn[42 * 2:42 * 2 + 2 * scriptLen]
    sigLen = int(script[0:2], 16)
    sig = script[2:2 + sigLen * 2]
    pubLen = int(script[2 + sigLen * 2:2 + sigLen * 2 + 2], 16)
    pub = script[2 + sigLen * 2 + 2:]

    assert (len(pub) == pubLen * 2)
    rest = txn[42 * 2 + 2 * scriptLen:]
    return [first, sig, pub, rest]


b58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base58encode(n):
    result = ''
    while n > 0:
        result = b58[n%58] + result
        n /= 58
    return result

def base58decode(s):
    result = 0
    for i in range(0, len(s)):
        result = result * 58 + b58.index(s[i])
    return result

def base256encode(n):
    result = ''
    while n > 0:
        result = chr(n % 256) + result
        n /= 256
    return result

def base256decode(s):
    result = 0
    for c in s:
        result = result * 256 + ord(c)
    return result

def countLeadingChars(s, ch):
    count = 0
    for c in s:
        if c == ch:
            count += 1
        else:
            break
    return count

# https://en.bitcoin.it/wiki/Base58Check_encoding
def base58CheckEncode(version, payload):
    s = chr(version) + payload
    checksum = hashlib.sha256(hashlib.sha256(s).digest()).digest()[0:4]
    result = s + checksum
    leadingZeros = countLeadingChars(result, '\0')
    return '1' * leadingZeros + base58encode(base256decode(result))

def base58CheckDecode(s):
    leadingOnes = countLeadingChars(s, '1')
    s = base256encode(base58decode(s))
    result = '\0' * leadingOnes + s[:-4]
    chk = s[-4:]
    checksum = hashlib.sha256(hashlib.sha256(result).digest()).digest()[0:4]
    assert(chk == checksum)
    version = result[0]
    return result[1:]

def pubKeyToAddr(s):
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(s.decode('hex')).digest())
    return base58CheckEncode(0, ripemd160.digest())

# Substitutes the scriptPubKey into the transaction, appends SIGN_ALL to make the version
# of the transaction that can be signed
def getSignableTxn(parsed):
    first, sig, pub, rest = parsed
    inputAddr = base58CheckDecode(pubKeyToAddr(pub))
    return first + "1976a914" + inputAddr.encode('hex') + "88ac" + rest + "01000000"



# Input is a hex-encoded, DER-encoded signature
# Output is a 64-byte hex-encoded signature
def derSigToHexSig(s):
    s, junk = ecdsa.der.remove_sequence(s.decode('hex'))
    if junk != '':
        print('JUNK', junk.encode('hex'))
    assert(junk == '')
    x, s = ecdsa.der.remove_integer(s)
    y, s = ecdsa.der.remove_integer(s)
    return '%064x%064x' % (x, y)
# Verifies that a transaction is properly signed, assuming the generated scriptPubKey matches
# the one in the previous transaction's output
def verifyTxnSignature(txn):
    parsed = parseTxn(txn)
    signableTxn = getSignableTxn(parsed)
    hashToSign = hashlib.sha256(hashlib.sha256(signableTxn.decode('hex')).digest()).digest().hex()
    assert(parsed[1][-2:] == '01') # hashtype
    sig = derSigToHexSig(parsed[1][:-2])
    public_key = parsed[2]
    vk = ecdsa.VerifyingKey.from_string(public_key[2:].decode('hex'), curve=ecdsa.SECP256k1)
    assert(vk.verify_digest(sig.decode('hex'), hashToSign.decode('hex')))


# Returns byte string value, not hex string
def varint(n):
    if n < 0xfd:
        return struct.pack('<B', n)
    elif n < 0xffff:
        return struct.pack('<cH', '\xfd', n)
    elif n < 0xffffffff:
        return struct.pack('<cL', '\xfe', n)
    else:
        return struct.pack('<cQ', '\xff', n)
# Takes and returns byte string value, not hex string
def varstr(s):
    return varint(len(s)) + s


def makeSignedTransaction(privateKey, outputTransactionHash, sourceIndex, scriptPubKey, outputs):
    myTxn_forSig = (make_raw_transaction(outputTransactionHash, sourceIndex, scriptPubKey, outputs)
         + "01000000") # hash code

    s256 = hashlib.sha256(hashlib.sha256(myTxn_forSig.decode('hex')).digest()).digest()
    sk = ecdsa.SigningKey.from_string(privateKey.decode('hex'), curve=ecdsa.SECP256k1)
    sig = sk.sign_digest(s256, sigencode=ecdsa.util.sigencode_der) + '\01' # 01 is hashtype
    pubKey = privateKeyToPublicKey(privateKey)
    scriptSig = varstr(sig).encode('hex') + varstr(pubKey.decode('hex')).encode('hex')
    signed_txn = make_raw_transaction(outputTransactionHash, sourceIndex, scriptSig, outputs)
    verifyTxnSignature(signed_txn)
    return signed_txn


class TestTxnUtils(unittest.TestCase):

    def test_make_raw_transaction(self):
        txn = make_raw_transaction(
            "f2b3eb2deb76566e7324307cd47c35eeb88413f971d88519859b1834307ecfec",  # output transaction hash
            1,  # sourceIndex
            "76a914010966776006953d5567439e5e39f86a0d273bee88ac",  # scriptSig
            [[99900000,  # satoshis
              "76a914097072524438d003d23a2f23edb65aae1bb3e46988ac"]],  # outputScript
        ) + "01000000"  # hash code type
        self.assertEqual(txn,
                         "0100000001eccf7e3034189b851985d871f91384b8ee357cd47c3024736e5676eb2debb3f2" +
                         "010000001976a914010966776006953d5567439e5e39f86a0d273bee88acffffffff" +
                         "01605af405000000001976a914097072524438d003d23a2f23edb65aae1bb3e46988ac" +
                         "0000000001000000")


if __name__ == '__main__':
    unittest.main()
