import ecdsa
import hashlib
import codecs
import base58
from blockrope.PrivateKeyGenerator import KeyGenerator


class BitcoinWallet:
    """
    A class that generates the necessary data for a bitcoin wallet.
    For generation, it is enough to create an instance of the object.

    Usage:
    - create an instance of BitcoinWallet class with private key as argument
    - call a getter method like attribute:
      get_public_key, get_short_public_key or get_address
    """

    def __init__(self, private_key):
        self.TESTNET = True
        self.COMPRESSED = False
        self.private_key = private_key
        self.public_key = "not generated"
        self.short_public_key = "not generated"
        self.address = "not generated"
        self.__init_wallet()

    @property
    def get_public_key(self):
        return self.public_key

    @property
    def get_short_public_key(self):
        return self.short_public_key

    @property
    def get_address(self):
        return self.address

    def __str__(self):
        return "Public Key: {0}\nCompressed Public Key: {1}\nAddress: {2}\n"\
            .format(self.public_key, self.short_public_key, self.private_key)

    def __init_wallet(self):
        """
        Helper method which call all necessary
        methods on initialisation of instance.
        """
        self.__generate_key()
        self.__generate_compressed_key()
        self.__generate_address()

    def __generate_key(self):
        """
        Method for generating public key from private key.
        Sets byte string in instance.
        """
        private_key_hex = codecs.decode(self.private_key, "hex")
        # get ECDSA public key
        key = ecdsa.SigningKey.from_string(private_key_hex, curve=ecdsa.SECP256k1).verifying_key
        key_hex = codecs.encode(key.to_string(), "hex")
        # add bitcoin byte
        public_key = b'04' + key_hex
        self.public_key = public_key

    def __generate_compressed_key(self):
        """
        Method for generating compressed public key
        (half of regular public key) from private key.
        Sets byte string in instance.
        """
        private_key_hex = codecs.decode(self.private_key, "hex")
        # get ECDSA public key
        key = ecdsa.SigningKey.from_string(private_key_hex, curve=ecdsa.SECP256k1).verifying_key
        key_hex = codecs.encode(key.to_string(), "hex")
        # get X from the key (first half)
        half_len = len(key_hex) // 2
        key_half = key_hex[:half_len]
        # add bitcoin byte: 0x02 if the last digit is even, 0x03 if the last digit is odd
        key_string = key_hex.decode("utf-8")
        last_byte = int(key_string[-1], 16)
        short_public_key = b'02' + key_half if last_byte % 2 == 0 else b'03' + key_half
        self.short_public_key = short_public_key

    def __generate_address(self):
        """
        Method for generating bitcoin address which work with next algorithm:
        Encrypting public key -> RIPEMD-160(SHA-256(public key))
        Setting network byte -> 0x00 or 0x6f + encrypted public key
        Adding checksum -> *net encrypted public key + first 4 bytes of SHA-256(SHA-256(*net encrypted public key))
        Encoding with Base58 previous result
        """
        public_key_hex = codecs.decode(self.public_key if not self.COMPRESSED else self.short_public_key, "hex")
        # run SHA256 for the public key
        sha256 = hashlib.sha256(public_key_hex)
        sha256_digest_key = sha256.digest()
        # run ripemd160 for the SHA256
        ripemd160 = hashlib.new("ripemd160")
        ripemd160.update(sha256_digest_key)
        ripemd160_digest_key = ripemd160.digest()
        encrypted_public_key = codecs.encode(ripemd160_digest_key, "hex")
        # add network byte
        network_bitcoin_public_key = b'00' if not self.TESTNET else b'6f' + encrypted_public_key
        network_bitcoin_public_key_hex = codecs.decode(network_bitcoin_public_key, "hex")
        # double SHA256 to get checksum
        sha256_1 = hashlib.sha256(network_bitcoin_public_key_hex)
        sha256_1_digest = sha256_1.digest()
        sha256_2 = hashlib.sha256(sha256_1_digest)
        sha256_2_digest = sha256_2.digest()
        c = codecs.encode(sha256_2_digest, "hex")
        # first 4 bytes of c
        checksum = c[:8]
        # concatenate public key and checksum to get the address
        address_hex = (network_bitcoin_public_key + checksum).decode("utf-8")
        address = base58.b58encode(address_hex)
        self.address = address


if __name__ == "__main__":
    prikg = KeyGenerator()
    prikg.seed_input_str("sdfg")
    prikg.generate_key()
    prik = prikg.get_private_key
    pubkg = BitcoinWallet(prik)
    print(prikg)
    print(pubkg)

