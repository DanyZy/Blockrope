import hashlib
import ecdsa
import json
from binascii import hexlify
from base58 import b58encode
from blockrope.PrivateKeyGenerator import KeyGenerator
from blockrope.WalletConfigurator import Config


class Wallet(Config):
    def __init__(self, private_key: bytes = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1).to_string()):
        Config.__init__(self)
        self.__compressed: bool = self._compressed
        self.__net_byte: str = self._net_byte
        self.__private_key: bytes = private_key
        self.__public_key: bytes = self.__generate_public_key()
        self.__bitcoin_address: bytes = self.__generate_bitcoin_address()
        self.__to_json()

    def __str__(self):
        return "Private Key: {0}\nPublic Key: {1}\nBitcoin Address: {2}\n" \
            .format(hexlify(self.__private_key), hexlify(self.__public_key), self.__bitcoin_address)

    def __to_json(self):
        to_json = {
            "Compressed format": self.__compressed,
            "Network": self.__net_byte,
            "Private Key": hexlify(self.__private_key).decode("utf-8"),
            "Public Key": hexlify(self.__public_key).decode("utf-8"),
            "Bitcoin Address": self.__bitcoin_address.decode("utf-8")
        }
        with open("package.json", "w") as f:
            json.dump(to_json, f, indent=5)

    @property
    def get_private_key(self):
        return self.__private_key

    @property
    def get_public_key(self):
        return self.__public_key

    @property
    def get_bitcoin_address(self):
        return self.__bitcoin_address

    def __generate_public_key(self):
        key = ecdsa.SigningKey.from_string(self.__private_key, curve=ecdsa.SECP256k1).get_verifying_key().to_string()
        half_key = key[:len(key)//2]
        key_string = hexlify(key).decode("utf-8")
        last_byte = int(key_string[-1], 16)
        if self.__compressed:
            return b'\x02' + half_key if last_byte % 2 == 0 else b'\x03' + half_key
        return b'\x04' + key

    def __generate_bitcoin_address(self):
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(hashlib.sha256(self.__public_key).digest())
        r = self.NET_BYTES.get(self.__net_byte) + ripemd160.digest()
        checksum = hashlib.sha256(hashlib.sha256(r).digest()).digest()[0:4]
        return b58encode(r + checksum)


if __name__ == '__main__':
    kg = KeyGenerator()
    kg.seed_input_cords()
    kg.generate_key()
    wallet = Wallet(private_key=kg.get_private_key)
    print(wallet)
