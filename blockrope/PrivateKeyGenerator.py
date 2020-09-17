import random
import secrets
import time
from binascii import unhexlify
from pynput import mouse


class KeyGenerator:
    """
    Class for generating a cryptographically secure private key for bitcoin wallet
    with user-entered entropy using keyword or cursor clicks coordinates.

    Usage:
    - create an instance of KeyGenerator class
    - call seed_input_cords or seed_input_str method
    - call generate_key method
    """

    def __init__(self):
        self.POOL_SIZE = 256
        self.KEY_BYTES = 32
        # because of ECDSA bitcoin key should be positive and less than the order of curve secp256k1
        self.CURVE_ORDER = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
        self._pool = [0] * self.POOL_SIZE
        self._pool_pointer = 0
        self._pool_rng_state = None
        self._key = b"not generated"
        self.__init_pool()

    def __str__(self):
        return "Private Key: {}".format(self._key)

    @property
    def private_key(self):
        return self._key

    def seed_input_str(self, str_input):
        """
        Method for converting a string to a sequence of bytes.
        :param str_input: any string
        """
        time_int = int(time.time())
        self.__seed_int(time_int)  # additional entropy by system time of method call
        for char in str_input:
            char_code = ord(char)
            self.__seed_byte(char_code)

    def seed_input_cords(self, fun=lambda x, y: x + y):
        """
        The method calls the listener to obtain entropy by
        collecting the coordinates of the cursor positions
        when the left mouse button is pressed; to terminate
        the listener, press the right mouse button.
        :param fun: any function that takes two integers
        as input and returns one
        """
        def on_click(x, y, button, pressed):
            if pressed and button == mouse.Button.left:
                print(x, y)
                time_int = int(time.time())
                self.__seed_int(time_int)  # additional entropy by system time of click
                self.__seed_int(fun(x, y))
            elif pressed and button == mouse.Button.right:
                return False

        with mouse.Listener(on_click=on_click) as listener:
            listener.join()

    def generate_key(self):
        """
        A method that generates a private key based
        on a number obtained from a set of obtained entropy.
        :return: bytes
        """
        big_int = self.__generate_big_int()
        big_int %= self.CURVE_ORDER - 1  # for case when key < curve order
        big_int += 1  # for case when key > 0
        key = hex(big_int)[2:]  # remove 0x
        # Add leading zeros if hex key is smaller than 64 chars
        key = key.zfill(self.KEY_BYTES * 2)
        self._key = unhexlify(key)

    def __init_pool(self):
        """
        Method for initializing the pool of entropy, filling the pool
        with secure random bytes.
        """
        for i in range(self.POOL_SIZE):
            random_byte = secrets.randbits(8)
            self.__seed_byte(random_byte)
        time_int = int(time.time())
        self.__seed_int(time_int)  # additional entropy by system time of method call

    def __seed_int(self, n):
        """
        Helper method to seed additional entropy to int's.
        :param n: any integer
        """
        self.__seed_byte(n)
        self.__seed_byte(n >> 8)
        self.__seed_byte(n >> 16)
        self.__seed_byte(n >> 24)

    def __seed_byte(self, n):
        """
        Method to seeding bytes into pool with entropy.
        :param n: any integer
        """
        self._pool[self._pool_pointer] ^= n & 255
        self._pool_pointer += 1
        if self._pool_pointer >= self.POOL_SIZE:
            self._pool_pointer = 0

    def __generate_big_int(self):
        """
        A method that converts all accumulated entropy in
        the form of a byte array to a numeric type.
        :return: integer
        """
        if self._pool_rng_state is None:
            seed = int.from_bytes(self._pool, byteorder="big", signed=False)
            random.seed(seed)
            self._pool_rng_state = random.getstate()
        random.setstate(self._pool_rng_state)
        big_int = random.getrandbits(self.KEY_BYTES * 8)
        self._pool_rng_state = random.getstate()
        return big_int
