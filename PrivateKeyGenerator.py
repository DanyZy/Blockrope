import random
import secrets
import time
from pynput import mouse


class KeyGen:

    def __init__(self):
        self.POOL_SIZE = 256
        self.KEY_BYTES = 32
        self.CURVE_ORDER = int('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16)
        self.pool = [0] * self.POOL_SIZE
        self.pool_pointer = 0
        self.pool_rng_state = None
        self.__init_pool()

    def seed_input_str(self, str_input):
        time_int = int(time.time())
        self.__seed_int(time_int)
        for char in str_input:
            char_code = ord(char)
            self.__seed_byte(char_code)

    def seed_input_cords(self, fun=lambda x, y: x + y):
        def on_click(x, y, button, pressed):
            if pressed and button == mouse.Button.left:
                print(x, y)
                time_int = int(time.time())
                self.__seed_int(time_int)
                self.__seed_int(fun(x, y))
            elif pressed and button == mouse.Button.right:
                return False

        with mouse.Listener(on_click=on_click) as listener:
            listener.join()

    def generate_key(self):
        big_int = self.__generate_big_int()
        big_int %= self.CURVE_ORDER - 1  # key < curve order
        big_int += 1  # key > 0
        key = hex(big_int)[2:]
        # Add leading zeros if the hex key is smaller than 64 chars
        key = key.zfill(self.KEY_BYTES * 2)
        return key

    def __init_pool(self):
        for i in range(self.POOL_SIZE):
            random_byte = secrets.randbits(8)
            self.__seed_byte(random_byte)
        time_int = int(time.time())
        self.__seed_int(time_int)

    def __seed_int(self, n):
        self.__seed_byte(n)
        self.__seed_byte(n >> 8)
        self.__seed_byte(n >> 16)
        self.__seed_byte(n >> 24)

    def __seed_byte(self, n):
        self.pool[self.pool_pointer] ^= n & 255
        self.pool_pointer += 1
        if self.pool_pointer >= self.POOL_SIZE:
            self.pool_pointer = 0

    def __generate_big_int(self):
        if self.pool_rng_state is None:
            seed = int.from_bytes(self.pool, byteorder='big', signed=False)
            random.seed(seed)
            self.pool_rng_state = random.getstate()
        random.setstate(self.pool_rng_state)
        big_int = random.getrandbits(self.KEY_BYTES * 8)
        self.pool_rng_state = random.getstate()
        return big_int


pkg = KeyGen()
pkg.seed_input_cords()
prk = pkg.generate_key()
print(prk)
