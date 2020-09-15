class Config:
    def __init__(self):
        self.NET_BYTES: dict = {
            "TESTNET": b'\x6f',
            "MAINNET": b'\x00',
            "NAMENET": b'\x34'
        }
        self._compressed = False
        self._net_byte = "TESTNET"