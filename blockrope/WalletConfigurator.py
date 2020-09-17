class Config:
    def __init__(self):
        self.NET_BYTES: dict = {
            "TESTNET": b'\x6f',
            "MAINNET": b'\x00',
            "NAMENET": b'\x34'
        }
        self._compressed = False
        self._net_byte = "TESTNET"
        self._save_data = True
        self._wallet_data_path = "C:\\Users\\Daniil\\PyCharmProjects\\Blockchain"
        self._wallet_data_limit = 10
