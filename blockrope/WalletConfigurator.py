import json
import os


class Config:
    def __init__(self):
        self.ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
        self.CONFIG_PATH = os.path.join(self.ROOT_DIR, 'config.json')
        print(self.ROOT_DIR)
        print(self.CONFIG_PATH)
        self.NET_BYTES: dict = {
            "TESTNET": b'\x6f',
            "MAINNET": b'\x00',
            "NAMENET": b'\x34'
        }
        self.__config_file_init()
        self.__set_config_data("wallet_data_path", self.ROOT_DIR)
        self._compressed = self.__get_config_data()["compressed"]
        self._net_byte = self.__get_config_data()["net_byte"]
        self._save_data = self.__get_config_data()["save_data"]
        self._wallet_data_path = self.__get_config_data()["wallet_data_path"]
        self._wallet_data_cache = self.__get_config_data()["wallet_data_cache"]

    def __config_file_init(self):
        to_json = {
            "compressed": False,
            "net_byte": "TESTNET",
            "save_data": True,
            "wallet_data_path": "",
            "wallet_data_cache": 5
        }
        with open(self.CONFIG_PATH, "w") as json_file:
            json.dump(to_json, json_file, indent=5)

    def __get_config_data(self):
        with open(self.CONFIG_PATH) as json_file:
            return json.load(json_file)

    def __set_config_data(self, key, value):
        with open(self.CONFIG_PATH, "w") as json_file:
            data = self.__get_config_data()
            data[key] = value
            json.dump(data, json_file, indent=5)

    @property
    def compressed(self):
        return self._compressed

    @property
    def net_byte(self):
        return self._net_byte

    @property
    def save_data(self):
        return self._save_data

    @property
    def wallet_data_path(self):
        return self._wallet_data_path

    @property
    def wallet_data_cache(self):
        return self._wallet_data_cache

    @compressed.setter
    def compressed(self, value):
        self.__set_config_data("compressed", value)
        self._compressed = value

    @net_byte.setter
    def net_byte(self, value):
        self.__set_config_data("net_byte", value)
        self._net_byte = value

    @save_data.setter
    def save_data(self, value):
        self.__set_config_data("net_byte", value)
        self._save_data = value

    @wallet_data_path.setter
    def wallet_data_path(self, value):
        self.__set_config_data("wallet_data_path", value)
        self._wallet_data_path = value

    @wallet_data_cache.setter
    def wallet_data_cache(self, value):
        self.__set_config_data("wallet_data_cache", value)
        self._wallet_data_cache = value
