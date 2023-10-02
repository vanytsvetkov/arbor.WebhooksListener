from models import Creds
from netmiko import ConnectHandler


class Connection:
    def __init__(self, device_params=None):
        if device_params is None:
            device_params = {}
        self.device_params = device_params
        self.connection = None

    def connect(self) -> None:
        print("entering")
        self.connection = ConnectHandler(**self.device_params)
        self.connection.enable()

    def execute(self, cmd: str) -> str:
        print(f'execute "{cmd}"')
        return self.connection.send_command(cmd)

    def disconnect(self):
        if self.connection:
            print("disconnecting")
            if "Exit anyway?" in self.connection.send_command_timing('exit'):
                self.connection.send_command_timing('y')

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()


class ArborCLI:
    def __init__(self, arborType: str, creds: Creds, **kwargs):
        super().__init__()

        self.cli = None

        self.arborType = arborType
        self.creds = creds

        self.device_params = {
            'device_type': 'linux',
            'ip': self.creds.arbors[self.arborType].url,
            'username': self.creds.arbors[self.arborType].username,
            'password': self.creds.arbors[self.arborType].password,
            "read_timeout_override": 600
            }

    def connection(self) -> Connection:
        self.cli = Connection(self.device_params)
        return self.cli

    def get_routes(self) -> str:
        return self.cli.execute("ip route show commands")

    def get_config(self) -> str:
        return self.cli.execute("config show")
