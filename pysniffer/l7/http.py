import pysniffer.l4

class Http:

    def register(self, app):
        self.app = app

    def boot(self):
        self.app[pysniffer.l4.TCP].onConnectionEstablished += lambda x:print(f'Http received connection: {x}')