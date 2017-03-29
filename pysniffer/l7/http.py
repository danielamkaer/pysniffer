import pysniffer.l4
import logging
logger = logging.getLogger(__name__)
import re

class Http:

    REGEX_cli = re.compile(b'^(GET|POST|DELETE|PUT|PATCH|HEAD) (.+) HTTP/(\d\.\d)')
    REGEX_srv = re.compile(b'^HTTP\/(\d\.\d) (\d{3}) (.+?)')

    def register(self, app):
        self.app = app

    def boot(self):
        self.app[pysniffer.l4.TCP].onConnectionEstablished += self.OnConnectionEstablished

    def OnConnectionEstablished(self, conn):
        conn.onClientSent += self.OnClientSent

    def OnClientSent(self, conn, packet):
        conn.onClientSent -= self.OnClientSent
        payload = bytes(packet['Raw'].load)

        if Http.REGEX_cli.match(payload):
            logger.info("Found HTTP client")
            conn.onServerSent += self.OnServerSent

    def OnServerSent(self, conn, packet):
        conn.onServerSent -= self.OnServerSent
        payload = bytes(packet['Raw'].load)

        if Http.REGEX_srv.match(payload):
            logger.info("Found HTTP server")

