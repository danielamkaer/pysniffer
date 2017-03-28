import pysniffer.l4
import logging
logger = logging.getLogger(__name__)
import re

class Ssh:

    REGEX = re.compile('^SSH-(.+?)$')

    def register(self, app):
        self.app = app

    def boot(self):
        self.app[pysniffer.l4.TCP].onConnectionEstablished += self.OnConnectionEstablished

    def OnConnectionEstablished(self, conn):
        conn.onClientSent += self.OnClientSent

    def OnClientSent(self, conn, packet):
        conn.onClientSent -= self.OnClientSent
        payload = bytes(packet['Raw'].load)

        m = Ssh.REGEX.match(payload.decode())
        if m:
            logger.info(f"Found SSH client : {m.group(1)}")
            conn.onServerSent += self.OnServerSent

    def OnServerSent(self, conn, packet):
        conn.onServerSent -= self.OnServerSent
        payload = bytes(packet['Raw'].load)

        m = Ssh.REGEX.match(payload.decode())
        if m:
            logger.info(f"Found SSH server : {m.group(1)}")


