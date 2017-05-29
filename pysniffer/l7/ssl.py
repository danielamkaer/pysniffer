import pysniffer.l4
import logging
import asyncio

logger = logging.getLogger(__name__)

CLIENT_HELLO = 'CLIENT_HELLO'
SERVER_HELLO = 'SERVER_HELLO'

class SslClientReport(pysniffer.core.Report):
    FIELDS = {
        'host' : 'The host which made the lookup',
        'port' : 'Server port',
        'dest' : 'Server IP address',
        'software' : 'Client user agent, id  detected'
    }

class SslServerReport(pysniffer.core.Report):
    FIELDS = {
        'host' : 'Server IP address',
        'port' : 'Server port',
        'software' : 'Server Software version, id  detected'
    }

class Ssl:
    def register(self, app):
        self.app = app
        self.sessions = {}

    def boot(self):
        self.app[pysniffer.l4.TCP].onConnectionEstablished += self.OnConnectionEstablished
    
    async def OnConnectionEstablished(self, conn):
        logger.debug(f'New connection {hex(id(conn))}')
        session = Session(conn, self)
        self.sessions[conn] = session
        conn.onClientSent += session.processClientMessage

    def deleteMe(self, session):
        del self.sessions[session.conn]
    
    async def generateReport(self, packet):
        await self.app.report(self, SslClientReport(host = packet.ip_dst, dest = packet.ip_src, port = packet.port_src, software = None))
        await self.app.report(self, SslServerReport(host = packet.ip_src, port = packet.port_src, software = None))
    
class Session:
    def __init__(self, conn, ssl):
        self.conn = conn
        self.ssl = ssl
        self.state = CLIENT_HELLO

    def parseSslMessage(self, message):
        if message[0] != 0x16:
            logger.debug(f'Not a ssl connection {hex(message[0])}')
            return False
        elif message[0] == 0x16:
            logger.debug(f'ssl connection {hex(message[0])}')
            return True
    
    async def processClientMessage(self, conn, packet):
        logger.debug(f'(client) packet id: {hex(id(packet))}')
        if not self.parseSslMessage(packet.scapy['Raw'].load):
            self.ssl.deleteMe(self)
            conn.onClientSent -= self.processClientMessage
        elif self.state == CLIENT_HELLO and self.parseSslMessage(packet.scapy['Raw'].load):
            logger.info(f'Found \'Client hello\' in ssl connection {packet.scapy.summary()}')
            conn.onClientSent -= self.processClientMessage
            conn.onServerSent += self.processServerMessage
        else:
            logger.error(f'Unexpected packet: {packet.scapy.summary()}')
            self.ssl.deleteMe(self)
            
    async def processServerMessage(self, conn, packet):
        logger.debug(f'(server) packet id: {hex(id(packet))}')
        if not self.parseSslMessage(packet.scapy['Raw'].load):
            self.ssl.deleteMe(self)
            conn.onServerSent -= self.processServerMessage
        elif self.state == CLIENT_HELLO and self.parseSslMessage(packet.scapy['Raw'].load):
            logger.info(f'Found matching Server hello in ssl connection {packet.scapy.summary()}')
            await self.ssl.generateReport(packet)
            conn.onServerSent -= self.processServerMessage
            self.state == SERVER_HELLO
            self.ssl.deleteMe(self)
        else:
            logger.error(f'unexpected packet: {packet.scapy.summary()}')
            self.ssl.deleteMe(self)
