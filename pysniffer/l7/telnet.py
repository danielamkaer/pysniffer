import pysniffer.l4
import logging 

logger = logging.getLogger(__name__)

TELNET_COMMAND_SIGNAL = 255 # 0xff - byte that tells the next byte is a command
TELNET_COMMAND = 240 #  0xf0 - 0xf0 to 0xff is a command, if it comes af 0xff 

class TelnetClientReport(pysniffer.core.Report):
    FIELD = {
        'host' : 'Client IP address',
        'port' : 'Server Port',
        'dest' : 'Server IP address',
        'software' : 'Client user agent, id detected'
    }

class TelnetServerReport(pysniffer.core.Report):
    FIELD = {
        'host' : 'Server IP Address',
        'port' : 'Server port',
        'software' : 'Server software version, id detected'
    }

class Telnet:
    def register(self, app):
        self.app = app
        self.sessions = {}

    def boot(self):
        self.app[pysniffer.l4.TCP].onConnectionEstablished += self.onConnectionEstablished
    
    async def onConnectionEstablished(self, conn):
        logger.debug(f'New connection {hex(id(conn))}')
        session = Session(conn, self)
        self.sessions[conn] = session
        conn.onClientSent += session.processClientMessage

    def deleteMe(self, session):
        del self.sessions[session.conn]

    async def generateReports(self, packet):
        self.app.report(
            self,
            TelnetClientReport(
                host = packet.ip_dst,
                dest = packet.ip_src,
                port = packet.port_src,
                software = None
            )
        )
        self.app.report(
            self,
            TelnetServerReport(
                host = packet.ip_src,
                port = packet.port_src,
                software = None
            )
        )

class Session:
    def __init__(self, conn, telnet):
        self.conn = conn
        self.telnet = telnet
        
    def parseTelnetMessage(self, message):
        if message[0] == TELNET_COMMAND_SIGNAL and message[3] == TELNET_COMMAND_SIGNAL and message[6] == TELNET_COMMAND_SIGNAL \
        and message[1] > TELNET_COMMAND and message[4] > TELNET_COMMAND and message[7] > TELNET_COMMAND:
            return True
        else:
            return False

    async def processClientMessage(self, conn, packet):
        if self.parseTelnetMessage(packet.scapy['Raw'].load):
            conn.onClientSent -= self.processClientMessage
            conn.onServerSent += self.processServerMessage
            logger.info(f'Client init telnet packet {packet.scapy.summary()}')
            self.telnet.deleteMe(self)
        else:
            logger.debug(f'Not a telnet connection {packet.scapy.summary()}')
            conn.onClientSent -= self.processClientMessage
            self.telnet.deleteMe(self)

    async def processServerMessage(self, conn, packet):
        if self.parseTelnetMessage(packet.scapy['Raw'].load):
            conn.onServerSent -= self.processServerMessage
            logger.info(f'Server telnet response packet {packet.scapy.summary()}')
        else:
            logger.debug(f'Not a telnet connection')
            conn.onServerSent -= self.processServerMessage
