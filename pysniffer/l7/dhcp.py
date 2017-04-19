import pysniffer.l4
import logging
from scapy.layers import dhcp, dhcp6
from scapy.layers.dhcp import DHCPTypes
import enum

logger = logging.getLogger(__name__)
inv_dhcptypes = dict(zip(DHCPTypes.values(), DHCPTypes.keys()))

class DhcpReport(pysniffer.core.Report):
    FIELDS = {
        'options' : 'The options which is shared',
        'host' : 'The hosts IP address',
        'mac' : 'The hosts MAC address',
        'hostname' : 'Devices hostname'
    }

class DhcpState(enum.Enum):
    discover = enum.auto()
    offer = enum.auto()
    request = enum.auto()
    ack = enum.auto()


class Client:
    def __init__ (self, mac, id):
        self.mac = mac
        self.options = dict()
        self.state = DhcpState.discover
        self.ip = str()
        self.id = id
        self.hostname = None

class Dhcp:
    PORT = 67

    def __init__(self):
        self.clients = dict()
    
    def register(self, app):
        self.app = app

    def boot(self):
        self.app[pysniffer.l4.UDP].onConnectionEstablished += self.onConnectionEstablished
    
    def getOptions(self, packet):
        return {x[0]:x[1:] for x in packet.scapy['DHCP options'].options if type(x) == tuple}

    async def onConnectionEstablished(self, conn):
        conn.onClientSent += self.OnClientSent
        conn.onServerSent += self.OnServerSent

    async def handleFrame(self, conn, packet):
        if 'DHCP' in packet.scapy:
            options = self.getOptions(packet)
            xid = packet.scapy['BOOTP'].xid
            if inv_dhcptypes['request'] in options['message-type']:
                if not xid in self.clients:
                    self.clients[xid] = Client(packet.mac_src, xid)
                self.clients[xid].state = DhcpState.request
                self.clients[xid].options['request'] = options
                logger.debug(f'Found request packet: {packet.scapy.summary()}')

            elif inv_dhcptypes['ack'] in options['message-type']:
                if not xid in self.clients:
                    logger.info(f'DHCP ack received without matching id {packet.scapy.summary()}')
                if xid in self.clients:
                    self.clients[xid].state = DhcpState.ack
                    self.clients[xid].options['ack'] = options
                    self.clients[xid].ip = packet.scapy['BOOTP'].yiaddr
                    if 'hostname' in self.clients[xid].options['request']:
                        self.clients[xid].hostname = "".join(map(chr, self.clients[xid].options['request']['hostname'][0]))
                        logger.info(f'Ack for device {self.clients[xid].hostname} {packet.scapy.summary()}')

                    else:
                        logger.info(f'Found ack packet: {packet.scapy.summary()}')

                    await self.generateReports(self.clients[xid])
                    del self.clients[xid]

    async def OnClientSent(self, conn, packet):
        await self.handleFrame(conn, packet)    
    
    async def OnServerSent(self, conn, packet):
        await self.handleFrame(conn, packet)

    async def generateReports(self, client):
        await self.app.report(
            self,
            DhcpReport(
                options = client.options,
                host = client.ip,
                mac = client.mac,
                hostname = client.hostname
            )
        )