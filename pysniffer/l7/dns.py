import pysniffer.l4
import logging
logger = logging.getLogger(__name__)
import re


logging.basicConfig(format='%(asctime)s %(message)s')


class Connection:
    STATE_QUERY_SENT = 'STATE_QUERY_SENT'
    STATE_RESPONSE_RECEIVED = 'STATE_RESPONSE_RECEIVED'
    def __init__(self, id, time):
        self.id = id
        self.time = time
        self.state = Connection.STATE_QUERY_SENT

"""
Refering to RFC 1035 https://tools.ietf.org/html/rfc1035
"""

class Dns:
    QUERY_ANCOUNT = b'\0\0'
    QUERY_NSCOUNT = b'\0\0'
    PORT = 53

    def __init__(self):
        self.conntrack = {}

    def register(self, app):
        self.app = app
    
    def boot(self):
        self.app[pysniffer.l4.UDP].onConnectionEstablished += self.onConnectionEstablished
    
    async def onConnectionEstablished(self, conn):
        conn.onClientSent += self.OnClientSent
        conn.onServerSent += self.OnServerSent

    async def OnClientSent(self, conn, packet):
        conn.onClientSent -= self.OnClientSent
        payload = bytes(packet['UDP'].payload)

        if packet.dport == Dns.PORT and \
           bytes(payload)[7:9] == Dns.QUERY_ANCOUNT and \
           bytes(payload)[9:11] == Dns.QUERY_NSCOUNT:
            id = bytes(payload[0:2])
            logger.info(f'Found DNS query id: {id}')
            self.conntrack[id] = Connection(id, packet.time)

    async def OnServerSent(self, conn, packet):
        conn.onServerSent -= self.OnServerSent
        payload = bytes(packet['UDP'].payload)
        id = payload[0:2]

        if packet.sport == Dns.PORT and \
           id in self.conntrack:
           logger.info(f'Found DNS response to {id}')
           del self.conntrack[id]