import pysniffer.l4
import logging
logger = logging.getLogger(__name__)
import re


logging.basicConfig(format='%(asctime)s %(message)s')
"""
Refering to RFC 1035 https://tools.ietf.org/html/rfc1035
"""
class Dns:
    #REGEX_cli = re.compile(b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00')
    REGEX = b'\x01\x00\x00\x01\x00\x00\x00\x00\x00'
    QUERY_ANCOUNT = b'\0\0'
    QUERY_NSCOUNT = b'\0\0'
    PORT = 53
    #REGEX_src = 
    def register(self, app):
        self.app = app
    
    def boot(self):
        self.app[pysniffer.l4.UDP].onConnectionEstablished += self.onConnectionEstablished
    
    async def onConnectionEstablished(self, conn):
        conn.onClientSent += self.OnClientSent

    async def OnClientSent(self, conn, packet):
        conn.onClientSent -= self.OnClientSent
        payload = bytes(packet['UDP'].payload)
        if packet.dport == Dns.PORT and \
           bytes(payload)[7:9] == Dns.QUERY_ANCOUNT and \
           bytes(payload)[9:11] == Dns.QUERY_NSCOUNT:
            logger.info('Found DNS query')

    async def OnServerSent(self, conn, packet):
        conn.onServerSent -= self.OnServerSent
        payload = bytes(packet['UDP'].payload)