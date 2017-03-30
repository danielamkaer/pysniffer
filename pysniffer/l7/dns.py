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
        self.query = str()

"""
Refering to RFC 1035 https://tools.ietf.org/html/rfc1035
"""

class Dns:
    QUERY_ANCOUNT = 0#b'\0\0'
    QUERY_NSCOUNT = 0#b'\0\0'
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
        payload = packet['UDP'].payload

        if packet.dport == Dns.PORT and \
           payload.ancount == Dns.QUERY_ANCOUNT and \
           payload.nscount == Dns.QUERY_NSCOUNT:
            logger.debug(payload.ancount)
            id = payload.id
            logger.info(f'Found DNS query id: {hex(id)}')
            self.conntrack[id] = Connection(id, packet.time)
            self.conntrack[id].query = payload.qd.qname.decode('utf-8')

    async def OnServerSent(self, conn, packet):
        conn.onServerSent -= self.OnServerSent
        payload = packet['UDP'].payload
        id = payload.id
            
        
        if packet.sport == Dns.PORT and \
           id in self.conntrack:
            if payload.rcode != 0:
                logger.info(f'DNS query not found for id {self.conntrack[id].query}')
                del self.conntrack[id]

            elif payload.rcode == 0 and not payload.an == None:
                response = list()
                logger.debug(f'length{len(payload.an)}')

                for i in range(payload.ancount):
                    if payload.an[i].type == 1:
                        response.append(payload.an[i].rdata)
                        logger.debug(f'{payload.an[i].rrname} {payload.an[i].type} {payload.an[i].rdata}')
                logger.info(f'Found DNS response {[i for i in response]} to {self.conntrack[id].query}')
                del self.conntrack[id]