import pysniffer.l4
import logging
logger = logging.getLogger(__name__)
import re
from scapy.layers.dns import dnsqtypes
inv_dnsqtypes = dict(zip(dnsqtypes.values(), dnsqtypes.keys()))

class DnsQueryReport(pysniffer.core.Report):
    FIELDS = {
        'host' : 'The host which made the lookup',
        'query': 'The query which it looked up',
        'response': 'A list with the response'
    }

class Query:
    def __init__(self, id, time):
        self.id = id
        self.time = time
        self.query = str()
        self.response = []

"""
Refering to RFC 1035 https://tools.ietf.org/html/rfc1035
"""
class Dns:
    QUERY_ANCOUNT = 0
    QUERY_NSCOUNT = 0
    PORT = 53

    def __init__(self):
        self.queries = {}

    def register(self, app):
        self.app = app
    
    def boot(self):
        self.app[pysniffer.l4.UDP].onConnectionEstablished += self.onConnectionEstablished
    
    async def onConnectionEstablished(self, conn):
        conn.onClientSent += self.OnClientSent
        conn.onServerSent += self.OnServerSent

    async def OnClientSent(self, conn, packet):
        conn.onClientSent -= self.OnClientSent
        if 'DNS' in packet.scapy:
            payload = packet.scapy['DNS']
        else:
            return

        if packet.port_dst== Dns.PORT and \
           payload.ancount == Dns.QUERY_ANCOUNT and \
           payload.nscount == Dns.QUERY_NSCOUNT:
            id = payload.id
            logger.info(f'Found DNS query id: {hex(id)}')
            self.queries[id] = Query(id, packet.scapy.time)
            self.queries[id].query = payload.qd.qname.decode('utf-8')

    async def OnServerSent(self, conn, packet):
        conn.onServerSent -= self.OnServerSent
        if 'DNS' in packet.scapy:
            payload = packet.scapy['DNS']
        else:
            return
        id = payload.id
        
        if packet.port_src == Dns.PORT and id in self.queries:
            if payload.rcode != 0:
                logger.info(f'DNS query not found for id {self.queries[id].query}')
                del self.queries[id]

            elif payload.rcode == 0 and not payload.an == None:
                response = list()
                response = self.queries[id].response

                for i in range(payload.ancount):
                    if payload.an[i].type == inv_dnsqtypes['A']:
                        response.append(payload.an[i].rdata)
                        logger.debug(f'{payload.an[i].rrname} {payload.an[i].type} {payload.an[i].rdata}')
                    elif payload.an[i].type == inv_dnsqtypes['AAAA']:
                        response.append(payload.an[i].rdata)
                        logger.debug(f'{payload.an[i].rrname} {payload.an[i].type} {payload.an[i].rdata}')
                await self.generateReports(packet, id)
                logger.info(f'Found DNS response {[i for i in response]} to {self.queries[id].query}')
                del self.queries[id]
    
    async def generateReports(self, packet, id):
        await self.app.report(
            self,
            DnsQueryReport(
                host = packet.ip_src,
                query = self.queries[id].query,
                response=self.queries[id].response
            )
        )
