import pysniffer.core
import pysniffer.l3
import logging

from scapy.layers.inet import IP_PROTOS

logger = logging.getLogger(__name__)

class ConnectionClosed(Exception):
    pass

class InvalidConnection(Exception):
    pass

class Connection:
    STATE_STARTED = 'STATE_STARTED'
    STATUS_ESTABLISHED = 'STATUS_ESTABLISHED'

    def __init__(self, src, dst, sport, dport):
        self.src = src
        self.dst = dst
        self.sport = sport
        self.dport = dport
        self.state = Connection.STATE_STARTED

        self.onClientSent = pysniffer.core.Event()
        self.onServerSent = pysniffer.core.Event()

    def pair(self):
        return (self.src, self.dst, self.sport, self.dport)

    @staticmethod
    def FromPacket(packet):
        if not 'UDP' in packet:
            return None
        
        return Connection(*UDP.UdpPair(packet))

    def HandleFrame(self, packet):
        pass

class UDP:
    def __init__(self):
        self.conntrack = {}
        self.onConnectionEstablished = pysniffer.core.Event()

    @staticmethod
    def UdpPair(packet):
        if 'IP' in packet:
            return (packet['IP'].src, packet['IP'].dst, packet['UDP'].sport, packet['UDP'].dport)        
        elif 'IPv6' in packet:
            return (packet['IPv6'].src, packet['IPv6'].dst, packet['UDP'].sport, packet['UDP'].dport)        
        
        return (None,None,None,None)

    @staticmethod
    def ReversePair(pair):
        return (pair[1],pair[0],pair[3],pair[2])

    @staticmethod
    def UdpPairReversed(packet):
        return UDP.ReversePair(UDP.UdpPair(packet))

    def register(self, app):
        self.app = app

    def boot(self):
        self.app[pysniffer.l3.IPv4].onFrameReceived += self.OnFrameReceived, lambda pkt:pkt['IP'].proto == IP_PROTOS.udp
        self.app[pysniffer.l3.IPv6].onFrameReceived += self.OnFrameReceived, lambda pkt:pkt['IPv6'].nh == IP_PROTOS.udp

    async def OnFrameReceived(self, packet):
        logger.debug(f'{self} received packet: {packet.summary()}')
        pair = UDP.UdpPair(packet)
        revpair = UDP.UdpPairReversed(packet)

        if pair in self.conntrack or revpair in self.conntrack:
            if pair not in self.conntrack:
                pair = revpair

        else:
            conn = Connection.FromPacket(packet)
            if conn:
                self.conntrack[pair] = conn
                logger.info(f'New connection established: {packet.summary()}')
                await self.onConnectionEstablished(self.conntrack[pair])