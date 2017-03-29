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
    STATE_SYN_RECEIVED = 'STATE_SYN_RECEIVED'
    STATE_SYNACK_RECEIVED = 'STATE_SYNACK_RECEIVED'
    STATE_ACK_RECEIVED = 'STATE_ACK_RECEIVED' 
    STATUS_ESTABLISHED = 'STATUS_ESTABLISHED'

    def __init__(self, src, dst, sport, dport, seq):
        self.src = src
        self.dst = dst
        self.sport = sport
        self.dport = dport
        self.startsseq = seq
        self.sseq = seq + 1
        self.sack = 0
        self.startdseq = 0
        self.dseq = 0
        self.dack = 0
        self.state = Connection.STATE_SYN_RECEIVED

        self.onClientSent = pysniffer.core.Event()
        self.onServerSent = pysniffer.core.Event()

    def pair(self):
        return (self.src, self.dst, self.sport, self.dport)

    @staticmethod
    def FromPacket(packet):
        if not 'TCP' in packet:
            return None
        
        if packet['TCP'].flags != TCP.SYN:
            return None

        conn = Connection(*TCP.TcpPair(packet), packet['TCP'].seq)
        return conn

    async def HandleFrame(self, packet):
        if self.state == Connection.STATE_SYN_RECEIVED:
            if packet['TCP'].flags == TCP.SYN|TCP.ACK:
                if packet['TCP'].ack == self.sseq:
                    self.state = Connection.STATE_SYNACK_RECEIVED
                    self.dseq = packet['TCP'].seq + 1
                    self.startdseq = packet['TCP'].seq
                    self.dack = packet['TCP'].ack
                else:
                    logger.warning("3wh: SYN+ACK received with wrong sequence number.")
                    raise InvalidConnection()
            else:
                logger.warning("3wh: Connection is in SYN received state, but non SYN+ACK received.")
                raise InvalidConnection()

        elif self.state == Connection.STATE_SYNACK_RECEIVED:
            if packet['TCP'].flags == TCP.ACK:
                if packet['TCP'].ack == self.dseq:
                    self.state = Connection.STATE_ACK_RECEIVED
                    self.sack = packet['TCP'].ack
                    logger.info(f"3wh: Connection established between {self.src}:{self.sport} -> {self.dst}:{self.dport}")
                    return Connection.STATUS_ESTABLISHED
                else:
                    logger.warning("3wh: ACK received with wrong sequence number.")
                    raise InvalidConnection()
            else:
                logger.warning("3wh: Connection is in SYN+ACK received state, but non ACK received.")
                raise InvalidConnection()
        elif self.state == Connection.STATE_ACK_RECEIVED:
            if packet['TCP'].flags & TCP.FIN:
                logger.info(f"3wh: Connection closed between {self.src}:{self.sport} -> {self.dst}:{self.dport}")
                raise ConnectionClosed()
            elif packet['TCP'].flags & TCP.ACK:
                if TCP.TcpPair(packet) == self.pair():
                    self.sack = packet['TCP'].ack
                    if 'Raw' in packet:
                        self.sseq += len(packet['Raw'].load)
                        await self.onClientSent(self, packet)
                else:
                    self.dack = packet['TCP'].ack
                    if 'Raw' in packet:
                        self.dseq += len(packet['Raw'].load)
                        await self.onServerSent(self, packet)

                
class TCP:
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80

    def __init__(self):
        self.conntrack = {}
        self.onConnectionEstablished = pysniffer.core.Event()

    @staticmethod
    def TcpPair(packet):
        if 'IP' in packet:
            return (packet['IP'].src, packet['IP'].dst, packet['TCP'].sport, packet['TCP'].dport)        
        elif 'IPv6' in packet:
            return (packet['IPv6'].src, packet['IPv6'].dst, packet['TCP'].sport, packet['TCP'].dport)        
        
        return (None,None,None,None)

    @staticmethod
    def ReversePair(pair):
        return (pair[1],pair[0],pair[3],pair[2])

    @staticmethod
    def TcpPairReversed(packet):
        return TCP.ReversePair(TCP.TcpPair(packet))

    def register(self, app):
        self.app = app

    def boot(self):
        self.app[pysniffer.l3.IPv4].onFrameReceived += self.OnFrameReceived, lambda pkt:pkt['IP'].proto == IP_PROTOS.tcp
        self.app[pysniffer.l3.IPv6].onFrameReceived += self.OnFrameReceived, lambda pkt:pkt['IPv6'].nh == IP_PROTOS.tcp

    async def OnFrameReceived(self, packet):
        logger.debug(f'{self} received packet: {packet.summary()}')
        pair = TCP.TcpPair(packet)
        revpair = TCP.TcpPairReversed(packet)

        if pair in self.conntrack or revpair in self.conntrack:
            if pair not in self.conntrack:
                pair = revpair
                
            status = None
            try:
                status = await self.conntrack[pair].HandleFrame(packet)
            except InvalidConnection:
                del self.conntrack[pair]
            except ConnectionClosed:
                del self.conntrack[pair]

            if status == Connection.STATUS_ESTABLISHED:
                await self.onConnectionEstablished(self.conntrack[pair])

        else:
            conn = Connection.FromPacket(packet)
            if conn:
                self.conntrack[pair] = conn