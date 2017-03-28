import pysniffer.core
import pysniffer.l3
import logging

from scapy.layers.inet import IP_PROTOS

logger = logging.getLogger(__name__)

class Connection:
    STATE_SYN_RECEIVED = 0
    STATE_SYNACK_RECEIVED = 1
    STATE_ACK_RECEIVED = 2 
    def __init__(self, src, dst, sport, dport, seq):
        self.src = src
        self.dst = dst
        self.sport = sport
        self.dport = dport
        self.seq = seq
        self.state = Connection.STATE_SYN_RECEIVED

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
        return TCP.ReversePair(TCP.GetPair(packet))

    def register(self, app):
        self.app = app

    def boot(self):
        self.app[pysniffer.l3.IPv4].onFrameReceived += self.OnFrameReceived, lambda pkt:pkt['IP'].proto == IP_PROTOS.tcp
        self.app[pysniffer.l3.IPv6].onFrameReceived += self.OnFrameReceived, lambda pkt:pkt['IPv6'].nh == IP_PROTOS.tcp

    def OnFrameReceived(self, packet):
        logger.debug(f'{self} received packet: {packet.summary()}')
        pair = TCP.TcpPair(packet)

        if packet['TCP'].flags == TCP.SYN:
            logger.debug('Received SYN')

            if pair not in self.conntrack:
                self.conntrack[pair] = Connection(*pair, packet['TCP'].seq)
            else:
                logger.warning(f'Already tracking {pair}')


        if packet['TCP'].flags == TCP.SYN|TCP.ACK:
            logger.debug('Received SYN+ACK')

            revpair = TCP.ReversePair(pair)
            if revpair in self.conntrack:
                conn = self.conntrack[revpair]
                if conn.state == Connection.STATE_SYN_RECEIVED:
                    if packet['TCP'].ack == conn.seq+1:
                        conn.state = Connection.STATE_SYNACK_RECEIVED
            else:
                logger.warning(f'Not tracking {pair}')

        if packet['TCP'].flags == TCP.ACK:
            logger.debug('Received ACK')

            if pair in self.conntrack:
                conn = self.conntrack[pair]
                if conn.state == Connection.STATE_SYNACK_RECEIVED:
#                    if packet['TCP'].ack == conn.seq+1:
                    conn.state = Connection.STATE_ACK_RECEIVED
                    logger.info(f'Connection established: {pair}')
                    self.onConnectionEstablished(conn)
            else:
                logger.warning(f'Not tracking {pair}')
