import pysniffer.core
import logging
from scapy.layers.l2 import ETHER_TYPES

logger = logging.getLogger(__name__)

class Ethernet:
    def __init__(self):
        self.onFrameReceived = pysniffer.core.Event()

    def register(self, app):
        self.app = app

    def boot(self):
        self.app[pysniffer.core.Sniffer].onPacketReceived += self.OnPacketReceived
    
    def OnPacketReceived(self, packet):
        logger.debug(f'{self} received packet: {packet.summary()}')

        self.onFrameReceived(packet)
