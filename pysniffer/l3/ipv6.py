import pysniffer.core
import pysniffer.l2
import logging

from scapy.layers.l2 import ETHER_TYPES

logger = logging.getLogger(__name__)

class IPv6:
    def __init__(self):
        self.onFrameReceived = pysniffer.core.Event()

    def register(self, app):
        self.app = app

    def boot(self):
        self.app[pysniffer.l2.Ethernet].onFrameReceived += self.OnFrameReceived, lambda pkt: pkt.is_ipv6

    async def OnFrameReceived(self, packet):
        logger.debug(f'{self} received packet: {packet.scapy.summary()}')
        await self.onFrameReceived(packet)