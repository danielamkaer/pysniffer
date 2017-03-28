import pysniffer.core
import pysniffer.l2
import logging

from scapy.layers.l2 import ETHER_TYPES

class IPv6:
    def __init__(self):
        self.onFrameReceived = pysniffer.core.Event()

    def register(self, app):
        self.app = app

    def boot(self):
        self.app[pysniffer.l2.Ethernet].onFrameReceived += self.OnFrameReceived, lambda pkt: pkt.type == ETHER_TYPES.IPv6

    def OnFrameReceived(self, packet):
        logging.debug(f'{self} received packet: {packet.summary()}')
        self.onFrameReceived(packet)