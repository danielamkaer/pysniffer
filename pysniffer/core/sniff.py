import logging
from pysniffer.core.util import Event

logger = logging.getLogger(__name__)

class Sniffer:
    def __init__(self):
        self.ifname = None
        self.store = 0
        self.packets = []
        self.onPacketReceived = Event()

    def setInterface(self, ifname):
        self.ifname = ifname

    def setStore(self, store):
        self.store = store

    def getPackets(self):
        return self.packets

    def start(self):
        import scapy.all
        self.packets = scapy.all.sniff(iface=self.ifname, store=self.store, prn=self.OnPacketReceived)

    def OnPacketReceived(self, packet):
        self.onPacketReceived(packet)