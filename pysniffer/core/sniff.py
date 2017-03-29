import logging
from pysniffer.core.util import Event
import asyncio
import functools

logger = logging.getLogger(__name__)

class Sniffer:
    def __init__(self):
        self.ifname = None
        self.store = 0
        self.packets = []
        self.onPacketReceived = Event()

    def setApp(self, app):
        self.app = app

    def setInterface(self, ifname):
        self.ifname = ifname

    def setStore(self, store):
        self.store = store

    def getPackets(self):
        return self.packets

    async def start(self):
        import scapy.all
        loop = self.app[asyncio.BaseEventLoop]
        self.packets = await loop.run_in_executor(None, functools.partial(scapy.all.sniff, iface=self.ifname, store=self.store, prn=self.OnPacketReceived))

    def OnPacketReceived(self, packet):
        loop = self.app[asyncio.BaseEventLoop]
        asyncio.run_coroutine_threadsafe(self.onPacketReceived(packet), loop)
        #self.onPacketReceived(packet)