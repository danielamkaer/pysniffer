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
        self.stopRequested = False

    def setApp(self, app):
        self.app = app

    def setInterface(self, ifname):
        self.ifname = ifname

    def setStore(self, store):
        self.store = store

    def getPackets(self):
        return self.packets

    def stop(self):
        print()
        print()
        print()
        print("STOPPING AFTER NEXT PACKET")
        print()
        print()
        print()
        self.stopRequested = True

    async def start(self):
        import scapy.all
        loop = self.app[asyncio.BaseEventLoop]
        self.packets = await loop.run_in_executor(None, functools.partial(scapy.all.sniff, iface=self.ifname, store=self.store, prn=self.OnPacketReceived, stop_filter=lambda pkt: self.stopRequested))

    def OnPacketReceived(self, packet):
        loop = self.app[asyncio.BaseEventLoop]
        fut = asyncio.run_coroutine_threadsafe(self.onPacketReceived(packet), loop)
        self.checkException(fut)

    def checkException(self, fut):
        fut.add_done_callback(self.doCheckException)

    def doCheckException(self, fut):
        if fut.exception():
            loop = self.app[asyncio.BaseEventLoop]
            loop.call_soon_threadsafe(self.doRaiseException, fut.exception())

    def doRaiseException(self, ex):
        raise ex