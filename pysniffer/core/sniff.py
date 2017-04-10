import logging
from pysniffer.core.util import Event
import asyncio
import functools

logger = logging.getLogger(__name__)

class Packet:
    def __init__(self, scapy):
        self.scapy = scapy

    @property
    def is_ipv4(self):
        return 'IP' in self.scapy

    @property
    def is_ipv6(self):
        return 'IPv6' in self.scapy

    @property
    def ip_src(self):
        if self.is_ipv4:
            return self.scapy['IP'].src
        elif self.is_ipv6:
            return self.scapy['IPv6'].src

    @property
    def ip_dst(self):
        if self.is_ipv4:
            return self.scapy['IP'].dst
        elif self.is_ipv6:
            return self.scapy['IPv6'].dst

    @property
    def mac_src(self):
        return self.scapy.src

    @property
    def mac_dst(self):
        return self.scapy.dst

    @property
    def is_tcp(self):
        return 'TCP' in self.scapy

    @property
    def is_udp(self):
        return 'UDP' in self.scapy

    @property
    def port_src(self):
        if self.is_tcp:
            return self.scapy['TCP'].sport
        elif self.is_udp:
            return self.scapy['UDP'].sport

    @property
    def port_dst(self):
        if self.is_tcp:
            return self.scapy['TCP'].dport
        elif self.is_udp:
            return self.scapy['UDP'].dport

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
        fut = asyncio.run_coroutine_threadsafe(self.onPacketReceived(Packet(packet)), loop)
        self.checkException(fut)

    def checkException(self, fut):
        fut.add_done_callback(self.doCheckException)

    def doCheckException(self, fut):
        if fut.exception():
            loop = self.app[asyncio.BaseEventLoop]
            loop.call_soon_threadsafe(self.doRaiseException, fut.exception())

    def doRaiseException(self, ex):
        raise ex