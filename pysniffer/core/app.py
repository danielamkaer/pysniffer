import argparse
import logging
from pysniffer.core.sniff import Sniffer
import pysniffer.l2
import pysniffer.l3
import pysniffer.l4
import pysniffer.l7
import inspect
import asyncio

logger = logging.getLogger(__name__)

class Container:
    def __init__(self):
        self.instances = {}
        self[asyncio.BaseEventLoop] = asyncio.get_event_loop()

    def __getitem__(self, key):
        if key in self.instances:
            return self.instances[key]

        if inspect.isclass(key):
            logger.debug(f'Autocreating type {key}.')
            self.instances[key] = key()
            return self.instances[key]

    def __setitem__(self, key, item):
        self.instances[key] = item

class Application(Container):
    register = [pysniffer.l2.Ethernet, pysniffer.l3.IPv4, pysniffer.l3.IPv6, pysniffer.l4.TCP, pysniffer.l7.Http, pysniffer.l7.Ssh]
    def __init__(self, argv):
        super().__init__()
        logging.basicConfig(level=logging.DEBUG)
        self.argv = argv
        self.parser = argparse.ArgumentParser("pysniffer")
        self.parser.add_argument('ifname', metavar='<ifname>', type=str, help='interface to listen on')
        self.args = self.parser.parse_args(self.argv[1:])
        logger.debug(f'Interface set to "{self.args.ifname}".')

        for t in Application.register:
            self[t].register(self)

    def run(self):


        sniffer = self[Sniffer]
        sniffer.setApp(self)
        sniffer.setInterface(self.args.ifname)

        for t in Application.register:
            self[t].boot()

        logger.info('Starting sniffer.')
        self[asyncio.BaseEventLoop].run_until_complete(sniffer.start())
        logger.info('Sniffer stopped.')