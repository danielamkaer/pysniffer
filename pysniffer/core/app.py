import argparse
import logging
from pysniffer.core.sniff import Sniffer
import pysniffer.l2
import pysniffer.l3
import pysniffer.l4
import pysniffer.l7
import inspect

class Container:
    def __init__(self):
        self.instances = {}

    def __getitem__(self, key):
        if key in self.instances:
            return self.instances[key]

        if inspect.isclass(key):
            logging.debug(f'Autocreating type {key}.')
            self.instances[key] = key()
            return self.instances[key]

    def __setitem__(self, key, item):
        self.instances[key] = item

class Application(Container):
    register = [pysniffer.l2.Ethernet, pysniffer.l3.IPv4, pysniffer.l3.IPv6, pysniffer.l4.TCP, pysniffer.l7.Http]
    def __init__(self, argv):
        super().__init__()
        logging.basicConfig(level=logging.DEBUG)
        self.argv = argv
        self.parser = argparse.ArgumentParser("pysniffer")
        self.parser.add_argument('ifname', metavar='<ifname>', type=str, help='interface to listen on')
        self.args = self.parser.parse_args(self.argv[1:])
        logging.debug(f'Interface set to "{self.args.ifname}".')

        for t in Application.register:
            self[t].register(self)

    def run(self):


        sniffer = self[Sniffer]
        sniffer.setInterface(self.args.ifname)

        for t in Application.register:
            self[t].boot()

        logging.info('Starting sniffer.')
        sniffer.start()
        logging.info('Sniffer stopped.')