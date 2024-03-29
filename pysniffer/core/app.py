import argparse
import logging
from pysniffer.core.sniff import Sniffer
import pysniffer.core
import inspect
import asyncio
import signal


logger = logging.getLogger(__name__)

class Arguments:
    def __init__(self):
        self.verbose = False
        self.warning = []
        self.debug = []
        self.info = []
        self.ifname = ""

class Container:
    def __init__(self):
        self.instances = {}
        self[asyncio.BaseEventLoop] = asyncio.new_event_loop()

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
    def __init__(self, argv=None, **kwargs):
        from pysniffer.core.modules import REGISTER
        super().__init__()

        if argv:
            self.argv = argv
            self.handleArguments()
        else:
            self.handleKeywordArguments(kwargs)

        self.configure()
        self.onReport = pysniffer.core.Event()

        for t in REGISTER:
            self[t].register(self)

    async def report(self, caller, report):
        await self.onReport(caller, report)

    def handleKeywordArguments(self, kwargs):
        self.args = Arguments()
        for key in kwargs:
            setattr(self.args, key, kwargs[key])

    def handleArguments(self):
        self.parser = argparse.ArgumentParser("pysniffer")
        self.parser.add_argument('ifname', metavar='<ifname>', type=str, help='interface to listen on')
        self.parser.add_argument('-d', action='append', dest='debug')
        self.parser.add_argument('-i', action='append', dest='info')
        self.parser.add_argument('-w', action='append', dest='warning')
        self.parser.add_argument('-v', action='store_true', dest='verbose')

        self.args = self.parser.parse_args(self.argv[1:])

    def configure(self):

        if self.args.verbose:
            logging.basicConfig(level=logging.DEBUG)
            logging.debug('Set log level to debug')
        else:
            logging.basicConfig(level=logging.ERROR)

        logger.debug(f'Interface set to "{self.args.ifname}".')

        if self.args.warning:
            for name in self.args.warning:
                logging.getLogger(name).setLevel(logging.WARNING)
                logging.getLogger(name).warning("Set log level to warning")

        if self.args.info:
            for name in self.args.info:
                logging.getLogger(name).setLevel(logging.INFO)
                logging.getLogger(name).info("Set log level to info")

        if self.args.debug:
            for name in self.args.debug:
                logging.getLogger(name).setLevel(logging.DEBUG)
                logging.getLogger(name).debug("Set log level to debug")


    def run(self):
        from pysniffer.core.modules import REGISTER


        sniffer = self[Sniffer]
        sniffer.setApp(self)
        sniffer.setInterface(self.args.ifname)

        for t in REGISTER:
            self[t].boot()

        loop = self[asyncio.BaseEventLoop]
        #loop.add_signal_handler(signal.SIGINT, sniffer.stop)

        logger.info('Starting sniffer.')
        loop.run_until_complete(sniffer.start())
        logger.info('Sniffer stopped.')

    def stop(self):
        self[Sniffer].stop()
