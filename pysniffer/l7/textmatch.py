import pysniffer.l4
import logging
logger = logging.getLogger(__name__)
import re

class HttpClientReport(pysniffer.core.Report):
    FIELDS = {
        'host': 'Client IP address',
        'port': 'Server port',
        'dest': 'Server IP address',
        'software': 'Client user agent, if detected'
    }

class HttpServerReport(pysniffer.core.Report):
    FIELDS = {
        'host': 'Server IP address',
        'port': 'Server port',
        'software': 'Server software version, if detected'
    }

class SshClientReport(pysniffer.core.Report):
    FIELDS = {
        'host': 'Client IP address',
        'port': 'Server port',
        'dest': 'Server IP address',
        'software': 'Client user agent, if detected'
    }

class SshServerReport(pysniffer.core.Report):
    FIELDS = {
        'host': 'Server IP address',
        'port': 'Server port',
        'software': 'Server software version, if detected'
    }

class TextMatch:

    def doesClientSendFirstMessage(self):
        raise NotImplementedError("doesClientSendFirstMessage must be implemented.")

    def getFirstPattern(self):
        raise NotImplementedError("getFirstPattern must be implemented.")

    def getSecondPattern(self):
        raise NotImplementedError("getSecondPattern must be implemented.")

    def generateReports(self, packet):
        raise NotImplementedError("generateReports must be implemented.")

    def register(self, app):
        self.app = app

    def boot(self):
        logger.debug(f"{self.__class__.__name__} booted!")
        self.app[pysniffer.l4.TCP].onConnectionEstablished += self.onConnectionEstablished

    async def onConnectionEstablished(self, conn):
        conn.userdata[self.__class__] = {}
        if self.doesClientSendFirstMessage():
            conn.onClientSent += self.onFirstMessage
        else:
            conn.onServerSent += self.onFirstMessage

    async def onFirstMessage(self, conn, packet):
        if self.doesClientSendFirstMessage():
            conn.onClientSent -= self.onFirstMessage
        else:
            conn.onServerSent -= self.onFirstMessage

        payload = packet.scapy['Raw'].load

        m = self.getFirstPattern().match(payload)
        if m:
            conn.userdata[self.__class__]['first'] = m
            if self.getSecondPattern() == None:
                logger.info(f"Found {self.__class__.__name__} service")
            else:
                logger.info(f"Found {self.__class__.__name__} first pattern")
                if self.doesClientSendFirstMessage():
                    conn.onServerSent += self.onSecondMessage
                else:
                    conn.onClientSent += self.onSecondMessage

    async def onSecondMessage(self, conn, packet):
        if self.doesClientSendFirstMessage():
            conn.onServerSent -= self.onSecondMessage
        else:
            conn.onClientSent -= self.onSecondMessage

        payload = bytes(packet.scapy['Raw'].load)

        m = self.getSecondPattern().match(payload)
        if m:
            conn.userdata[self.__class__]['second'] = m
            logger.info(f"Found {self.__class__.__name__} service")
            await self.generateReports(packet, conn.userdata[self.__class__])

class Http(TextMatch):
    #(?=.*(?:Server: (?P<server>[^\n]+)))?(?=.*(?:X-Powered-By: (?P<x_powered_by>[^\n]+)))?^HTTP\/(?P<version>\d\.\d) (?P<result>\d{3}) (?P<status>[^\r\n]+)
    REGEX_cli = re.compile(b'^(?P<method>GET|POST|DELETE|PUT|PATCH|HEAD) (?P<path>.+) HTTP/(?P<version>\d\.\d)(?:.*User-Agent: (?P<user_agent>[^\n\r]+))?', re.DOTALL)
    REGEX_srv = re.compile(b'^HTTP\/(?P<version>\d\.\d) (?P<result>\d{3}) (?P<status>[^\r\n]+)(?:.*Server: (?P<server>[^\r\n]+))?', re.DOTALL)
    def doesClientSendFirstMessage(self):
        return True

    def getFirstPattern(self):
        return self.REGEX_cli    

    def getSecondPattern(self):
        return self.REGEX_srv    

    async def generateReports(self, packet, userdata):
        await self.app.report(self, HttpClientReport(host=packet.ip_dst, dest=packet.ip_src, port=packet.port_src, software=str(userdata['first'].group('user_agent'))))
        await self.app.report(self, HttpServerReport(host=packet.ip_src, port=packet.port_src, software=str(userdata['second'].group('server'))))
        
class Ssh(TextMatch):
    REGEX = re.compile(b'^SSH-(?P<software>.+?)\r?$')
    def doesClientSendFirstMessage(self):
        return True

    def getFirstPattern(self):
        return self.REGEX    

    def getSecondPattern(self):
        return self.REGEX    

    async def generateReports(self, packet, userdata):
        await self.app.report(self, SshClientReport(host=packet.ip_dst, dest=packet.ip_src, port=packet.port_src, software=str(userdata['first'].group('software'))))
        await self.app.report(self, SshServerReport(host=packet.ip_src, port=packet.port_src, software=str(userdata['second'].group('software'))))
        