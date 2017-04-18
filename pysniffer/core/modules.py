import pysniffer.l2
import pysniffer.l3
import pysniffer.l4
import pysniffer.l7

REGISTER = [
    pysniffer.l2.Ethernet,
    pysniffer.l3.IPv4,
    pysniffer.l3.IPv6,
    pysniffer.l4.TCP,
    pysniffer.l4.UDP,
    pysniffer.l7.Http,
    pysniffer.l7.Telnet,
    pysniffer.l7.Ssh,
    pysniffer.l7.Dns,
    pysniffer.l7.Ssl,
    pysniffer.l7.Dhcp

]