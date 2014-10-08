__author__ = 'joan.aguilar'

from scapy.all import *
from threading import Thread, Event

import random
import sys

conf.iface = 'eth9'

class TimedFunct(Thread):
    def __init__(self, interval, function, args=[], kwargs={}):
        Thread.__init__(self)
        self.interval = interval
        self.function = function
        self.args = args
        self.kwargs = kwargs
        self.finished = Event()

    def cancel(self):
        """Stop the timer if it hasn't finished yet"""
        self.finished.set()

    def run(self):
        while not self.finished.is_set():
            self.function(*self.args, **self.kwargs)
            self.finished.wait(self.interval)

class DHCPC_Am(AnsweringMachine):
    function_name = "dhcpc"
    filter = "udp and port 68 and port 67"
    send_function = staticmethod(sendp)

    @property
    def dhcp_complete(self):
        return self.__ip is not None

    @property
    def ip(self):
        return self.__ip

    @property
    def mac(self):
        return self.__mac

    def parse_options(self, ip=None, mac=str(RandMAC(template="00:a0:3f")), options=None):
        if options is None:
            self.__options = []

        self.__mac = mac
        self.__ip = ip
        self.__router = None
        self.__lease_time = 0
        self.__discoverer = None
        self.__xid = random.randint(0, sys.maxint)

        self.sniff_options['stop_filter'] = self.stop_dhcp_filter

        self.start_discover()

    def start_discover(self):
        print "Sending discover with mac: {mac} through {iface}".format(mac=self.__mac, iface=conf.iface)
        l3 = Ether(dst='ff:ff:ff:ff:ff:ff', src=self.__mac, type=0x0800)
        l2 = IP(src='0.0.0.0', dst='255.255.255.255')
        udp =  UDP(dport=67,sport=68)
        bootp = BOOTP(op=1, xid=self.__xid)
        dhcp = DHCP(options=[('message-type','discover'), ('end')])

        packet = l3/l2/udp/bootp/dhcp

        self.__discoverer = TimedFunct(5, sendp, args=[packet])
        self.__discoverer.start()

    def print_reply(self, req, reply):
        requested_addr = ''
        dhcp_serv = ''
        for option in reply.getlayer(DHCP).options:
            if option[0] == 'requested_addr':
                requested_addr = option[1]
            elif option[0] == 'server_id':
                dhcp_serv = option[1]
        print "Requesting address {ip} from {serv}".format(ip=requested_addr, serv=dhcp_serv)

    def is_request(self, req):
        if req.haslayer(BOOTP):
            bootp = req.getlayer(BOOTP)
            if bootp.xid == self.__xid:
                if req.haslayer(DHCP) and self.__ip is None:
                    print "Dhcp packet!"
                    dhcp = req.getlayer(DHCP)
                    if dhcp.options[0][0] == 'message-type':
                        message_type = dhcp.options[0][1]
                        # Only interested in offers
                        if message_type == 2:
                            return 1
        return 0

    def make_reply(self, req):
        self.__discoverer.cancel()
        self.__xid = random.randint(0, sys.maxint)

        self.__ip = req.getlayer(IP).yiaddr
        self.__router = req.getlayer(IP).src

        l3 = Ether(dst=req.getlayer(Ether).src, src=self.__mac)
        l2 = IP(src=self.__ip, dst=req.getlayer(IP).src)
        udp = UDP(sport=req.dport, dport=req.sport)
        bootp = BOOTP(op=1, chaddr=self.__mac, xid=self.__xid)
        dhcp = DHCP(options=[('message-type','request'),
                             ('client_id', self.__mac),
                             ('requested_addr', self.__ip),
                             ('server_id', self.__router),
                             ('end')])

        rep=l3/l2/udp/bootp/dhcp

        return rep

    def stop_discover(self):
        if self.__discoverer is not None:
            self.__discoverer.cancel()

    def stop_dhcp_filter(self, req):
        if req.haslayer(IP):
            if req.getlayer(IP).dst == self.__ip:
                if req.haslayer(DHCP):
                    dhcp = req.getlayer(DHCP)
                    if dhcp.options[0][0] == 'message-type':
                        message_type = dhcp.options[0][1]
                        if message_type == 5:
                            return 1
        return 0

    def wait_lease(self):
        arp_responder = self.create_arp_am()
        arp_responder()

    def create_arp_am(self):
        return ARP_am(IP_addr=self.__ip, ARP_addr=self.__mac)

if __name__ == '__main__':
    dhcp_client = DHCPC_Am()

    try:
        print "Starting sniff"
        dhcp_client()
        # Respond to arp requests til the end of tiem, or -TERM'd of course.
        dhcp_client.wait_lease()

    except KeyboardInterrupt:
        dhcp_client.stop_discover()