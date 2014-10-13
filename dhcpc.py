__author__ = 'joan.aguilar'

from scapy.all import *
from threading import Thread, Event

import random
import sys
import optparse

conf.iface = 'eth9'

class TimedFunct(Thread):
    def __init__(self, interval, function, repetitions=0, args=[], kwargs={}):
        Thread.__init__(self)
        self.interval = interval
        self.repetitions = repetitions
        self.function = function
        self.args = args
        self.kwargs = kwargs
        self.finished = Event()

    def cancel(self):
        """Stop the timer if it hasn't finished yet"""
        self.finished.set()

    @property
    def completed(self):
        return self.finished.is_set()

    def run(self):
        counter = self.repetitions
        while not self.finished.is_set():
            self.function(*self.args, **self.kwargs)
            self.finished.wait(self.interval)
            if counter != 0:
                counter -= 1
            elif self.repetitions != 0:
                self.cancel()

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

    def __init__(self, *args, **kwargs):
        mac = kwargs.pop('mac', None)
        options = kwargs.pop('options', None)
        super(DHCPC_Am, self).__init__(*args, **kwargs)

        if options is None:
            self.__options = []
        if mac is None:
            mac= str(RandMAC(template="00:a0:3f"))

        self.__mac = mac
        self.__ip = None
        self.__router = None
        self.__lease_time = 0
        self.__discoverer = None
        self.__xid = random.randint(0, sys.maxint)

    def start_discover(self):
        if self.__discoverer is None:
            print "Sending discover with mac: {mac} through {iface}".format(mac=self.__mac, iface=conf.iface)
            l3 = Ether(dst='ff:ff:ff:ff:ff:ff', src=self.__mac, type=0x0800)
            l2 = IP(src='0.0.0.0', dst='255.255.255.255')
            udp =  UDP(dport=67,sport=68)
            bootp = BOOTP(op=1, xid=self.__xid)
            dhcp = DHCP(options=[('message-type','discover'), ('end')])

            packet = l3/l2/udp/bootp/dhcp
            self.__discoverer = TimedFunct(5, sendp, repetitions=5, args=[packet])
            self.__discoverer.start()

    def parse_options(self):
        self.sniff_options['stop_filter'] = self.stop_dhcp_filter

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
        if self.__ip is not None:
            if req.haslayer(IP):
                if req.getlayer(IP).dst == self.__ip:
                    if req.haslayer(DHCP):
                        dhcp = req.getlayer(DHCP)
                        if dhcp.options[0][0] == 'message-type':
                            message_type = dhcp.options[0][1]
                            if message_type == 5:
                                return 1
        elif self.__discoverer.completed:
            # If self.__ip is none and the discoverer is done then
            # The discoverer has timed out, we are done.
            return 1
        return 0

    def wait_lease(self):
        arp_responder = self.create_arp_am()
        arp_responder()

    def create_arp_am(self):
        return ARP_am(IP_addr=self.__ip, ARP_addr=self.__mac)

    def __call__(self, *args, **kwargs):
        self.start_discover()
        super(DHCPC_Am, self).__call__(*args, **kwargs)

if __name__ == '__main__':
    usage = "dhcpc.py  [--mac mac address] [--dhcp_opts dhcp options]"
    parser = optparse.OptionParser(usage=usage)

    parser.add_option("--mac", dest="mac_address",
                      help="A full mac address or part of it, if incomplete it will be randomly generated.")
    parser.add_option("--iface", dest="iface",
                      help="Interface to use.")

    parser.add_option("--dhcp_opts", dest="opts", action="store_true",
                      help="Dhcp options, must come last")

    (options, args) = parser.parse_args()

    dhcp_options = []
    if options.opts:
        for arg in args:
            dhcp_options.append(arg)

    if options.iface is not None:
        conf.iface = options.iface
    dhcp_client = DHCPC_Am(mac=options.mac_address, options=dhcp_options)
    try:
        dhcp_client()
        if dhcp_client.ip is not None:
            # Respond to arp requests til the end of tiem, or -TERM'd of course.
            dhcp_client.wait_lease()
        else:
            exit(2)

    except KeyboardInterrupt:
        dhcp_client.stop_discover()
