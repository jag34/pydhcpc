pydhcpc
=======

Dhcp client with scapy and python

# Usage

```
dhcpc.py  [--iface network interface] [--mac mac address] [--dhcp_opts dhcp options]

Options:
  -h, --help         show this help message and exit
  --mac=MAC_ADDRESS  A full mac address or part of it, if incomplete it will
                     be randomly generated.
  --iface=IFACE      Interface to use.
  --dhcp_opts        Dhcp options, must come las
```

## Requires

scapy-2.2.0-4.1

python 2.6+

## Disclaimers

Not tested on windows

Windows DHCP servers don't seem to like this.
