Simplistic ARP Monitor
======================

This program uses the `sniff()` callback (paramter `prn`). The `store`
parameter is set to 0 so that `sniff()` will not store anything (as it
would do otherwise) and thus can run forever. The `filter` parameter
is used for better performances on high load: the filter is applied
inside the kernel and Scapy will only see ARP traffic.

```python
#! /usr/bin/env python
from scapy import *

def arp_monitor_callback(pkt):
    if ARP in pkt and pkt[ARP].op in (1,2): #who-has or is-at
        return pkt.sprintf("%ARP.hwsrc% %ARP.psrc%")

sniff(prn=arp_monitor_callback, filter="arp", store=0)
```
