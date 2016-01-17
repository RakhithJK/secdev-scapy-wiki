Monitor RIP broadcasts as they happen
=====================================

Problem
-------

You need to monitor RIP broadcast as they happen to help diagnose RIP
problems

Solution
--------

```python
#! /usr/bin/env python
from scapy import *
import IPy

def rip_cb(p):
        try:
                src = socket.gethostbyaddr(p[IP].src)[0]
        except socket.herror, e:
                if e.args[0] == 1:
                        src = p[IP].src

        re = p[RIPEntry]
        while type(re) != NoPayload:
                addr = re.addr + "/" + re.mask
                print "%-25s %-18s %s" % \
                        ( src, IPy.IP(addr), re.metric)
                re = re.payload


sniff(prn=rip_cb, filter="udp and dst port route", store=0)
```

Discussion
----------

When run it prints out three columns the source address, the route
offered and the metric.

See also
--------

[SimplisticARPMonitor](Contrib: Code: SimplisticARPMonitor)

Credits
-------

Thomas Stewart 2008
