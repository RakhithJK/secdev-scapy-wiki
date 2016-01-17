Scapy sniff() patch to be able to stop the sniffer in a programmatic way
========================================================================

`sniff()` function is `sendrecv.py` now takes 2 more arguments:
`stopperTimeout` and `stopper`, so every "`stopperTimeout` sec",
`stopper()` is called and `sniff` is stopped if `stopper()` returns
`True`

```python
def sniff(count=0, store=1, offline=None, prn = None, lfilter=None, L2socket=None, timeout=None, stopperTimeout=None, stopper = None, *arg, **karg):
    """Sniff packets
sniff([count=0,] [prn=None,] [store=1,] [offline=None,] [lfilter=None,] + L2ListenSocket args) -> list of packets

  count: number of packets to capture. 0 means infinity
  store: wether to store sniffed packets or discard them
    prn: function to apply to each packet. If something is returned,
         it is displayed. Ex:
         ex: prn = lambda x: x.summary()
lfilter: python function applied to each packet to determine
         if further action may be done
         ex: lfilter = lambda x: x.haslayer(Padding)
offline: pcap file to read packets from, instead of sniffing them
timeout: stop sniffing after a given time (default: None)
stopperTimeout: break the select to check the returned value of 
         stopper() and stop sniffing if needed (select timeout)
stopper: function returning true or false to stop the sniffing process
L2socket: use the provided L2socket
    """
    c = 0

    if offline is None:
        if L2socket is None:
            L2socket = conf.L2listen
        s = L2socket(type=ETH_P_ALL, *arg, **karg)
    else:
        s = PcapReader(offline)

    lst = []
    if timeout is not None:
        stoptime = time.time()+timeout
    remain = None

    if stopperTimeout is not None:
        stopperStoptime = time.time()+stopperTimeout
    remainStopper = None
    while 1:
        try:
            if timeout is not None:
                remain = stoptime-time.time()
                if remain <= 0:
                    break

            if stopperTimeout is not None:
                remainStopper = stopperStoptime-time.time()
                if remainStopper <=0:
                    if stopper and stopper():
                        break
                    stopperStoptime = time.time()+stopperTimeout
                    remainStopper = stopperStoptime-time.time()

                sel = select([s],[],[],remainStopper)
                if s not in sel[0]:
                    if stopper and stopper():
                        break
            else:
                sel = select([s],[],[],remain)

            if s in sel[0]:
                p = s.recv(MTU)
                if p is None:
                    break
                if lfilter and not lfilter(p):
                    continue
                if store:
                    lst.append(p)
                c += 1
                if prn:
                    r = prn(p)
                    if r is not None:
                        print r
                if count > 0 and c >= count:
                    break
        except KeyboardInterrupt:
            break
    s.close()
    return plist.PacketList(lst,"Sniffed")
```


Sample code to test:

```python
#!/usr/bin/python
import sys, os
from scapy.all import *

incrementMe=0

def callback(pkt):
    print "packet received"

def stopperCheck():
    global incrementMe
    incrementMe=incrementMe+1
    print "incrementMe is now %s" % incrementMe

    if incrementMe>3: 

        # Time to stop the sniffer ;)
        return True

    # No ? let's continu
    return False

def main():
    expr='tcp or udp'
    try:
        sniff(filter=expr, prn=callback, stopperTimeout=1, stopper=stopperCheck, store=0)
    except KeyboardInterrupt:
        exit(0)


if __name__ == "__main__":
    main()
```

Hope this helps, Franck34
