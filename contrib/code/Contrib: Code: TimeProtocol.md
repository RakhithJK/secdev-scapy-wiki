TIME protocol extension
=======================

This Scapy add-on provides some layers for the
[TIME](http://en.wikipedia.org/wiki/TIME_protocol) protocol over UDP
as specified in RFC 868.

The TIME protocol is much simpler than NTP and less accurate. This is
more of an educational example. Have a look at the
[code](../../attachments/Code/TimeProtocol/time-rfc868-ext.py).

Usage
-----

Run the attached `time-rfc-868-ext.py` script and you'll get an
interactive prompt:

```
Welcome to Scapy (1.2.0.2)
TIME protocol (RFC 868) extension v0.2
>>>
```

First we ask the server `time-a.nist.gov` for the current time:

```
>>> a,u=sr(IP(dst="time-a.nist.gov")/UDP()/TIME_Req())
Begin emission:
Finished to send 1 packets.
...*
Received 4 packets, got 1 answers, remaining 0 packets
>>> a.summary()
IP / UDP 192.168.1.10:3737 > 129.6.15.28:time / TIME_Req ==> IP / UDP 129.6.15.2
8:time > 192.168.1.10:3737 / TIME_Resp / Padding
>>> a[0][1]
<IP  version=4L ihl=5L tos=0x0 len=32 id=7384 flags= frag=0L ttl=53 proto=udp 
chksum=0x1721 src=129.6.15.28 dst=192.168.1.10 options='' |
<UDP  sport=time dport=3737 len=12 chksum=0x1873 |
<TIME_Resp  time_stamp='Sat Apr 05 10:47:42 2008' |
<Padding  load='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' |>>>>
```

The results are show in the `time_stamp` attribute of the response.

We can run our own time server as well. It will listen for requests
and return the current system time in response:

```
>>> TIME_server()
Ether / IP / UDP 192.168.1.11:1053 > 192.168.1.10:time / Padding ==> IP / UDP 19
2.168.1.10:time > 192.168.1.11:1053 / Raw
```

== Known bugs ==

TIME requests technically do not have to have a payload. 

Currently, those packets are dissected only as UDP datagrams and not
as TIME requests.

== See also ==

 * [TIME protocol (Wikipedia)](http://en.wikipedia.org/wiki/TIME_protocol)
 * [List of TIME servers](http://tf.nist.gov/tf-cgi/servers.cgi)
 * [RFC 868](http://www.faqs.org/rfcs/rfc2328.html), official specification
 * [Neuthon](http://keir.net/neutron.html): a TIME client for Windows

== Credits ==

The TIME protocol extension was written by Dirk Loss (2008-04-05) and
is licensed under the GNU GPL.
