OSPF extension
==============

This Scapy add-on provides some layers for the Open Shortest Path First routing protocol.

Download the latest version [scapy_ospf-v0.91.py](attachments/Code/OSPF/scapy_ospf-v0.91.py) and rename the file to `scapy_ospf.py`.

Usage
-----

Run the `scapy_ospf.py` script and you'll get an interactive prompt:  

```
Welcome to Scapy (2.0.0.10 beta)
OSPF extension v0.9.1
>>>
```

First we get some OSPF traffic from a Wireshark capture file ([ospf.cap](http://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=ospf.cap)):

```
>>> o=rdpcap("ospf.cap")
>>> o.nsummary()
0000 Ether / 192.168.170.8 > 224.0.0.5 ospf / OSPF_Hdr / OSPF_Hello
0001 Ether / 192.168.170.8 > 224.0.0.5 ospf / OSPF_Hdr / OSPF_Hello
0002 Ether / 192.168.170.8 > 224.0.0.5 ospf / OSPF_Hdr / OSPF_Hello
0003 Ether / 192.168.170.8 > 224.0.0.5 ospf / OSPF_Hdr / OSPF_Hello
0004 Ether / 192.168.170.8 > 224.0.0.5 ospf / OSPF_Hdr / OSPF_Hello
0005 Ether / 192.168.170.8 > 224.0.0.5 ospf / OSPF_Hdr / OSPF_Hello
0006 Ether / 192.168.170.2 > 224.0.0.5 ospf / OSPF_Hdr / OSPF_Hello
0007 Ether / 192.168.170.8 > 224.0.0.5 ospf / OSPF_Hdr / OSPF_Hello
0008 Ether / 192.168.170.2 > 224.0.0.5 ospf / OSPF_Hdr / OSPF_Hello
0009 Ether / 192.168.170.8 > 192.168.170.2 ospf / OSPF_Hdr / OSPF_DBDesc
0010 Ether / 192.168.170.2 > 192.168.170.8 ospf / OSPF_Hdr / OSPF_DBDesc
0011 Ether / 192.168.170.2 > 192.168.170.8 ospf / OSPF_Hdr / OSPF_DBDesc
0012 Ether / 192.168.170.8 > 192.168.170.2 ospf / OSPF_Hdr / OSPF_DBDesc
0013 Ether / 192.168.170.2 > 192.168.170.8 ospf / OSPF_Hdr / OSPF_DBDesc
0014 Ether / 192.168.170.8 > 192.168.170.2 ospf / OSPF_Hdr / OSPF_DBDesc
0015 Ether / 192.168.170.2 > 192.168.170.8 ospf / OSPF_Hdr / OSPF_DBDesc
0016 Ether / 192.168.170.2 > 192.168.170.8 ospf / OSPF_Hdr / OSPF_LSReq
0017 Ether / 192.168.170.8 > 192.168.170.2 ospf / OSPF_Hdr / OSPF_LSReq
0018 Ether / 192.168.170.8 > 224.0.0.5 ospf / OSPF_Hdr / OSPF_LSUpd
0019 Ether / 192.168.170.2 > 224.0.0.6 ospf / OSPF_Hdr / OSPF_LSUpd
0020 Ether / 192.168.170.2 > 224.0.0.6 ospf / OSPF_Hdr / OSPF_LSUpd
0021 Ether / 192.168.170.8 > 224.0.0.5 ospf / OSPF_Hdr / OSPF_LSUpd
0022 Ether / 192.168.170.8 > 224.0.0.5 ospf / OSPF_Hdr / OSPF_LSUpd
0023 Ether / 192.168.170.8 > 224.0.0.5 ospf / OSPF_Hdr / OSPF_LSAck
0024 Ether / 192.168.170.2 > 224.0.0.6 ospf / OSPF_Hdr / OSPF_LSUpd
0025 Ether / 192.168.170.8 > 224.0.0.5 ospf / OSPF_Hdr / OSPF_LSAck
0026 Ether / 192.168.170.2 > 192.168.170.8 ospf / OSPF_Hdr / OSPF_LSUpd
0027 Ether / 192.168.170.8 > 192.168.170.2 ospf / OSPF_Hdr / OSPF_LSAck
0028 Ether / 192.168.170.2 > 224.0.0.6 ospf / OSPF_Hdr / OSPF_LSUpd
0029 Ether / 192.168.170.8 > 192.168.170.2 ospf / OSPF_Hdr / OSPF_LSAck
0030 Ether / 192.168.170.8 > 224.0.0.5 ospf / OSPF_Hdr / OSPF_Hello
```

Let's have a deeper look at packet number 21:

```
>>> o[21].show()
###[[|Ethernet ]]###
  dst= 01:00:5e:00:00:05
  src= 00:e0:18:b1:0c:ad
  type= 0x800
###[[|IP ]]###
     version= 4L
     ihl= 5L
     tos= 0xc0
     len= 80
     id= 2074
     flags= 
     frag= 0L
     ttl= 1
     proto= ospf
     chksum= 0x65c5
     src= 192.168.170.8
     dst= 224.0.0.5
     options= ''
###[[|OSPF Header ]]###
        version= 2
        type= LSUpd
        len= 60
        src= 192.168.170.8
        area= 0.0.0.1
        chksum= 0x2f6f
        authtype= Null
        authdata= 0x0
###[[|OSPF Link State Update ]]###
           lsacount= 1
           \lsalist\
            |###[[|OSPF Network LSA ]]###
            |  age= 1
            |  options= E
            |  type= 2
            |  id= 192.168.170.8
            |  adrouter= 192.168.170.8
            |  seq= 0x80000001L
            |  chksum= 0x37b7
            |  len= 32
            |  mask= 255.255.255.0
            |  routerlist= [['192.168.170.3',|'192.168.170.8']]
```

Two more interesting packets are number 11 and number 17: (We skip the output here for brevity).

```
>>> o[11].show()
>>> o[17].show()
```

Now we construct OSPF packets on our own and analyze them. Checksums are computed automatically:

```
>>> p=IP()/OSPF_Hdr()/OSPF_LSReq(requests=[OSPF_LSReq_Item()])
>>> p.show2()
>>> q=IP()/OSPF_Hdr()/OSPF_LSUpd(lsalist=[[OSPF_Router_LSA(id='1.1.1.1'),|OSPF_Router_LSA(id='2.2.2.2')]])
>>> wireshark(q)
```

If you use the `.command()` method on a sniffed packet, Scapy tells you how to reproduce it: 
```
>>> o[17][OSPF_Hdr].command()
```

Some more examples:
```
>>> IP(dst="192.168.1.1")/OSPF_Hdr()/OSPF_LSUpd(lsalist=[[
|OSPF_Router_LSA(linklist=[OSPF_Link(), OSPF_Link()]]), OSPF_Network_LSA(),
         OSPF_SummaryIP_LSA(), OSPF_SummaryASBR_LSA(), OSPF_External_LSA()])
>>> IP(dst='224.0.0.5')/OSPF_Hdr(src='192.168.170.8')/OSPF_Hello(hellointerval=10,
         prio=1, deadinterval=40, router='192.168.170.8', backup='0.0.0.0', options=2)
>>> IP(dst="1.1.1.1")/OSPF_Hdr(src='192.168.170.8')/OSPF_LSUpd(lsalist=[[
|OSPF_Router_LSA(seq=2147487171L, age=994, adrouter='192.168.170.8', 
         linklist=[OSPF_Link(type=3, metric=10, data='255.255.255.0', id='192.168.170.0', 
         toscount=0)]], flags=512L, id='192.168.170.8', options=2L)])
```

See also
--------

 * [OSPF (Wikipedia)](http://en.wikipedia.org/wiki/Open_Shortest_Path_First)
 * [RFC 2328](http://www.faqs.org/rfcs/rfc2328.html), official specification
 * [Wireshark sample captures](http://wiki.wireshark.org/SampleCaptures), offers some OSPF capture files to experiment with

Credits
-------

The OSPF extension was written by Dirk Loss (2008-03-28) and is licensed under the GNU GPL.
LLS support was contributed by Jochen Bartl.
