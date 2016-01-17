Regression Tests
================

This file describe regression tests to use with
[UTscapy](http://www.secdev.org/projects/UTscapy). Contribute yours!

```
% Regression tests for Scapy

# More informations at http://www.secdev.org/projects/UTscapy/
# $Id: regression.uts,v 1.3 2006/04/29 13:51:54 pbi Exp $

############
############
+ Informations on Scapy

= Get conf
conf

= List layers
ls()

= List commands
lsc()

= Configuration
conf.debug_dissect=1

############
############
+ Basic tests

* Those test are here mainly to check nothing has been broken
* and to catch Exceptions

= Building some packets packet
IP()/TCP()
Ether()/IP()/UDP()/NTP()
Dot11()/LLC()/SNAP()/IP()/TCP()/"XXX"
IP(ttl=25)/TCP(sport=12, dport=42)

= Manipulating some packets
a=IP(ttl=4)/TCP()
a.ttl
a.ttl=10
del(a.ttl)
a.ttl
TCP in a
a[TCP]
a[TCP].dport=[80,443]
a
a=3


= Checking overloads
a=Ether()/IP()/TCP()
a.proto
_ == 6


= sprintf() function
a=Ether()/IP()/IP(ttl=4)/UDP()/NTP()
a.sprintf("%type% %IP.ttl% %#05xr,UDP.sport% %IP:2.ttl%")
_ in [[|'0x800 64 0x07b 4', 'IPv4 64 0x07b 4']]


= sprintf() function 
* This test is on the conditionnal substring feature of <tt>sprintf()</tt>
a=Dot11()/LLC()/SNAP()/IP()/TCP()
a.sprintf("{IP:{TCP:flags=%TCP.flags%}{UDP:port=%UDP.ports%} %IP.src%}")
_ == 'flags=S 127.0.0.1'


= haslayer function
x=IP(id=1)/ISAKMP_payload_SA(prop=ISAKMP_payload_SA(prop=IP()/ICMP()))/TCP()
TCP in x, ICMP in x, IP in x, UDP in x
_ == (True,True,True,False)

= getlayer function
x=IP(id=1)/ISAKMP_payload_SA(prop=IP(id=2)/UDP(dport=1))/IP(id=3)/UDP(dport=2)
x[IP]
x[IP:2]
x[IP:3]
x[IP:4]
x[UDP]
x[UDP:1]
x[UDP:2]
x[IP].id == 1 and x[IP:2].id == 2 and x[IP:3].id == 3 and \
 x[UDP].dport == 1 and x[UDP:2].dport == 2 and x[UDP:3] is None

= equality
w=Ether()/IP()/UDP(dport=53)
x=Ether()/IP(dst="127.0.0.1")/UDP()
y=Ether()/IP()/UDP(dport=4)
z=Ether()/IP()/UDP()/NTP()
t=Ether()/IP()/TCP()
x==y, x==z, x==t, y==z, y==t, z==t, w==x
_ == (False, False, False, False, False, False, True)


############
############
+ Tests on FieldLenField

= Creation of a layer with FieldLenField
class TestFLenF(Packet):
    name = "test"
    fields_desc = [[|FieldLenField("len", None, "str", "B"),
                    StrLenField("str", "default", "len", shift=1) ]]

= Assembly of an empty packet
TestFLenF()
str(_)
_ == "\x08default"

= Assembly of non empty packet
TestFLenF(str="123")
str(_)
_ == "\x04123"

= Disassembly
TestFLenF("\x04ABCDEFGHIJKL")
_
_.len == 4 and _.str == "ABC" and Raw in _

############
############
+ Tests on FieldListField

= Creation of a layer
class TestFLF(Packet):
    name="test"
    fields_desc = [[|FieldLenField("len", None, "lst", "B"),
                    FieldListField("lst", None, IntField("elt",0), "len")
                   ]]

= Assembly of an empty packet
a = TestFLF()
str(a)

= Assembly of a non-empty packet
a = TestFLF()
a.lst = [7,65539]
ls(a)
str(a)
_ == struct.pack("!BII", 2,7,65539)

= Disassemble
TestFLF("\x00\x11\x12")
assert(_.len == 0 and Raw in _ and _[Raw].load == "\x11\x12")
TestFLF(struct.pack("!BIII",3,1234,2345,12345678))
assert(_.len == 3 and _.lst == [1234,2345,12345678])

= Manipulate
a = TestFLF(lst=[4])
str(a)
assert(_ == "\x01\x00\x00\x00\x04")
a.lst.append(1234)
TestFLF(str(a))
a.show2()
a.len=7
str(a)
assert(_ == "\x07\x00\x00\x00\x04\x00\x00\x04\xd2")
a.len=2
a.lst=[1,2,3,4,5]
TestFLF(str(a))
assert(Raw in _ and _[Raw].load == '\x00\x00\x00\x03\x00\x00\x00\x04\x00\x00\x00\x05') 


############
############
+ PacketListField tests

= Create a layer
class TestPLF(Packet):
    name="test"
    fields_desc=[[|FieldLenField("len", None, "plist"),
                  PacketListField("plist", []], IP, "len",) ]

= Test the PacketListField assembly
x=TestPLF()
str(x)
_ == "\x00\x00"

= Test the PacketListField assembly 2
x=TestPLF()
x.plist=[[IP()/TCP(),|IP()/UDP()]]
str(x)
_.startswith('\x00\x02E')

= Test disassembly
x=TestPLF(plist=[[IP()/TCP(seq=1234567),|IP()/UDP()]])
TestPLF(str(x))
_.show()
IP in _ and TCP in _ and UDP in _ and _[TCP].seq == 1234567

= Nested PacketListField
y=IP()/TCP(seq=111111)/TestPLF(plist=[IP()/TCP(seq=222222),IP()/UDP()])
TestPLF(plist=[y,IP()/TCP(seq=333333)])
_.show()
IP in _ and TCP in _ and UDP in _ and _[TCP].seq == 111111 and _[TCP:2].seq==222222 and _[TCP:3].seq == 333333


############
############
+ ISAKMP transforms test

= ISAKMP creation

p=IP(dst='10.0.0.1')/UDP()/ISAKMP()/ISAKMP_payload_SA(prop=ISAKMP_payload_Proposal(trans=ISAKMP_payload_Transform(transforms=[[('Encryption',|'AES-CBC'), ('Hash', 'MD5'), ('Authentication', 'PSK'), ('GroupDesc', '1536MODPgr'), ('KeyLength', 256), ('LifeType', 'Seconds'), ('LifeDuration', 86400L)]])/ISAKMP_payload_Transform(res2=12345,transforms=[[('Encryption',|'3DES-CBC'), ('Hash', 'SHA'), ('Authentication', 'PSK'), ('GroupDesc', '1024MODPgr'), ('LifeType', 'Seconds'), ('LifeDuration', 86400L)]])))
p.show()
p


= ISAKMP manipulation
p[ISAKMP_payload_Transform:2]
_.res2 == 12345

= ISAKMP assembly
hexdump(p)
str(p) == "E\x00\x00\x96\x00\x01\x00\x00@\x11\xa7\x9f\xc0\xa8\x08\x0e\n\x00\x00\x01\x01\xf4\x01\xf4\x00\x82\xbf\x1e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00z\x00\x00\x00^\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00R\x01\x01\x00\x00\x03\x00\x00'\x00\x01\x00\x00\x80\x01\x00\x07\x80\x02\x00\x01\x80\x03\x00\x01\x80\x04\x00\x05\x80\x0e\x01\x00\x80\x0b\x00\x01\x00\x0c\x00\x03\x01Q\x80\x00\x00\x00#\x00\x0109\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\x00\x01\x80\x04\x00\x02\x80\x0b\x00\x01\x00\x0c\x00\x03\x01Q\x80"


= ISAKMP disassembly
q=IP(str(p))
q.show()
q[ISAKMP_payload_Transform:2]
_.res2 == 12345



############
############
+ Dot11 tests


= WEP tests
conf.wepkey = "ABCDEFGH"
str(Dot11WEP()/LLC()/SNAP()/IP()/TCP(seq=12345678))
assert(_ == '\x00\x00\x00\x00\x1e\xafK5G\x94\xd4m\x81\xdav\xd4,c\xf1\xfe{\xfc\xba\xd6;T\x93\xd0\t\xdb\xfc\xa5\xb9\x85\xce\x05b\x1cC\x10\xd7p\xde22&\xf0\xbcUS\x99\x83Z\\D\xa6')
Dot11WEP(_)
assert(TCP in _ and _[TCP].seq == 12345678)


############
############
+ Network tests

* Those tests need network access

= Sending and receiving an ICMP
x=sr1(IP(dst="www.apple.com")/ICMP(),timeout=3)
x
x is not None and ICMP in x and x[ICMP].type == 0

= DNS request
* A possible cause of failure could be that the open DNS (147.210.18.138)
* is not reachable or down.
dns_ans = sr1(IP(dst="147.210.18.138")/UDP()/DNS(rd=1,qd=DNSQR(qname="www.slashdot.com")))
dns_ans



############
############
+ More complex tests

= Implicit logic
a=IP(ttl=(5,10))/TCP(dport=[80,443])
[[p|for p in a]]
len(_) == 12

= Invalid syntax
* This test will fail.
* Don't worry about this.
sr(IP(ttl=3)/TCP(dport=2)),timeout=3)



############
############
+ Real usages

= Port scan
ans,unans=sr(IP(dst="www.google.com/30")/TCP(dport=[80,443]),timeout=2)
ans.make_table(lambda (s,r): (s.dst, s.dport, r.sprintf("{TCP:%TCP.flags%}{ICMP:%ICMP.code%}")))

= Traceroute function
* Let's test traceroute
traceroute("www.slashdot.org")
ans,unans=_

= Result manipulation
ans.nsummary()
s,r=ans[0]
s.show()
s.show(2)

= DNS packet manipulation
* We have to recalculate IP and UDP length because
* DNS is not able to reassemble correctly
dns_ans.show()
del(dns_ans[IP].len)
del(dns_ans[UDP].len)
dns_ans.show2()
dns_ans[DNS].an.show()
DNS in IP(str(dns_ans))

= Arping
* This test assumes the local network is a /24. This is bad.
conf.route.route("0.0.0.0")[2]
arping(_+"/24")


= Double Encapsulated Packets

* The following would verify whether a packet is able to pass through a switch between two machines which is programmed to prohibit double encapsulated packets

scapy>> sendp(Ether(dst="<destination MAC>")/Dot1Q(vlan=<first encapsulated VLAN ID>)/Dot1Q(vlan=<second encapsulated VLAN ID>)/IP(dst="<destination IP>")/ICMP())
```
