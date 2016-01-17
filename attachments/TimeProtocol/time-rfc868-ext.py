"""
Time protocol (RFC 868) extension for Scapy <http://www.secdev.org/scapy>

Copyright (c) 2008 Dirk Loss  :  mail dirk-loss de

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
"""

from scapy import *

EXT_VERSION = "v0.2"

# Seconds between Unix epoch (1970-01-01) and NTP epoch (1900-01-01)
EPOCH1900_DIFF = 2208988800

class IntTimeField(IntField):
    """ Human readable timestamp (seconds since midnight 1900-01-01, as in RFC 868) """
    def i2h(self, pkt, x):
        return time.ctime(x - EPOCH1900_DIFF)

class TIME_Req(Packet):
    name = "TIME protocol (RFC 868) request"
    # TIME requests do not have to have a payload, but correctly dissecting 
    # UDP datagrams without payload is hard 
    fields_desc = [ StrField("request", "\n") ]
    
class TIME_Resp(Packet):
    name = "TIME protocol (RFC 868) response"    
    fields_desc = [ IntTimeField("time_stamp", IntAutoTime(base=-EPOCH1900_DIFF))]
    
    def answers(self, other):
        return isinstance(other, TIME_Req)


class TIME_am(AnsweringMachine):
    function_name="TIME_server"
    filter = "udp port 37"

    def is_request(self, req):
        # We cannot use 'isinstance(req, TIME_Req)' here because the request
        # may not have a payload and thus would not be decoded as TIME_Req 
        return (req.haslayer(UDP) and req[UDP].dport == 37)
    
    def make_reply(self, req):
        timestamp = struct.pack("!I", int(time.time() + EPOCH1900_DIFF))
        ip = req.getlayer(IP)
        return IP(dst=ip.src, src=ip.dst)/UDP(dport=ip.sport,sport=ip.dport)/Raw(timestamp)


# Overloading the source port makes sure that we do not interfere with UDP's default (DNS)    
bind_layers(UDP, TIME_Req, dport=37, sport=3737)
bind_layers(UDP, TIME_Resp, sport=37)

# Some RFC 868 time servers: time-a.nist.gov, time-nw.nist.gov, nist.expertsmi.com
# A list is available at <http://tf.nist.gov/tf-cgi/servers.cgi>  

if __name__ == "__main__":
    interact(mydict=globals(), mybanner="TIME protocol (RFC 868) extension %s" % EXT_VERSION)
