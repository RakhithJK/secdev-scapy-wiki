Wish list for new layers
========================

Layers for the following protocols haven't been implemented yet for
Scapy, but were nice to have:

- [ISL](http://en.wikipedia.org/wiki/Cisco_Inter-Switch_Link):
    Inter-Switch Link Protocol ([yersinia](http://www.yersinia.net/)).
- [CIPSO](http://lwn.net/Articles/204905/): Commercial Internet
    Security
    Option. ([IETF-draft v2.2](http://netlabel.sourceforge.net/files/draft-ietf-cipso-ipsecurity-01.txt))
- [IS-IS](http://en.wikipedia.org/wiki/IS-IS): Intermediate system to
    intermediate system Routing Protocol
- [LLDP](http://en.wikipedia.org/wiki/Link_Layer_Discovery_Protocol):
    Link Layer Discovery
    Protocol. ([Wireshark](http://wiki.wireshark.org/LinkLayerDiscoveryProtocol))
- [STUN](http://en.wikipedia.org/wiki/Simple_traversal_of_UDP_over_NATs):
    Simple Traversal of UDP Through Network Address
    Translators. ([RFC 3489](http://www.faqs.org/rfcs/rfc3489.html))

Feel free to add your suggestions. Commonly used UDP or Layer 2 protocols with open specifications would be a good idea. Please check if the layer is really missing (, [community page](:community)) and provide a link to the specification (or an open source implementaion) if you can.

And keep in mind that we do not have a TCP implementation in Scapy, so layers for HTTP, SMTP, FTP, etc. probably won't make much sense.
