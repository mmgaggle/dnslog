DESCRIPTION
===========

DNS logging daemon that increments a Cassandra DNS qname counter column for each
DNS query recieved. It is intended to be ran on a server connected to a SPAN
switch port that mirrors authoritative DNS server traffic. This could be useful
for billing or general monitoring.

DIAGRAM
=======

![Diagram](dnslog/blob/master/dnslog.png "DNSLOG")
