#!/usr/bin/env python
import pycassa
from scapy.all import *

from pycassa.pool import ConnectionPool
pool = ConnectionPool('dns_query_count', ['localhost:9160'])

from pycassa.columnfamily import ColumnFamily
col_fam = pycassa.ColumnFamily(pool, 'counters')

def dns_monitor_callback(pkt):
  if DNS in pkt:
    return col_fam.add('dns',str(pkt.qd.qname), 1)

sniff(prn=dns_monitor_callback, filter="udp and port 53", store=0)
