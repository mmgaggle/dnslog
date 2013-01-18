#!/usr/bin/env python
import argparse, signal, logging, pycassa

# supress annoying scapy ipv6 gateway warning
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

parser = argparse.ArgumentParser(description='Monitor and log DNS traffic.')
parser.add_argument('--host', action='store', dest='host', default='127.0.0.1',
                    help='cassandra hostname')
parser.add_argument('--port', action='store', dest='port', default=9160,
                    help='cassandra port')
parser.add_argument('--interface', action='store', dest='interface',
                    help='interface to sniff')
parser.add_argument('--verbose', action='store_true', dest='verbose')

args = parser.parse_args()
host = args.host
port = args.port
interface = args.interface
verbose = args.verbose

c = host + ":" + port 
connect = [c]
print " [+] connecting to cassandra backend"

from pycassa.pool import ConnectionPool
pool = ConnectionPool('dns_query_count', connect)

from pycassa.columnfamily import ColumnFamily
col_fam = pycassa.ColumnFamily(pool, 'counters')

# Capture interrupt signal and cleanup before exiting
def signal_handler(signal, frame):

    print " [+] stopping sniffer"
    sys.exit(0)

def dns_monitor_callback(pkt):
    if DNS in pkt:
        if verbose:
            print " [v] dns qname - " + pkt.qd.qname
        return col_fam.add('dns',str(pkt.qd.qname), 1)

# Capture CTRL-C
signal.signal(signal.SIGINT, signal_handler)

print " [+] sniffing dns traffic on " + interface
sniff(prn=dns_monitor_callback, filter="port 53", store=0, iface=interface)

