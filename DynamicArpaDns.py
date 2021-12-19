# -*- coding: utf-8 -*-
# Copyright 2021 Christian Nilsson
# https://github.com/NiKiZe/DynamicArpaDns

from __future__ import print_function

from dnslib import RR,QTYPE,RCODE,parse_time
from dnslib import A,NS,CNAME,SOA,PTR,MX,TXT,AAAA
from dnslib.label import DNSLabel
from dnslib.server import DNSServer,DNSHandler,BaseResolver,DNSLogger

from ipaddress import IPv4Address, IPv6Address, ip_address

class Ip6Arpa(BaseResolver):
    """
        Example dynamic resolver.
    """
    def __init__(self, mapings, ns, address, ttl):
        self.nameserver = ns
        self.address = address
        self.ttl = parse_time(ttl)
        nsip = ip_address(address)
        self.nsrr = self.get_A(self.nameserver, nsip)

        self.map = {}
        for m in mapings:
            ip,_,origin = m.partition(',')
            print("map: %s %s %s" % (ip, origin, DNSLabel(origin)))
            self.map[ip] = DNSLabel(origin)

    def get_A(self, name, ip):
        is6 = ip.version == 6
        return RR(name, QTYPE.AAAA if is6 else QTYPE.A, ttl=self.ttl,
                        rdata=AAAA(str(ip)) if is6 else A(str(ip)))

    def get_map_from_ip(self, ipstr):
        return next((i for i in self.map.items() if ipstr.startswith(i[0])), None)

    def get_map_from_origin(self, qname):
        return next(((o,i) for (i,o) in self.map.items() if qname.matchSuffix(o)), None)

    def get_arpa_ip(self, qname):
        if qname.matchSuffix('in-addr.arpa.'):
            parts = str(qname.stripSuffix('in-addr.arpa.'))[:-1].split('.')
            ipstr = '.'.join(reversed(parts))
            return IPv4Address(ipstr)

        elif qname.matchSuffix('ip6.arpa.'):
            parts = str(qname.stripSuffix('ip6.arpa.'))[:-1].split('.')
            # do some grouping and joining to get a v6 address string
            ipstr = ':'.join(map(''.join, zip(*[reversed(parts)]*4)))
            return IPv6Address(ipstr)

        return None

    def resolve(self, request, handler):
        reply = request.reply()
        q = request.q
        qname = q.qname

        qtype = q.qtype
        is_arpa = qname.matchSuffix('arpa.')
        is_ptr_arpa = is_arpa and qtype in [QTYPE.PTR, QTYPE.ANY]
        ip_ptr = self.get_arpa_ip(qname) if is_ptr_arpa else None
        qnoriginip = self.get_map_from_origin(qname) if [QTYPE.A, QTYPE.AAAA, QTYPE.ANY] else None

        print(" query: ", handler.client_address, QTYPE[qtype], qtype, qname)
        # TODO SOA and NS needs to respond to closest match, not qname
        if qtype == QTYPE.SOA:
            s=SOA(
                mname=self.nameserver,  # primary name server
                rname="hostmaster.domain",  # email of the domain administrator
                times=(
                    2021121901,  # serial number
                    60 * 60 * 1,  # refresh
                    60 * 60 * 3,  # retry
                    60 * 60 * 24,  # expire
                    60 * 60 * 1,  # minimum
                )
            )
            reply.add_answer(RR(qname, QTYPE.SOA, ttl=60 * 60 * 24, rdata=s))

        # TODO A/AAAA for self.nsrr
        # TODO only respond with ns and SOA for known domains
        elif qtype == QTYPE.NS:
            reply.add_answer(RR(qname, QTYPE.NS, ttl=self.ttl, rdata=NS(self.nameserver)))
            reply.add_ar(self.nsrr)

        elif is_ptr_arpa and ip_ptr:
            ipstr = str(ip_ptr)
            is6 = ip_ptr.version == 6
            iporigin = self.get_map_from_ip(ipstr)
            if iporigin:
                ipmatch,origin = iporigin
                dstr = "i%i%s" % (ip_ptr.version, ipstr[len(ipmatch):].replace(':' if is6 else '.', '-'))
                print("  ptr i%i %s %s match: %s origin: %s" % (ip_ptr.version, ipstr, dstr, ipmatch, origin))
                reply.add_answer(RR(qname, QTYPE.PTR, ttl=self.ttl, rdata=PTR(origin.add(dstr))))
            else:
                print("  unknown origin for ptr i%i %s" % (ip_ptr.version, ipstr))
                reply.header.rcode = RCODE.NXDOMAIN

        elif qnoriginip and str(qname)[:2] in ['i6', 'i4']:
            # in theory the i6/i4 prefix dont matter
            ippfx = qnoriginip[1]
            qn = str(qname.stripSuffix(qnoriginip[0]))
            is6 = ':' in ippfx
            dip = ippfx + qn[2:-1].replace('-', ':' if is6 else '.')
            print(qname, qnoriginip, dip)
            ip = ip_address(dip)
            reply.add_answer(self.get_A(qname, ip))

        else:
            reply.header.rcode = RCODE.NXDOMAIN

        return reply

if __name__ == '__main__':

    import argparse,time

    p = argparse.ArgumentParser(description="Dynamic arpa DNS helper")
    p.add_argument("--map","-m",action="append",required=True,
                    metavar="<ip>,<origin>",
                    help="Map ip prefix to origin domain (multiple supported)")
    p.add_argument("--ns","-n",default="ns.master",
                    metavar="<ns>",
                    help="Nameservers name (default: ns.master)")
    p.add_argument("--ttl","-t",default="60s",
                    metavar="<ttl>",
                    help="Response TTL (default: 60s)")
    p.add_argument("--port","-p",type=int,default=53,
                    metavar="<port>",
                    help="Server port (default:53)")
    p.add_argument("--address","-a",required=True,
                    metavar="<address>",
                    help="Listen address")
    p.add_argument("--udplen","-u",type=int,default=0,
                    metavar="<udplen>",
                    help="Max UDP packet length (default:0)")
    p.add_argument("--log",default="request,reply,truncated,error",
                    help="Log hooks to enable (default: +request,+reply,+truncated,+error,-recv,-send,-data)")
    p.add_argument("--log-prefix",action='store_true',default=False,
                    help="Log prefix (timestamp/handler/resolver) (default: False)")
    args = p.parse_args()

    resolver = Ip6Arpa(args.map, args.ns, args.address, args.ttl)
    logger = DNSLogger(args.log, args.log_prefix)

    print("Starting Dynamic arpa Resolver (%s:%d) [%s]" % (
                        args.address or "*",
                        args.port,
                        "UDP/TCP"))

    if args.udplen:
        DNSHandler.udplen = args.udplen

    udp_server = DNSServer(resolver,
                           port=args.port,
                           address=args.address,
                           logger=logger)
    udp_server.start_thread()

    tcp_server = DNSServer(resolver,
                           port=args.port,
                           address=args.address,
                           tcp=True,
                           logger=logger)
    tcp_server.start_thread()

    while udp_server.isAlive():
        time.sleep(1)

    # Test Ip6.ARpa (must work case insensitive)
    # Test convert to and from arpa both v4 and v6
    # Test non correct number of parts for v4 and v6
