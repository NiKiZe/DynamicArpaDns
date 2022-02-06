#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
from ipaddress import ip_address
from dnslib.dns import DNSRecord

from DynamicArpaDns import Ip6Arpa


class TestDynamicArpaDns(unittest.TestCase):
    resolver = None

    def get_resolver(self):
        if self.resolver is None:
            map = ["2001:8b8:6::/64,cli6.example.com"]
            self.resolver = Ip6Arpa(map, "cli.ns.example.com", "2001:8b8::53", "60s")
        return self.resolver

    def get_arpa_ip(self, qname, qtype="PTR"):
        resolver = self.get_resolver()
        q = DNSRecord.question(qname, qtype)
        return resolver.get_arpa_ip(q.q.qname)

    def assertArpa(self, expected, arpa):
        self.assertEqual(ip_address(expected), self.get_arpa_ip(arpa))

    def test_caseInsensitiveMatchSuffix(self):
        q = DNSRecord.question("test.example.Com", "ANY")
        self.assertTrue(q.q.qname.matchSuffix("example.Com"))
        self.assertTrue(q.q.qname.matchSuffix("example.com"))

    def test_arpa(self):
        # long v6 address
        self.assertArpa(
            "2001:8bd:6::dcba:4321",
            "1.2.3.4.a.b.c.d.0.0.0.0.0.0.0.0.0.0.0.0.6.0.0.0.d.b.8.0.1.0.0.2.ip6.arpa.",
        )
        # short v6 address
        self.assertArpa(
            "2001:8bd:6::1",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.0.0.0.d.b.8.0.1.0.0.2.ip6.arpa.",
        )
        # v4 address
        self.assertArpa("192.0.2.3", "3.2.0.192.in-addr.arpa.")
        # invalid
        self.assertEqual(None, self.get_arpa_ip("x.arpa."))
        # missmatch v6 case
        self.assertArpa(
            "2001:8bd:6::1",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.0.0.0.d.b.8.0.1.0.0.2.Ip6.ARpa.",
        )
        # missmatch v4 case
        self.assertArpa("192.0.2.3", "3.2.0.192.in-addR.arPa.")

    # Test convert to and from arpa both v4 and v6
    # Test non correct number of parts for v4 and v6
