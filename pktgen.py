#! /usr/bin/env python

import argparse
import sys
import random

from faker import Faker
from scapy.all import *


class PacketGenerator(object):
    def __init__(self, tcpcount, udpcount, httpcount, icmpcount, dnscount):
        self.tcpcnt = tcpcount
        self.udpcnt = udpcount
        self.httpcnt = httpcount
        self.icmpcnt = icmpcount
        self.dnscnt = dnscount
        self.packets = self.genPackets()

    def buildEther(self):
        return fuzz(Ether(dst=str(Faker().mac_address()),
                          src=str(Faker().mac_address())))

    def buildIP(self, ipv4=True):

        def buildIPv4():
            return fuzz(IP(version=4, src=str(RandIP()), dst=str(RandIP())))

        def buildIPv6():
            return fuzz(IPv6(version=6, src=str(RandIP6()), dst=str(RandIP6())))

        if ipv4:
            return buildIPv4()
        else:
            return buildIPv6()

    def buildTCP(self, sport=None, dport=None):
        if sport and dport:
            return fuzz(TCP(sport=sport, dport=dport))
        else:
            return fuzz(TCP(sport=int(RandShort()), dport=int(RandShort())))

    def buildUDP(self, sport=None, dport=None):
        if sport and dport:
            return fuzz(UDP(sport=sport, dport=dport))
        else:
            return fuzz(UDP(sport=int(RandShort()), dport=int(RandShort())))

    def buildICMP(self):
        return fuzz(ICMP())

    def buildHTTP(self, request=True):

        def buildHTTPRequest():

            def RandMethod():
                METHODS = ["OPTIONS", "HEAD", "GET", "POST",
                           "PUT", "DELETE", "TRACE", "CONNECT"]
                return random.choice(METHODS)

            def RandPath():
                if random.choice([False, True, False]):
                    return '/{0}/{1}{2}'.format(str(Faker().uri_path()),
                                                str(Faker().uri_page()),
                                                str(Faker().uri_extension()))
                else:
                    return '/{0}{1}'.format(str(Faker().uri_page()),
                                            str(Faker().uri_extension()))

            def RandDomain():
                if random.choice([False, True, False]):
                    return str(Faker().domain_name(2))
                else:
                    return str(Faker().domain_name())

            return '{0} {1} HTTP/1.1\r\nHost: {2}\r\n\r\n'.format(RandMethod(),
                                                                  RandPath(),
                                                                  RandDomain())

        def buildHTTPResponse():

            def RandResp():
                RESPONSES = ['200 OK\r\n\r\n' + str(RandBin()),
                             '201 Created\r\n\r\n',
                             '202 Accepted\r\n\r\n',
                             '204 No Content\r\n\r\n',
                             ('301 Moved Permanently\r\nlocation: ' +
                              str(Faker().url() + '\r\n\r\n')),
                             ('302 Found\r\nlocation: ' +
                              str(Faker().url() + '\r\n\r\n')),
                             '400 Bad Request\r\n\r\n',
                             '401 Unauthorized\r\n\r\n',
                             '403 Forbidden\r\n\r\n',
                             '404 Not Found\r\n\r\n',
                             '418 Im a teapot\r\n\r\n',
                             '500 Internal Server Error\r\n\r\n',
                             '503 Service Unavailable\r\n\r\n',
                             '504 Gateway Timeout\r\n\r\n']
                return random.choice(RESPONSES)

            return 'HTTP/1.1 {0}'.format(RandResp())

        if request:
            return (TCP(sport=int(RandShort()), dport=80) / buildHTTPRequest())
        else:
            return (TCP(sport=80, dport=int(RandShort())) / buildHTTPResponse())

    def buildDNS(self, request=True):

        def buildDNSRequest():

            def RandRecord():
                RECORDS = ["A", "CNAME", "MX", "NS", "PTR", "TXT"]
                return random.choice(RECORDS)

            def RandClass():
                return random.choice(["IN", "ANY"])

            def RandDomain():
                if random.choice([False, True, False]):
                    return str(Faker().domain_name(2))
                else:
                    return str(Faker().domain_name())

            return DNS(qd=DNSQR(qname=RandDomain(),
                                qtype=RandRecord(),
                                qclass=RandClass()))

        def buildDNSResponse():
            dnsquery = buildDNSRequest()
            dnsquery.an = DNSRR(rrname=dnsquery.qd.qname,
                                type=dnsquery.qd.qtype,
                                rclass=dnsquery.qd.qclass,
                                ttl=random.randint(0, 604800),
                                rdata=str(RandIP()))
            return dnsquery

        if request:
            return (UDP(sport=int(RandShort()), dport=53) / buildDNSRequest())
        else:
            return (UDP(sport=53, dport=int(RandShort())) / buildDNSResponse())

    def genPackets(self):
        pkts = []
        for i in range(self.tcpcnt):
            IPBool = random.choice([True, False])
            pkts.append(self.buildEther() / self.buildIP(IPBool) /
                        self.buildTCP())
        for i in range(self.udpcnt):
            IPBool = random.choice([True, False])
            pkts.append(self.buildEther() / self.buildIP(IPBool) /
                        self.buildUDP())
        for i in range(self.httpcnt):
            IPBool = random.choice([True, False])
            HTTPBool = random.choice([True, False])
            pkts.append(self.buildEther() / self.buildIP(IPBool) /
                        self.buildHTTP(HTTPBool))
        for i in range(self.icmpcnt):
            IPBool = random.choice([True, False])
            pkts.append(self.buildEther() / self.buildIP(IPBool) /
                        self.buildICMP())
        for i in range(self.dnscnt):
            IPBool = random.choice([True, False])
            DNSBool = random.choice([True, False])
            pkts.append(self.buildEther() / self.buildIP(IPBool) /
                        self.buildDNS(DNSBool))
        random.shuffle(pkts)
        return pkts


def dumpPackets(packets, o):
    for p in packets:
        hexdump(p)
        print ''


def showPackets(packets, o):
    for p in packets:
        print p.show()


def summaryPackets(packets, o):
    for p in packets:
        print p.summary()


def writePcap(packets, o):
    pktWriter = PcapWriter(o, linktype=1, append=True)
    for p in packets:
        pktWriter.write(p)
    pktWriter.close()


def quiz(pkt):
    p = pkt[0]
    hexdump(p)
    print ''
    if p[2].name == 'ICMP':
        fields = [(p[0].dst, 'destination MAC address'),
                  (p[0].src, 'source MAC address'),
                  (p[1].src, 'source IP address'),
                  (p[1].dst, 'destination IP address'),
                  (p[2].name, 'protocol')]
    else:
        fields = [(p[0].dst, 'destination MAC address'),
                  (p[0].src, 'source MAC address'),
                  (p[1].src, 'source IP address'),
                  (p[1].dst, 'destination IP address'),
                  (p[2].name, 'protocol'),
                  (p[2].sport, 'source port'),
                  (p[2].dport, 'destination port')]
    i = random.choice(fields)
    answer = raw_input('What is the ' + i[1] + ' in this packet? ')
    if str(i[0]).upper() == answer.upper():
        print 'Correct! {0} is the {1} in this packet.\n'.format(i[0], i[1])
    else:
        print 'Incorrect. {0} is the {1} in this packet.\n'.format(i[0], i[1])


def main(args):
    switch = {
        'dump': dumpPackets,
        'show': showPackets,
        'summary': summaryPackets,
        'write': writePcap
    }
    if args.ACTION == 'quiz':
        ask = True
        while ask:
            r = random.choice(['10000', '01000', '00100', '00010', '00001'])
            args.tcp = int(r[0])
            args.udp = int(r[1])
            args.http = int(r[2])
            args.icmp = int(r[3])
            args.dns = int(r[4])
            packets = PacketGenerator(args.tcp, args.udp, args.http,
                                      args.icmp, args.dns)
            quiz(packets.packets)
            print ''
            resp = raw_input('Would you like another question? [Y/n]: ')
            if resp and resp[0].upper() == 'N':
                ask = False
        sys.exit(0)
    elif args.ACTION not in switch:
        sys.stderr.write('{0} is not a valid action'.format(args.ACTION))
        sys.exit(1)
    else:
        func = switch[args.ACTION]
        if args.random:
            args.tcp = random.randint(10, 100)
            args.udp = random.randint(10, 100)
            args.http = random.randint(10, 100)
            args.icmp = random.randint(10, 100)
            args.dns = random.randint(10, 100)
        packets = PacketGenerator(args.tcp, args.udp, args.http,
                                  args.icmp, args.dns)
        func(packets.packets, args.output)
        sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate Packets')
    parser.add_argument('ACTION', type=str,
                        help='dump, show, summary, write, or quiz')
    parser.add_argument('-t', '--tcp', type=int, default=0,
                        help='number of TCP packets to generate')
    parser.add_argument('-u', '--udp', type=int, default=0,
                        help='number of UDP packets to generate')
    parser.add_argument('-p', '--http', type=int, default=0,
                        help='number of HTTP packets to generate')
    parser.add_argument('-i', '--icmp', type=int, default=0,
                        help='number of ICMP packets to generate')
    parser.add_argument('-d', '--dns', type=int, default=0,
                        help='number of DNS packets to generate')
    parser.add_argument('-r', '--random', action='store_true',
                        help='random number of packets')
    parser.add_argument('-o', '--output', type=str, help='Save to pcap')
    main(parser.parse_args())
