#!/usr/bin/python
#-*- coding:utf-8 -*-
"""
 @author: Rémi Oudin <oudin@crans.org>
 @date: 13/04/2017

 This is a simple PCAP file generator.
 It can generate tcp/udp files.
"""


import scapy.all as scapy
import random
import argparse


def make_mac_hdr(src_mac=None, dst_mac=None, ethtype=None, **kwargs):
    """ Creates the mac header."""
    hdr = scapy.Ether()
    if src_mac:
        hdr.src = src_mac
    if dst_mac:
        hdr.dst = dst_mac
    if ethtype:
        hdr.type = ethtype
    return hdr

def make_ip_hdr(src_ip=None, dst_ip=None, ttl=None, **kwargs):
    """ Creates the IP layer header."""
    hdr = scapy.IP()
    if src_ip:
        hdr[scapy.IP].src = src_ip.replace("110", str(random.randrange(0,22)))
    if dst_ip:
        hdr[scapy.IP].dst = dst_ip
    if ttl:
        hdr[scapy.IP].ttl = ttl
    return hdr

def make_udp_hdr(sport=None, dport=None, **kwargs):
    """ Create the UDP headers."""
    hdr = scapy.UDP()
    if sport:
        hdr[scapy.UDP].sport = sport
    if dport:
        hdr[scapy.UDP].dport = dport
    return hdr


def make_ip_pkt(pkt_len=64, **kwargs):
    """ Create the IP packet of length pkt_len."""
    if pkt_len < 64:
        pkt_len = 64
    pkt = make_mac_hdr(**kwargs)/make_ip_hdr(**kwargs)/payload(pkt_len-34)
    return pkt


def make_udp_pkt(pkt_len=64, **kwargs):
    """ Create the UDP packet of length pkt_len."""
    if pkt_len < 64:
        pkt_len = 64
    pkt = make_mac_hdr(**kwargs)/make_ip_hdr(pky_len=pkt_len,**kwargs)/\
          make_udp_hdr(**kwargs)/payload(pkt_len - 42)
    return pkt


def payload(length):
    """ Generate the payload of the packet."""
    default = "you lost the game "
    def_len = len(default)
    repeat = length / def_len
    msg = default * repeat + "0" * (length - def_len*repeat)
    return msg



if __name__ == "__main__":
    PARSER = argparse.ArgumentParser(description="Simple pcap file generator")
    PARSER.add_argument(
        "--src_mac",
        type=str,
        action="store",
        metavar="SRC_MAC",
        default="77:61:6B:65:75:70",
        help="The source mac to write in the packet"
    )
    PARSER.add_argument(
        "--dst_mac",
        type=str,
        action="store",
        metavar="DST_MAC",
        default="5C:28:5E:5E:29:2F",
        help="The destination mac to write in the packet"
    )
    PARSER.add_argument(
        "--src_ip",
        type=str,
        action="store",
        metavar="SRC_IP",
        default="71.117.105.110",
        help="The source IP to write in the packet"
    )
    PARSER.add_argument(
        "--dst_ip",
        type=str,
        action="store",
        metavar="DST_IP",
        default="110.101.115.115",
        help="The destination IP to write in the packet"
    )
    PARSER.add_argument(
        "--dport",
        type=int,
        action="store",
        metavar="DST_PORT",
        default="1337",
        help="The destination l4 port"
    )
    PARSER.add_argument(
        "--sport",
        type=int,
        action="store",
        metavar="SRC_PORT",
        default="1515",
        help="The src l4 port"
    )
    PARSER.add_argument(
        "--number",
        type=int,
        action="store",
        metavar="NUMBER",
        default=1,
        help="The number of packets to generate"
    )
    PARSER.add_argument(
        "--outfile",
        type=str,
        action="store",
        metavar="OUTFILE",
        default="output.pcap",
        help="The output file"
    )
    PARSER.add_argument(
        "--length",
        type=int,
        action="store",
        metavar="LENGTH",
        default=256,
        help="Lenght of the packet"
    )
    PARSER.add_argument(
        "--type",
        type=str,
        action="store",
        metavar="TYPE",
        default="UDP",
        help="The packet type"
    )
    PARSER.add_argument(
        "--ttl",
        type=int,
        action="store",
        metavar="TTL",
        default=17,
        help="Time to live of the packet"
    )

    ARGS = PARSER.parse_args()

    pkts = []
    if ARGS.type.lower() == "udp":
        for i in range(ARGS.number):
            pkt = make_udp_pkt(
                    dst_mac=ARGS.dst_mac, dst_ip=ARGS.dst_ip,
                    src_mac=ARGS.src_mac, src_ip=ARGS.src_ip,
                    sport=ARGS.sport, dport=ARGS.dport, ttl=ARGS.ttl,
                    pkt_len=ARGS.length)
            pkt.time = i*1e-6
            pkts.append(pkt)
    else:
        for i in range(ARGS.number):
            pkt = make_ip_pkt(
                    dst_mac=ARGS.dst_mac, dst_ip=ARGS.dst_ip,
                    src_mac=ARGS.src_mac, src_ip=ARGS.src_ip,
                    sport=ARGS.sport, dport=ARGS.dport, ttl=ARGS.ttl,
                    pkt_len=ARGS.length)
            pkt.time = i*1e-6
            pkts.append(pkt)
    scapy.wrpcap(ARGS.outfile, pkts)
