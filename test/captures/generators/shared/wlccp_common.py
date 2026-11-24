# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import struct
def csum(b):
    if len(b)%2: b+=b'\0'
    s=sum(struct.unpack('!%dH'%(len(b)//2),b)); s=(s>>16)+(s&0xffff); s+=s>>16
    return (~s)&0xffff
def udp_frame(payload, sport, dport, src='192.0.2.1', dst='192.0.2.2'):
    import socket
    udp=struct.pack('!HHHH',sport,dport,8+len(payload),0)+payload
    ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(udp),1,0,64,17,0,socket.inet_aton(src),socket.inet_aton(dst))
    ip=ip[:10]+struct.pack('!H',csum(ip))+ip[12:]
    eth=b'\x02\x00\x00\x00\x00\x02'+b'\x02\x00\x00\x00\x00\x01'+b'\x08\x00'
    return eth+ip+udp
def eth_frame(payload, ethertype):
    return b'\x02\x00\x00\x00\x00\x02'+b'\x02\x00\x00\x00\x00\x01'+struct.pack('!H',ethertype)+payload
def write_pcap(name, frames, linktype=1):
    with open(name,'wb') as f:
        f.write(struct.pack('<IHHiIII',0xa1b2c3d4,2,4,0,0,262144,linktype))
        for i,fr in enumerate(frames):
            f.write(struct.pack('<IIII',i,0,len(fr),len(fr))); f.write(fr)
