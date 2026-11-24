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
def udp(payload, sport=1024, dport=9201, src='192.0.2.1', dst='192.0.2.2'):
    import socket
    u=struct.pack('!HHHH',sport,dport,8+len(payload),0)+payload
    ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(u),1,0,64,17,0,socket.inet_aton(src),socket.inet_aton(dst))
    ip=ip[:10]+struct.pack('!H',csum(ip))+ip[12:]
    return b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00'+ip+u
def eth(ethertype, payload):
    return b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01'+struct.pack('!H',ethertype)+payload
def write(name, frames, linktype=1):
    with open(name,'wb') as f:
        f.write(struct.pack('<IHHiIII',0xa1b2c3d4,2,4,0,0,262144,linktype))
        for i,fr in enumerate(frames):
            f.write(struct.pack('<IIII',i+1,0,len(fr),len(fr))); f.write(fr)
