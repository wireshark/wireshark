#!/usr/bin/env python3
# Generates test/captures/mate_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic capture and configuration files for the MATE plugin
(plugins/epan/mate).

Usage: mkmate.py <outdir> [-v]
Writes mate-coverage.pcap, mate-coverage-malformed.pcap and the MATE
configuration mate_cov.mate (which has an #include of mate_cov_inc.mate;
the include path is the absolute path of <outdir>), mate_cov_inc.mate.
mate_cov_debug.mate is the same with a Debug section that writes
<outdir>/mate_debug.out.  Built with struct only.
"""
import os
import struct
import sys


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


class Cap:
    def __init__(self):
        self.frames = []
        self.t = 1700000000.0
        self.ipid = 1

    def add(self, fr, dt=0.001):
        self.t += dt
        self.frames.append((self.t, fr))
        return len(self.frames)

    def write(self, fn):
        with open(fn, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for t, fr in self.frames:
                s = int(t)
                us = int(round((t - s) * 1e6))
                f.write(struct.pack('<IIII', s, us, len(fr), len(fr)) + fr)


def eth(payload, src, dst, et=0x0800):
    return bytes([2, 0, 0, 0, 0, dst, 2, 0, 0, 0, 0, src]) + struct.pack('!H', et) + payload


def ip4(src, dst, proto, payload, ident=1):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0, src, dst)
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload


def udp_hdr(sport, dport, payload):
    return struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload


def tcp_hdr(sport, dport, seq, ack, flags, payload):
    return struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload


SYN, ACK, PSH, RST, FIN = 2, 0x10, 8, 4, 1


def A(n):
    return bytes([192, 0, 2, n])


def B(n):
    return bytes([198, 51, 100, n])


class Tcp:
    def __init__(self, cap, cip, sip, cport, sport):
        self.cap, self.cip, self.sip, self.cport, self.sport = cap, cip, sip, cport, sport
        self.cseq, self.sseq = 1000, 5000

    def fr(self, c2s, flags, data=b''):
        cap = self.cap
        cap.ipid += 1
        if c2s:
            seg = tcp_hdr(self.cport, self.sport, self.cseq, self.sseq, flags, data)
            return eth(ip4(self.cip, self.sip, 6, seg, cap.ipid), 1, 2)
        seg = tcp_hdr(self.sport, self.cport, self.sseq, self.cseq, flags, data)
        return eth(ip4(self.sip, self.cip, 6, seg, cap.ipid), 2, 1)

    def send(self, c2s, data=b'', flags=PSH | ACK, dt=0.01):
        n = self.cap.add(self.fr(c2s, flags, data), dt)
        if c2s:
            self.cseq += len(data) + (1 if flags & (SYN | FIN) else 0)
        else:
            self.sseq += len(data) + (1 if flags & (SYN | FIN) else 0)
        return n

    def handshake(self, dt=0.01):
        self.send(True, b'', SYN, dt)
        self.send(False, b'', SYN | ACK, 0.01)
        self.send(True, b'', ACK, 0.01)

    def close(self, dt=0.01):
        self.send(True, b'', FIN | ACK, dt)
        self.send(False, b'', FIN | ACK, 0.01)
        self.send(True, b'', ACK, 0.01)


def dns(idn, qr, name=b'\x03www\x07example\x04test\x00', answers=0, rcode=0):
    flags = (0x8180 if qr else 0x0100) | rcode
    h = struct.pack('!HHHHHH', idn, flags, 1, answers, 0, 0)
    q = name + struct.pack('!HH', 1, 1)
    a = b''
    for i in range(answers):
        a += b'\xc0\x0c' + struct.pack('!HHIH4s', 1, 1, 60, 4, bytes([203, 0, 113, 1 + i]))
    return h + q + a


def nbns(idn, rsp=False):
    q = b'\x20' + b'EGFDEBEEEPCACACACACACACACACACAAA' + b'\x00' + struct.pack('!HH', 0x20, 1)
    if rsp:
        return struct.pack('!HHHHHH', idn, 0x8500, 0, 1, 0, 0) + q[:-4] + struct.pack('!HHIHH4s', 0x20, 1, 300, 6, 0, A(33))
    return struct.pack('!HHHHHH', idn, 0x0110, 1, 0, 0, 0) + q


def udp4(cap, cip, sip, cport, sport, data, c2s=True, dt=0.01):
    cap.ipid += 1
    if c2s:
        return cap.add(eth(ip4(cip, sip, 17, udp_hdr(cport, sport, data), cap.ipid), 1, 2), dt)
    return cap.add(eth(ip4(sip, cip, 17, udp_hdr(sport, cport, data), cap.ipid), 2, 1), dt)


def http_req(path, host=b'www.example.test', body=b''):
    h = b'POST ' + path + b' HTTP/1.1\r\nHost: ' + host + b'\r\n'
    if body:
        h += b'Content-Type: application/octet-stream\r\nContent-Length: %d\r\n' % len(body)
    return h + b'\r\n' + body


def http_rsp(body=b'', ctype=b'application/octet-stream'):
    return (b'HTTP/1.1 200 OK\r\nContent-Type: ' + ctype + b'\r\nContent-Length: %d\r\n\r\n' % len(body)) + body


# ---------------------------------------------------------------- configuration
INC = '''// included file: transforms and the Gog
Transform add_tcp_stop {
    Match (tcp_flags_reset="True") Insert (tcp_stop="True");
    Match Strict (tcp_flags_fin="True") Insert (tcp_stop="True");
    Match Loose (tcp_nothing, tcp_start="True") Insert (tcp_open=1.5);
    Match Every (addr) Insert (seen_addr="yes");
    Insert (tcp_always=10.0.0.1);
    Match (tcp_start="True") Replace (tcp_start="True", tcp_mac=01:AB:3);
    Match (tcp_never) ;
    ;
};

Transform dns_names {
    Match (dns_resp="True", client) Replace (dns_resp="True");
    Match (host^"www") Insert (dns_www);
    Match (host$".test") Insert (dns_test);
    Match (host~"xample") Insert (dns_xample);
    Match (dns_rcode>0) Insert (dns_failed);
    Match (dns_rcode<1) Insert (dns_ok);
    Match (dns_rcode!0) Insert (dns_err);
    Match (dns_id{"0x0001"|"0x0002"|"0x0003"}) Insert (dns_low);
};

'''

INC2 = '''// second included file: Gops of DNS and NetBIOS, includes the Gogs
Gop dns_req On dns_pdu Match (addr, addr, dns_id) {
    Start (dns_resp="False");
    Stop (dns_resp="True");
    Extra (host, client, dns_rcode);
    Transform dns_names;
    ShowTree BasicTree;
    ShowTimes true;
};

Gop nbns_tx On nbns_pdu Match (addr, addr, nbid) {
    Extra (nbid, client);
};

#include %s
'''

INC3 = '''// third file (included from the second one): the Gogs
/* a block comment
   over two lines */
Gog client_ses {
    Member tcp_ses (client);
    Member dns_req (client);
    Member nbns_tx (client);
    Extra (host, client, nbid);
    Expiration 3.0;
    GopTree BasicTree;
    ShowTimes true;
};

Gog web_ses {
    Member http_tx (client);
    Member http_nodrop (client);
    Extra (client);
    Expiration 1;
    GopTree BasicTree;
    ShowTimes false;
};
'''


def main_cfg(inc_path, inc2_path, debug=None):
    dbg = ''
    if debug:
        dbg = '''Debug {
    Filename "%s";
    Level 3;
    Pdu Level 5;
    Gop Level 5;
    Gog Level 5;
};

''' % debug
    return dbg + '''// MATE configuration of the synthetic capture
Default {
    Pdu {
        DropUnassigned false;
        DiscardPduData false;
    };
    Gop {
        Expiration 5.0;
        IdleTimeout 4;
        Lifetime 100;
        DropUnassigned false;
        ShowTree PduTree;
        ShowTimes true;
    };
    Gog {
        Expiration 5.0;
        ShowTree FrameTree;
        GopTree BasicTree;
        ShowTimes true;
    };
};

#include %s

Pdu tcp_pdu Proto tcp Transport ip {
    Extract addr From ip.addr;
    Extract client From ip.src;
    Extract port From tcp.port;
    Extract tcp_start From tcp.flags.syn;
    Extract tcp_flags_reset From tcp.flags.reset;
    Extract tcp_flags_fin From tcp.flags.fin;
    Transform add_tcp_stop;
    DropUnassigned false;
};

Pdu dns_pdu Proto dns Transport udp/ip {
    Extract addr From ip.addr;
    Extract client From ip.src;
    Extract dns_id From dns.id;
    Extract dns_resp From dns.flags.response;
    Extract dns_rcode From dns.flags.rcode;
    Extract host From dns.qry.name;
    Criteria Reject Strict (dns_id="0x029a");
    LastPdu false;
};

Pdu nbns_pdu Proto nbns Transport udp/ip {
    Extract addr From ip.addr;
    Extract client From ip.src;
    Extract nbid From nbns.id;
    Criteria Accept Every (nbid);
    DropUnassigned true;
    DiscardPduData true;
};

Pdu http_pdu Proto http Transport tcp/ip {
    Payload data;
    Extract addr From ip.addr;
    Extract port From tcp.port;
    Extract client From ip.src;
    Extract http_rq From http.request.method;
    Extract http_rs From http.response.code;
    Extract http_host From http.host;
    Extract http_ctype From http.content_type;
    Extract data_len From data.len;
    Criteria Accept Loose (http_rq, http_rs);
};

Gop tcp_ses On tcp_pdu Match (addr, addr, port, port) {
    Start (tcp_start="True");
    Stop (tcp_stop="True");
    Extra (client, tcp_open);
    Expiration 2.5;
    IdleTimeout 3.0;
    Lifetime 60;
    DropUnassigned true;
    ShowTree FrameTree;
    ShowTimes true;
};

Gop http_tx On http_pdu Match (addr, addr, port, port) {
    Start (http_rq);
    Stop (http_rs);
    Extra (http_host, http_ctype, client);
    IdleTimeout 0.3;
    Lifetime 0.5;
    ShowTree NoTree;
    ShowTimes false;
};

// A second Gop on the same PDU is an error: this one uses the same PDU type
// as nothing else so it is a Gop of a PDU without Gop (see http_nodrop)
Pdu http_other Proto http Transport tcp/ip {
    Extract addr From ip.addr;
    Extract port From tcp.port;
    Extract client From ip.src;
    Extract http_rq From http.request.method;
    DropUnassigned true;
    DiscardPduData false;
    LastPdu true;
};

Gop http_nodrop On http_other Match (addr, addr, port, port) {
    Start (http_rq);
    Extra (client);
    DropUnassigned true;
    ShowTree PduTree;
};

#include %s

Done;
''' % (inc_path, inc2_path)


def build():
    cap = Cap()
    notes = []

    def note(txt):
        notes.append((len(cap.frames) + 1, txt))

    note('TCP connection 192.0.2.10 -> 198.51.100.20:80: handshake, close (tcp_ses Gop with Start SYN and Stop FIN, Gog client_ses)')
    c = Tcp(cap, A(10), B(20), 40001, 80)
    c.handshake()
    c.send(True, http_req(b'/a', body=b'x' * 40))
    c.send(False, http_rsp(b'ok'))
    c.close()
    note('A second connection of the same client, reset (Stop on RST), with an HTTP request in two segments and no response')
    c = Tcp(cap, A(10), B(20), 40002, 80)
    c.handshake(0.3)
    r = http_req(b'/b', body=b'y' * 100)
    c.send(True, r[:90], ACK | PSH)
    c.send(True, r[90:])
    c.send(False, b'', RST | ACK, 0.2)
    note('DNS query/response pairs of two clients (dns_req Gop, Gog by client): normal, NXDOMAIN, a rejected query, ID reuse, a response with no query, a query never answered')
    udp4(cap, A(10), B(30), 41000, 53, dns(1, 0), True, 0.5)
    udp4(cap, A(10), B(30), 41000, 53, dns(1, 1, answers=1), False, 0.02)
    udp4(cap, A(11), B(30), 41001, 53, dns(2, 0), True, 0.05)
    udp4(cap, A(11), B(30), 41001, 53, dns(2, 1, rcode=3), False, 0.02)
    udp4(cap, A(11), B(30), 41001, 53, dns(666, 0, name=b'\x06reject\x04test\x00'), True, 0.02)
    udp4(cap, A(11), B(30), 41001, 53, dns(3, 1, answers=2), False, 0.02)
    udp4(cap, A(10), B(30), 41000, 53, dns(1, 0), True, 0.5)
    udp4(cap, A(10), B(30), 41000, 53, dns(1, 1, answers=1), False, 0.02)
    udp4(cap, A(12), B(30), 41002, 53, dns(7, 0, name=b'\x03abc\x03net\x00'), True, 0.05)
    note('NetBIOS name queries (nbns_tx Gop without Start, only through the Gog key), after a DNS query of the same client')
    udp4(cap, A(10), B(31), 137, 137, nbns(0x10), True, 0.1)
    udp4(cap, A(10), B(31), 137, 137, nbns(0x10, True), False, 0.02)
    udp4(cap, A(40), B(31), 137, 137, nbns(0x11), True, 0.05)
    udp4(cap, A(10), B(31), 137, 137, nbns(0x12), True, 0.05)
    note('HTTP on port 80: three transactions of one client with growing gaps (Lifetime 0.5 s and IdleTimeout 0.3 s of http_tx; a Start on a released Gop starts a new one)')
    c = Tcp(cap, A(13), B(21), 42000, 80)
    c.handshake(1.0)
    for i, gap in enumerate((0.05, 0.2, 0.6, 0.35, 0.05)):
        c.send(True, http_req(b'/t%d' % i, body=b'z' * (10 + i)), PSH | ACK, gap)
        c.send(False, http_rsp(b'r' * i), PSH | ACK, 0.02)
        c.send(True, http_req(b'/u%d' % i), PSH | ACK, gap + 0.1)
    note('Frames that no Pdu configuration extracts from: ICMP, ARP-like, UDP on another port, TCP on another port (no http_pdu)')
    cap.ipid += 1
    echo = struct.pack('!BBHHH', 8, 0, 0, 1, 1) + b'ping'
    echo = echo[:2] + struct.pack('!H', csum(echo)) + echo[4:]
    cap.add(eth(ip4(A(10), B(20), 1, echo, cap.ipid), 1, 2), 0.1)
    udp4(cap, A(10), B(20), 50000, 50001, b'plain', True, 0.1)
    c = Tcp(cap, A(10), B(20), 40003, 9000)
    c.handshake(0.1)
    c.send(True, b'junk', PSH | ACK)
    note('Long gap, then the client of the first DNS query again, and a connection after the Gog expiration (new Gog, 3 s expiration)')
    udp4(cap, A(10), B(30), 41000, 53, dns(9, 0), True, 10.0)
    udp4(cap, A(10), B(30), 41000, 53, dns(9, 1, answers=1), False, 0.02)
    udp4(cap, A(10), B(30), 41000, 53, dns(10, 0), True, 4.0)
    udp4(cap, A(10), B(30), 41000, 53, dns(10, 1, answers=1), False, 0.02)
    return cap, notes


def build_malformed():
    cap = Cap()
    # truncated DNS and HTTP, TCP with a bad header: the Pdu extraction
    # runs on whatever fields decode
    udp4(cap, A(10), B(30), 41000, 53, b'\x00\x05\x01\x00\x00\x01\x00', True, 0.1)
    udp4(cap, A(10), B(30), 41000, 53, dns(5, 1, answers=3)[:40], False, 0.1)
    udp4(cap, A(10), B(31), 137, 137, nbns(0x20)[:20], True, 0.1)
    c = Tcp(cap, A(10), B(20), 45000, 80)
    c.handshake(0.1)
    c.send(True, b'POST /x HTTP/1.1\r\nHost: x.test\r\nContent-Length: 500\r\n\r\nshort', PSH | ACK)
    c.send(False, b'HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n12', PSH | ACK)
    c.send(True, b'', RST | ACK)
    return cap


def bad_configs(out):
    b = {}
    pdu = 'Pdu p Proto dns Transport udp/ip { Extract id From dns.id; };\n'
    b['syntax'] = 'Pdu 123;\n'
    b['eof'] = 'Pdu p Proto dns'
    b['unknown_proto'] = 'Pdu p Proto nosuchproto Transport ip { Extract id From dns.id; };\n'
    b['unknown_field'] = 'Pdu p Proto dns Transport ip { Extract id From dns.nosuchfield; };\n'
    b['dup_pdu_gop'] = pdu + 'Gop g On p Match (id) { };\nGop h On p Match (id) { };\n'
    b['dup_gop'] = pdu + 'Pdu q Proto dns Transport ip { Extract id From dns.id; };\nGop g On p Match (id) { };\nGop g On q Match (id) { };\n'
    b['no_pdu'] = 'Gop g On nopdu Match (id) { };\n'
    b['no_gop_member'] = pdu + 'Gog g { Member nogop (id); };\n'
    b['dup_gog'] = pdu + 'Gop g On p Match (id) { };\nGog x { Member g (id); };\nGog x { Member g (id); };\n'
    b['dup_transform'] = 'Transform t { Match (a) Insert (b); };\nTransform t { Match (a) Insert (b); };\n'
    b['no_transform'] = 'Pdu p Proto dns Transport udp/ip { Extract id From dns.id; Transform nosuch; };\n'
    b['bad_colon'] = 'Transform t { Match (a=aaa:bbbb:cc) Insert (b); };\n'
    b['dup_extract'] = 'Pdu p Proto dns Transport udp/ip { Extract id From dns.id; Extract id From dns.flags.response; };\n'
    b['bad_debug_file'] = 'Debug { Filename "/nonexistent/dir/x"; };\n'
    b['include_missing'] = '#include %s/nonexistent_file.mate\nDone;\n' % out
    b['include_self'] = '#include %s/bad/include_self.mate\n' % out
    b['include_newline'] = 'Transform t { Match (a) Insert (b); };\n#include %s/mate_cov_inc3.mate\n\n\nTransform u { Match (a) Insert (b); };\nDone;\n' % out
    b['empty'] = ''
    b['comments_only'] = '// nothing\n/* nothing */\nDone;\n'
    return b


if __name__ == '__main__':
    out = os.path.abspath(sys.argv[1])
    cap, notes = build()
    cap.write(os.path.join(out, 'mate-coverage.pcap'))
    build_malformed().write(os.path.join(out, 'mate-coverage-malformed.pcap'))
    inc, inc2, inc3 = [os.path.join(out, 'mate_cov_inc%s.mate' % n) for n in ('', '2', '3')]
    open(inc, 'w').write(INC)
    open(inc2, 'w').write(INC2 % inc3)
    open(inc3, 'w').write(INC3)
    open(os.path.join(out, 'mate_cov.mate'), 'w').write(main_cfg(inc, inc2))
    open(os.path.join(out, 'mate_cov_debug.mate'), 'w').write(main_cfg(inc, inc2, os.path.join(out, 'mate_debug.out')))
    # configurations with errors, used by runcov.sh only (coverage of the
    # error paths of the parser)
    bad = os.path.join(out, 'bad')
    os.makedirs(bad, exist_ok=True)
    for name, text in bad_configs(out).items():
        open(os.path.join(bad, name + '.mate'), 'w').write(text)
    if '-v' in sys.argv:
        print(len(cap.frames), 'frames')
        for i, (first, txt) in enumerate(notes):
            last = notes[i + 1][0] - 1 if i + 1 < len(notes) else len(cap.frames)
            print('%d-%d: %s' % (first, last, txt))
