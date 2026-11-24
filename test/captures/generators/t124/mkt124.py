#!/usr/bin/env python3
# Generates test/captures/t124_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the T.124 (GCC) coverage captures.  Usage: mkt124.py <outdir>
All packets are synthetic.  GCC PDUs are carried as ConnectData in the
user data of the T.125 Connect-Initial / Connect-Response (TPKT and COTP
on TCP port 3389); the T.125 heuristic hands them to the T.124 heuristic."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from mcslib import (
    connect_initial, connect_response, cotp_cc, cotp_cr, cotp_dt, domain_pdu, gz, TcpStream,
    write_pcap,
)
from gcclib import (
    conf_create_request, conf_create_response, conf_invite_request, conf_invite_response,
    conf_join_request, conf_join_response, conf_query_request, conf_query_response, connect_data,
    name_like, termination, W,
)

def main(out):
    f = []
    s = TcpStream(40001, 3389)
    f += s.handshake()
    c = lambda p: f.append(s.c2s(cotp_dt(p)))
    sv = lambda p: f.append(s.s2c(cotp_dt(p)))
    f.append(s.c2s(cotp_cr())); f.append(s.s2c(cotp_cc()))
    req = lambda pdu: c(connect_initial(connect_data(pdu)))
    rsp = lambda pdu, **kw: sv(connect_response(connect_data(pdu), **kw))
    H = lambda b: ('h221', b)
    O = lambda o: ('obj', o)
    # --- an RDP style exchange: the McDn server data registers the send data channels
    def ud_block(t, body): return struct.pack('<HH', t, 4 + len(body)) + body
    cs_core = ud_block(0xc001, struct.pack('<IHHHHII', 0x80004, 1024, 768, 0xca01, 0xaa03, 0x409, 2600)
                       + b'TESTCLIENT'.ljust(32, b'\0')[:32].replace(b'T\0', b'T') [:32]
                       + struct.pack('<III', 4, 0, 12) + b'\0' * 64)
    cs_net = ud_block(0xc003, struct.pack('<I', 2) + b'cliprdr\0' + struct.pack('<I', 0xc0a00000)
                      + b'rdpdr\0\0\0' + struct.pack('<I', 0x80800000))
    sc_core = ud_block(0x0c01, struct.pack('<I', 0x80004))
    sc_sec = ud_block(0x0c02, struct.pack('<II', 0, 0))
    sc_net = ud_block(0x0c03, struct.pack('<HH', 1003, 2) + struct.pack('<HH', 1004, 1005))
    req(conf_create_request(('1',), ud=[(('h221', b'Duca'), cs_core + cs_net)]))
    rsp(conf_create_response(1002, 1, 0, [(('h221', b'McDn'), sc_core + sc_sec + sc_net)]), result=0)
    # --- conference create request / response
    req(conf_create_request(('1',), ud=[(H(b'Test'), b'\x01\x02\x03')]))
    req(conf_create_request(('12345', 'name', 'unicode name'), conv_pw=('9', 'conv', 'u'), pw=('8',),
                            locked=True, listed=False, conductible=True, term=1,
                            cond_priv=[0, 1, 2, 3, 4], conducted_priv=[1], nonconducted_priv=[],
                            desc='A conference', caller='caller',
                            ud=[(O('1.2.3.4'), None), (H(b'Duc0'), b'xy'), (O('0.0.20.124.0.1'), b'\0'), (H(b'KeyX'), None)],
                            prio=(7, (H(b'Prio'), b'p')), mode=(H(b'Mode'), b'm')))
    for m in range(5):
        req(conf_create_request(('1',), prio=(m, (O('1.2.3'), b'')) if m == 1 else None, mode=m))
    req(conf_create_request(('1',), mode=5 and (O('1.2.3.4.5'), b'mode')))
    # a request whose PDU is exactly 42 octets (RDP quirk handled by T.124)
    for n in range(0, 40):
        p = conf_create_request(('1',), desc='x' * n)
        if len(p) == 42: break
    req(p)
    rsp(conf_create_response(1002, 1, 0, [(H(b'Test'), b'\x01\x02')]), result=0)
    for r in range(5):
        rsp(conf_create_response(1003 + r, 100 + r, r), result=0 if r == 0 else 14)
    # --- conference query request / response
    for nt in range(3):
        req(conf_query_request(nt))
    req(conf_query_request(0, ('calling',), [(H(b'Test'), b'q')]))
    req(conf_query_request(1, ('called',)))
    req(conf_query_request(2, ('unknown', 70000)))
    net = [('aggregated', [i % 2 == 0 for i in range(18)], '1234567890', '123', None, [True, False] * 3 + [True]),
           ('aggregated', [True] * 18, '1', None, None, None),
           ('transport', b'\x01\x02\x03\x04', b'\xaa\xbb'),
           ('transport', b'\x05', None),
           ('nonstd', H(b'Nets'), b'n')]
    rsp(conf_query_response(0, None, [dict(name=('1',))], 0), result=0)
    rsp(conf_query_response(2, ('calling',),
        [dict(name=('42', 'conf', 'uni'), modifier='7', desc='descr', locked=True, pw_clear=True,
              netaddr=net, default_flag=True, mode=0),
         dict(name=('43',), default_flag=False, mode=(H(b'Mode'), b'x')),
         dict(name=('44',), mode=4)], 1, [(H(b'Test'), b'r')], wait=True, nounlisted=False))
    rsp(conf_query_response(1, ('unknown', 5), [], 0))
    # --- conference join request / response
    req(conf_join_request())
    req(conf_join_request(('numeric', '77'), '1', 5, ('clear', ('numeric', '55')), ('text', 'cp'), 'me',
                          [(H(b'Test'), b'j')], 0))
    req(conf_join_request(('text', 'room'), None, 6, ('clear', ('text', 'pw')), ('unicode', 'cpw'), None, None, 1))
    req(conf_join_request(('unicode', 'unicode room'), None, None, ('clear', ('unicode', 'upw')), ('numeric', '1'),
                          None, None, 2))
    req(conf_join_request(None, None, 7, ('cr', (11, [('clear', [(H(b'Chal'), b'c')]),
                                                       ((H(b'Algo'), b'a'), [(O('1.2.3'), b'o')])]),
                                          (12, 'clear', ('pw', ('numeric', '3')))),
                          None, None, None, (H(b'Cat1'), b'c')))
    req(conf_join_request(None, None, 8, ('cr', None, (13, (H(b'Algo'), b'z'), ('ud', [(H(b'Resp'), b'r')])))))
    req(conf_join_request(None, None, 9, ('cr', (14, []), None)))
    rsp(conf_join_response(), result=0)
    rsp(conf_join_response(1002, 1001, 5, ('numeric', '77'), True, True, False, True, 1, [0, 2], [1], [3, 4],
                           'desc', ('clear', ('numeric', '1')), 0, [(H(b'Test'), b'j')], 0, (H(b'Mode'), b'm')), result=0)
    for r in range(7):
        rsp(conf_join_response(None, 1001 + r, r, ('text', 'x') if r % 2 else ('unicode', 'y'),
                               result_=r, category=(r % 3 if r % 4 else (H(b'Cat2'), b'c')), mode=(r % 5 if r % 6 else (O('1.2.3'), b''))), result=0)
    # --- conference invite request / response
    req(conf_invite_request(('5',)))
    req(conf_invite_request(('6', 't', 'u'), 1003, 1001, 4, True, True, False, True, 1, [0], [1], [2, 3], 'inv',
                            'caller', [(H(b'Test'), b'i')], (9, (H(b'Sch1'), b'!')), (H(b'Node'), b'n'), 3))
    req(conf_invite_request(('7',), prio=(1, (H(b'Sch2'), b'!')), category=2, mode=1))
    rsp(conf_invite_response(0), result=0)
    rsp(conf_invite_response(1, [(H(b'Test'), b'k')]), result=0)
    # --- T.125 domain PDUs with user data and the GCC channel ids
    c(domain_pdu(1, 3, 200))
    c(domain_pdu(10))
    sv(domain_pdu(11, 0, 1005))
    c(domain_pdu(14, 1005, 1003))
    sv(domain_pdu(15, 0, 1005, 1003, 1003))
    c(domain_pdu(14, 1005, 0))
    sv(domain_pdu(15, 0, 1005, 0, 1010))
    c(domain_pdu(25, 1005, 1020, 1, 3, b'\x01\x02\x03'))
    sv(domain_pdu(26, 1006, 1020, 3, 0, b'\x04' * 130))
    sv(domain_pdu(26, 1006, 65535, 0, 2, b''))
    # data on the channels registered above: RDP virtual channel PDUs and the I/O channel
    c(domain_pdu(25, 1005, 1004, 1, 3, struct.pack('<II', 8, 3) + struct.pack('<HHI', 1, 0, 0)))
    sv(domain_pdu(26, 1006, 1005, 1, 3, struct.pack('<II', 4, 3) + b'wxyz'))
    c(domain_pdu(8, 0))
    # ConnectData for another object identifier: the T.124 heuristic rejects it
    c(connect_initial(connect_data(conf_create_request(('1',)), oid_='1.2.3.4')))
    write_pcap(os.path.join(out, 't124-coverage.pcap'), f)
    gz(os.path.join(out, 't124-coverage.pcap'), os.path.join(out, 't124_coverage.pcap.gz'))

    m = []
    s = TcpStream(40101, 3389)
    m += s.handshake()
    c = lambda p: m.append(s.c2s(cotp_dt(p)))
    req = lambda pdu: c(connect_initial(connect_data(pdu)))
    good = conf_create_request(('12345', 'name', 'uni'), desc='A conference', ud=[(('h221', b'Test'), b'abc')])
    for n in (1, 2, 3, 5, 8, 12, 20, len(good) - 1):
        req(good[:n])
    # ConnectData with a connectPDU longer than the data
    cd = connect_data(good)
    c(connect_initial(cd[:len(cd) - 5]))
    c(connect_initial(cd[:8]))
    c(connect_initial(cd[:3]))
    c(connect_initial(b'\x00\x05\x00\x14\x7c\x00\x01\xff'))
    c(connect_initial(b'\x00\x05\x00\x14\x7c\x00'))
    # invalid choice indices in the ConnectGCCPDU (extension alternative and unknown)
    req(b'\x80\x01\x00')
    req(b'\xe0')
    req(b'\x70\x00')
    req(b'\x00')
    # response PDUs cut short
    for pdu in (conf_create_response(1002, 1, 0, [(('h221', b'Test'), b'x')]),
                conf_query_response(0, None, [dict(name=('1',), netaddr=[('transport', b'\x01', b'\x02')])], 0),
                conf_join_response(1002, 1001, 1, ('numeric', '1'), pw=('cr', (1, [('clear', [])]), None)),
                conf_invite_request(('5',), ud=[(('h221', b'Test'), b'i')])):
        for n in (2, 4, len(pdu) // 2, len(pdu) - 1):
            m.append(s.s2c(cotp_dt(connect_response(connect_data(pdu[:n])))))
    # huge SET OF / lengths
    w = W(); w.choice(0, 8, ext=True); w.bit(0)
    for _ in range(8): w.bit(0)
    name_like(w, '1'); w.boolean(0); w.boolean(0); w.boolean(0); termination(w, 0)
    base = w.bytes()
    req(base[:-1] + b'\x00')
    w2 = W(); w2.choice(0, 8, ext=True); w2.bit(0); w2.bits(0b00000001, 8)
    name_like(w2, '1'); w2.boolean(0); w2.boolean(0); w2.boolean(0); termination(w2, 0)
    w2.length(3); w2.bits(0xffffff, 24)
    req(w2.bytes())
    # unknown extension additions and a bad extension bitmap length
    w3 = W(); w3.choice(0, 8, ext=True); w3.bit(1); w3.bits(0, 8)
    name_like(w3, '1'); w3.boolean(0); w3.boolean(0); w3.boolean(0); termination(w3, 0)
    w3.ext_additions([None, None, b'\x01\x02'])
    req(w3.bytes())
    w4 = W(); w4.choice(0, 8, ext=True); w4.bit(1); w4.bits(0, 8)
    name_like(w4, '1'); w4.boolean(0); w4.boolean(0); w4.boolean(0); termination(w4, 0)
    w4.length_small(62); w4.bits(0xffffffff, 32)
    req(w4.bytes())
    # ExtraDiallingString: decoded as a plain BMPString by the dissector, not as X.691 says
    rsp = lambda pdu: m.append(s.s2c(cotp_dt(connect_response(connect_data(pdu)))))
    rsp(conf_query_response(0, None, [dict(name=('1',), netaddr=[('aggregated', [True] * 18, '1', '2', '0#*,9', None)])], 0))
    # a conference name with a numeric string that is not all digits (index above 9)
    w5 = W(); w5.choice(0, 8, ext=True); w5.bit(0); w5.bits(0, 8); w5.bit(0); w5.bit(0)
    w5.bits(1, 8); w5.align(); w5.bits(0xfe, 8)
    req(w5.bytes())
    # domain PDUs cut short or with an invalid index
    c(b'\x04'); c(b'\x2e'); c(b'\x2e\x00\x00'); c(b'\x38\x00\x01'); c(b'\x3e\x00')
    c(b'\x64'); c(b'\x64\x00\x01\x03\xea'); c(b'\x68\x00\x01\x03\xea\x70\x81')
    c(b'\x21'); c(b'\x20')
    # INTEGER(0..MAX) with a multi-octet value: the PER code reads a one octet value
    c(domain_pdu(1, 3, 1000000))
    # DomainMCSPDU with a send data whose length is longer than the packet
    c(domain_pdu(25, 1005, 1003, 1, 3, b'\x01' * 300)[:30])
    write_pcap(os.path.join(out, 't124-coverage-malformed.pcap'), m)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
