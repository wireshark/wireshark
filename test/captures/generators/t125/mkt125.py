#!/usr/bin/env python3
# Generates test/captures/t125_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the T.125 (MCS) coverage captures.  Usage: mkt125.py <outdir>
All packets are synthetic.  MCS is carried over TPKT/COTP on TCP port
3389 (reached through the COTP heuristic).  The heuristic accepts only
eight of the 43 DomainMCSPDU types; the others cannot be reached."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















from mcslib import (
    connect_additional, connect_initial, connect_response, connect_result, cotp_cc, cotp_cr,
    cotp_dt, domain_params, domain_pdu, gz, TcpStream, write_pcap,
)

def main(out):
    f = []
    s = TcpStream(40001, 3389)
    f += s.handshake()
    c = lambda p: f.append(s.c2s(p))
    sv = lambda p: f.append(s.s2c(p))
    # 4-5: COTP connection request / confirm (no user data)
    c(cotp_cr()); sv(cotp_cc())
    # an empty data TPDU (the heuristic runs on an empty tvb)
    c(cotp_dt(b''))
    # 6: Connect-Initial with user data that is not T.124
    c(cotp_dt(connect_initial(b'\x00\x01\x02\x03')))
    # 7: Connect-Response, successful
    sv(cotp_dt(connect_response(b'\xff\xfe\xfd', 0, 0)))
    # 8: Connect-Response, rt-domain-merging, nonzero calledConnectId, other domain parameters
    sv(cotp_dt(connect_response(b'', 1, 300, domain_params(65535, 65535, 65535, 4, 100, 3, 1056, 2))))
    # 9-10: Connect-Additional and Connect-Result
    c(cotp_dt(connect_additional(5, 3)))
    sv(cotp_dt(connect_result(8)))
    # 11-: domain PDUs accepted by the heuristic
    c(cotp_dt(domain_pdu(1, 1, 128)))                       # erectDomainRequest
    c(cotp_dt(domain_pdu(10)))                              # attachUserRequest
    sv(cotp_dt(domain_pdu(11, 0, 1002)))                    # attachUserConfirm with initiator
    sv(cotp_dt(domain_pdu(11, 14, None)))                   # attachUserConfirm without initiator
    c(cotp_dt(domain_pdu(14, 1002, 1003)))                  # channelJoinRequest
    sv(cotp_dt(domain_pdu(15, 0, 1002, 1003, 1003)))        # channelJoinConfirm with channelId
    sv(cotp_dt(domain_pdu(15, 3, 1002, 1004, None)))        # channelJoinConfirm without channelId
    c(cotp_dt(domain_pdu(25, 1002, 1003, 1, 3, b'\x01\x02\x03\x04')))   # sendDataRequest
    sv(cotp_dt(domain_pdu(26, 1002, 1003, 2, 1, b'\x05' * 200)))        # sendDataIndication, long data
    c(cotp_dt(domain_pdu(25, 1002, 1004, 0, 0, b'')))
    c(cotp_dt(domain_pdu(8, 3)))                            # disconnectProviderUltimatum
    # PDU the heuristic does not accept (plumbDomainIndication)
    c(cotp_dt(domain_pdu(0, 5)))
    # Connect-Initial over two COTP data TPDUs (reassembled by COTP)
    ci = connect_initial(bytes(i & 0xff for i in range(300)))
    c(cotp_dt(ci[:100], eot=False))
    c(cotp_dt(ci[100:]))
    write_pcap(os.path.join(out, 't125-coverage.pcap'), f)
    gz(os.path.join(out, 't125-coverage.pcap'), os.path.join(out, 't125_coverage.pcap.gz'))

    # malformed
    m = []
    s = TcpStream(40101, 3389)
    m += s.handshake()
    c = lambda p: m.append(s.c2s(p))
    c(cotp_dt(b''))                                     # empty data TPDU
    c(cotp_dt(b'\x7f\x65\x00'))                         # Connect-Initial with no content
    c(cotp_dt(b'\x7f\x65\x82\x01\x00' + b'\x04\x01\x01'))     # length beyond the packet
    c(cotp_dt(connect_initial(b'x')[:30]))              # truncated Connect-Initial
    c(cotp_dt(connect_response(b'')[:12]))
    c(cotp_dt(b'\x7f\x66\x03\x04\x01\x01'))             # wrong element types
    c(cotp_dt(b'\x7f\x67\x00'))
    c(cotp_dt(b'\x7f\x68\x00'))
    c(cotp_dt(b'\x7f\x69\x00'))                         # application tag outside the range
    c(cotp_dt(b'\x04'))                                 # erectDomainRequest cut short
    c(cotp_dt(b'\x2e'))                                 # attachUserConfirm cut short
    c(cotp_dt(b'\x64\x03\xea'))                         # sendDataRequest cut short
    c(cotp_dt(domain_pdu(25, 1002, 1003, 1, 3, b'\x01' * 20)[:12]))   # data longer than the packet
    c(cotp_dt(b'\x21'))                                 # disconnectProviderUltimatum cut short
    c(cotp_dt(b'\xfc\x00\x00\x00'))                     # index 63: invalid choice
    c(cotp_dt(b'\x04\x80\x00\x00\x00'))                 # huge integer length
    write_pcap(os.path.join(out, 't125-coverage-malformed.pcap'), m)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
