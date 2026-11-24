#!/usr/bin/env python3
# Generates test/captures/ros_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the ROS coverage captures: mkros.py <outdir>

ROS (X.880 Remote Operations Service, packet-ros.c, generated from
epan/dissectors/asn1/ros) is not reached on a port of its own: it
dissects the ROSE APDUs of an association over the OSI upper layers
(TCP 102, TPKT, COTP, session, presentation, ACSE). ROS is registered
by the protocols that use it: the abstract syntax of DAP (2.5.9.1) is
found in the ROS protocol table (ros_try_string), the ones of DISP, DSP
and DOP in the "ros.oid" table. This capture uses DAP and DISP.

Every packet is built with struct; the helpers for BER, the OSI upper
layers and X.500 types are in x500lib.py. Nothing comes from a real
network.
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct

from x500lib import (  # noqa: E402,
    Assoc, AT_SN, attribute, ava, BITS, BOOL, CTX_DAP, DN_ALICE, DN_BOB, DN_DSA, DN_ORG,
    entry_information, ENUM, INT, NULL, OCTS, OID_DAP_AC, OID_DAP_AS, R_CN2, ros_error,
    ros_invoke, ros_reject, ros_result, SEQ, SET, tlv, UTF8, write_pcap, X,
)

AC_DISP_CONSUMER = '2.5.3.4'
AS_DISP = '2.5.9.3'
CTX = 3
READ, COMPARE, ABANDON, LIST, SEARCH, ADD, REMOVE, MODIFY, MODIFYDN = range(1, 10)
E_ATTR, E_NAME, E_SERVICE, E_REFERRAL, E_ABANDONED, E_SECURITY, E_ABANDONFAILED, E_UPDATE = range(1, 9)
DISP_REQUEST = 1
DISP_SHADOW_ERROR = 1


def retag(tag, enc):
    return bytes([tag]) + enc[1:]


# ------------------------------------------------------- X.500 binds

def bind_arg(creds=None, versions=True):
    body = b''
    if creds is not None:
        body += X(0, creds)
    if versions:
        body += X(1, BITS(6, b'\xc0'))
    return SET(body)


def simple_creds(name=DN_ALICE, password='plain'):
    body = X(0, name)
    if password == 'plain':
        body += X(2, OCTS(b'secret'))
    return X(0, SEQ(body))


def bind_error_data(kind='service', problem=1):
    body = X(0, BITS(6, b'\xc0'))
    body += X(1, INT(problem)) if kind == 'service' else X(2, INT(problem))
    return SET(body)


# ----------------------------------------------- ROSE APDUs not in x500lib

def ros_invoke_absent(opcode, arg=None):
    """Invoke with the InvokeId alternative absent (NULL)."""
    body = NULL() + INT(opcode)
    if arg is not None:
        body += arg
    return tlv(0xa1, body)


def ros_result_absent(opcode, result):
    return tlv(0xa2, NULL(), SEQ(INT(opcode), result))


def ros_error_absent(code, param=None):
    return tlv(0xa3, NULL(), INT(code), param if param is not None else b'')


def ros_reject_absent(ptag, problem):
    return tlv(0xa4, NULL(), INT(problem, 0x80 | ptag))


class Dap(Assoc):
    def __init__(self, frames, cport):
        super().__init__(frames, cport, OID_DAP_AC, [(CTX_DAP, OID_DAP_AS)])


class Disp(Assoc):
    def __init__(self, frames, cport):
        super().__init__(frames, cport, AC_DISP_CONSUMER, [(CTX, AS_DISP)])


def dap_read():
    return SET(X(0, DN_ALICE))


def dap_read_result():
    return SET(X(0, entry_information()))


def main_frames():
    F = []
    d = Dap(F, 40001)
    d.open()
    # bind: invoke, result and error (ros_try_string: the built-in bind codes)
    d.bind(bind_arg(simple_creds()))
    d.bind_result(bind_arg(simple_creds(DN_DSA, None)))
    # every operation with its argument and result; the invoke carries the
    # invoke id, the result the opcode again
    d.op(READ, dap_read(), dap_read_result())
    d.op(COMPARE, SET(X(0, DN_ALICE), X(1, ava(AT_SN, UTF8('Jones')))), SET(X(0, BOOL(False))))
    d.op(ABANDON, SEQ(X(0, INT(1))), NULL())
    d.op(LIST, SET(X(0, DN_ORG)), SET(X(1, SET())))
    d.op(SEARCH, SET(X(0, DN_ORG), X(1, INT(0))), SET(X(0, SET())))
    d.op(ADD, SET(X(0, DN_BOB), X(1, SET())), NULL())
    d.op(REMOVE, SET(X(0, DN_BOB)), NULL())
    d.op(MODIFY, SET(X(0, DN_ALICE), X(1, SEQ())), NULL())
    d.op(MODIFYDN, SET(X(0, DN_BOB), X(1, R_CN2)), NULL())
    # a linked invoke (linkedId [0]) and an invoke whose result comes back
    # in two directions of the association
    d.iid += 1
    d.pdata(True, ros_invoke(d.iid, READ, dap_read(), linked=1))
    d.pdata(False, ros_result(d.iid, READ, dap_read_result()))
    # a result with the invoke id only (no opcode, no result)
    d.iid += 1
    d.pdata(True, ros_invoke(d.iid, REMOVE, SET(X(0, DN_BOB))))
    d.pdata(False, ros_result(d.iid))
    # errors of DAP with their parameters
    d.op(READ, dap_read(), None, (E_SERVICE, SET(X(0, INT(1)))))
    d.op(READ, dap_read(), None, (E_NAME, SET(X(0, INT(1)), X(1, DN_ORG))))
    d.op(READ, dap_read(), None, (E_ABANDONED, SET()))
    d.op(ADD, SET(X(0, DN_ALICE), X(1, SET(attribute(AT_SN, UTF8('x'))))), None,
         (E_UPDATE, SET(X(0, INT(12)))))
    # an error without a parameter
    d.iid += 1
    d.pdata(True, ros_invoke(d.iid, READ, dap_read()))
    d.pdata(False, tlv(0xa3, INT(d.iid), INT(E_SERVICE)))
    # bind error
    d.bind(bind_arg(simple_creds()))
    d.bind_error(bind_error_data('service', 1))
    # rejects: every problem of every kind
    for ptag, n in ((0, 3), (1, 8), (2, 3), (3, 5)):
        for problem in range(n):
            d.iid += 1
            d.pdata(True, ros_invoke(d.iid, READ, dap_read()))
            d.reject(ptag, problem)
    # absent invoke ids: invoke, result, error and reject
    d.pdata(True, ros_invoke_absent(READ, dap_read()))
    d.pdata(False, ros_result_absent(READ, dap_read_result()))
    d.pdata(True, ros_invoke_absent(READ, dap_read()))
    d.pdata(False, ros_error_absent(E_SERVICE, SET(X(0, INT(1)))))
    d.pdata(False, ros_reject_absent(1, 1))
    # two invokes with the same id (the first stays unmatched), results
    d.pdata(True, ros_invoke(50, READ, dap_read()))
    d.pdata(True, ros_invoke(50, READ, dap_read()))
    d.pdata(False, ros_result(50, READ, dap_read_result()))
    # a result for an invoke id that was never invoked, and a repeated result
    d.pdata(False, ros_result(60, READ, dap_read_result()))
    d.pdata(True, ros_invoke(61, READ, dap_read()))
    d.pdata(False, ros_result(61, READ, dap_read_result()))
    d.pdata(False, ros_result(61, READ, dap_read_result()))
    # the reproducer of "ROS: Mask the opcode and reset per-PDU state"
    # (1): operation codes above 24 bits used to change the PDU type, so
    # the argument was handed to the wrong sub-dissector. 0x20000001 is
    # read with the "result" bits set, 0x10000001 with the "argument" bits
    # on a result, 0x7f000002 with every high bit on an error
    d.iid += 1
    d.pdata(True, ros_invoke(d.iid, 0x20000001, dap_read()))
    d.pdata(False, ros_result(d.iid, 0x10000001, dap_read_result()))
    d.iid += 1
    d.pdata(True, ros_invoke(d.iid, 0x01000001, dap_read()))
    d.pdata(False, ros_error(d.iid, 0x7f000000 + E_SERVICE, SET(X(0, INT(1)))))
    # (2) an absent invoke id after an invoke with id 200: the old invoke id
    # was reused, so the response matched the second invoke
    d.pdata(True, ros_invoke(200, READ, dap_read()))
    d.pdata(True, ros_invoke_absent(READ, dap_read()))
    d.pdata(False, ros_result(200, READ, dap_read_result()))
    # unbind is not decoded further by ROS, so it is in the malformed capture
    d.close()

    # DISP: the ROS OID table path (bind, operation, result, error)
    s = Disp(F, 40002)
    s.open()
    s.bind(bind_arg(simple_creds()))
    s.bind_result(bind_arg(simple_creds(DN_DSA, None)))
    unsigned = lambda x: retag(0xa0, x)            # noqa: E731
    s.op(DISP_REQUEST, unsigned(SEQ(SEQ(INT(1), INT(1)), ENUM(1))), NULL())
    s.op(DISP_REQUEST, unsigned(SEQ(SEQ(INT(1), INT(1)), ENUM(2))), None,
         (DISP_SHADOW_ERROR, SEQ(INT(1))))
    s.bind(bind_arg(simple_creds()))
    s.bind_error(bind_error_data('service', 2))
    s.close()
    return F


def malformed_frames():
    F = []
    d = Dap(F, 41001)
    d.open()
    d.bind(bind_arg(simple_creds()))
    # unbind invoke, result and error: ROS builds the operation code 0 for
    # them, which has no sub-dissector, so nothing is decoded
    d.pdata(True, tlv(0xb3, INT(1)))
    d.pdata(False, tlv(0xb4, INT(2)))
    d.pdata(False, tlv(0xb5, INT(3)))
    # (empty ones: the unknown BER dissector runs out of data)
    d.pdata(True, tlv(0xb3, b''))
    # unknown operation and error codes, and a negative one
    d.op(42, SET(), SET())
    d.op(READ, dap_read(), None, (42, SET()))
    d.op(-1, SET(), SET())
    d.iid += 1
    d.pdata(True, ros_invoke(d.iid, 0x20000000, SET()))
    # an APDU ROS does not know: not a ROS tag (a SEQUENCE, a [9])
    d.pdata(True, SEQ(INT(1)))
    d.pdata(True, tlv(0xa9, INT(1)))
    # two ROS PDUs in one P-DATA: the second is read as a second ROS PDU
    d.pdata(True, ros_invoke(90, READ, dap_read()) + ros_invoke(91, READ, dap_read()))
    # truncated PDUs
    d.pdata(True, ros_invoke(92, READ, dap_read())[:-5])
    d.pdata(True, bytes([0xa1, 0x04, 0x02, 0x01]))
    d.pdata(True, bytes([0xa2]))
    # reject with an unknown problem choice and an invalid general problem
    d.pdata(False, tlv(0xa4, INT(1), INT(1, 0x85)))
    d.pdata(False, ros_reject(1, 0, 77))
    d.close()
    # DISP with opcodes and errors it has no dissector for: ROS reports
    # that the OID is not implemented
    s = Disp(F, 41002)
    s.open()
    s.op(9, NULL(), NULL())
    s.op(DISP_REQUEST, unsigned_dummy(), None, (9, NULL()))
    s.close()
    return F


def unsigned_dummy():
    return retag(0xa0, SEQ(SEQ(INT(1), INT(1)), ENUM(1)))


def pcapng(path, frames_by_if):
    """A pcapng with Ethernet and Exported PDU interfaces; frames_by_if is
    a list of (interface, bytes)."""
    def blk(btype, body):
        body += b'\0' * (-len(body) % 4)
        n = len(body) + 12
        return struct.pack('<II', btype, n) + body + struct.pack('<I', n)
    out = blk(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1))
    out += blk(1, struct.pack('<HHI', 1, 0, 262144))
    out += blk(1, struct.pack('<HHI', 252, 0, 262144))
    for i, (ifc, data) in enumerate(frames_by_if):
        ts = 1793491200 * 1000000 + i * 1000
        out += blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(data), len(data)) + data)
    open(path, 'wb').write(out)


def exp_pdu(name, payload):
    n = name.encode()
    tags = struct.pack('>HH', 12, len(n) + (-len(n) % 4)) + n + b'\0' * (-len(n) % 4)
    return tags + struct.pack('>HH', 0, 0) + payload


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'ros-coverage.pcap'), main_frames())
    # the malformed capture is a pcapng: it adds an Exported PDU frame that
    # hands ROS an APDU without the association data
    frames = [(0, f) for f in malformed_frames()]
    frames.append((1, exp_pdu('ros', ros_invoke(1, READ, dap_read()))))
    pcapng(os.path.join(out, 'ros-coverage-malformed.pcapng'), frames)


if __name__ == '__main__':
    main()
