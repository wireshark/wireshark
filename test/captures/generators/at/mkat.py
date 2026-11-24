#!/usr/bin/env python3
# Generates test/captures/at_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Build synthetic captures that exercise the AT command dissector
# (epan/dissectors/packet-at.c). Every packet is built here with struct;
# nothing comes from a real network or device.
#
#   python3 mkat.py <outdir>
#
# writes
#   at-coverage.pcap            main capture, Linux USB mmapped (DLT 220)
#   at-coverage-malformed.pcap  sub-dissector errors, truncated frames (DLT 220)
#   at-coverage-exppdu.pcap     Exported PDU "at" frames (DLT 252), the only
#                               way to reach the dissector with an unknown
#                               direction (USB always sets one)
#
# AT reaches the dissector through the default-enabled "at_usb_bulk"
# heuristic. The host (DTE) sends commands as bulk OUT submissions on
# endpoint 0x02, the modem (DCE) answers in bulk IN completions on
# endpoint 0x81; the USB dissector sets P2P_DIR_SENT / P2P_DIR_RECV, which
# the AT dissector turns into the DTE / DCE role.
import os
import struct
import sys

T0 = 1700000000


def usb(payload, ev, ep, urb_id, ts, devnum=3, caplen=None):
    # Linux USB mmapped header (64 octets), bulk transfer, data present
    h = struct.pack('<QBBBBHBB', urb_id, ord(ev), 3, ep, devnum, 1, ord('-'), 0)
    h += struct.pack('<qii', ts // 1000000, ts % 1000000, 0)
    h += struct.pack('<II', len(payload), len(payload))
    h += b'\0' * 8
    h += struct.pack('<iiII', 0, 0, 0, 0)
    assert len(h) == 64
    return h + payload


def write_pcap(fn, linktype, pkts):
    """pkts: list of (frame bytes, caplen or None)"""
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, (p, caplen) in enumerate(pkts):
            ts = i * 10000
            cl = len(p) if caplen is None else caplen
            f.write(struct.pack('<IIII', T0 + ts // 1000000, ts % 1000000, cl, len(p)))
            f.write(p[:cl])


class Usb:
    def __init__(self):
        self.pkts = []
        self.urb = 0xffff9a0001000000

    def _add(self, payload, ev, ep, caplen):
        self.urb += 0x100
        ts = len(self.pkts) * 10000
        frame = usb(payload, ev, ep, self.urb, T0 * 1000000 + ts)
        self.pkts.append((frame, None if caplen is None else 64 + caplen))

    def dte(self, payload, caplen=None):
        self._add(payload, 'S', 0x02, caplen)

    def dce(self, payload, caplen=None):
        self._add(payload, 'C', 0x81, caplen)


def crlf(*lines):
    return b''.join(b'\r\n' + l + b'\r\n' for l in lines)


# SMS-DELIVER from +31641600986, "Hello world!" style 7-bit text
SMS = b"040B911346610089F60000208062917314080CC8F71D14969741F977FD07"
# The dissector skips the first 16 hex characters (8 octets) of the PDU line
PDU = b"0000000000000000" + SMS
# SMS-DELIVER, 8-bit data, 4 octets of user data
SMS2 = b"040B911346610089F60004208062917314080404DEADBEEF"
PDU2 = b"07911326040000F0" + SMS2


def main_capture():
    u = Usb()
    # ---- Reproducers of the fixes on the branch -----------------------
    # at_ciev_null_usb.py: +CIEV whose first parameter starts with CR
    u.dce(b"\r\n+CIEV:\rX,1\r\n")
    # at_cmux_speed.py: port speed decoded from its digits
    u.dce(b"\r\n+CMUX: 0,0,5\r\n")
    u.dce(b"\r\n+CMUX: 0,0,123456\r\n")
    u.dce(b"\r\n+CMUX: 0,0,\r\n")
    # at_cmgr_pdu.py: the PDU line alone is not AT (no heuristic magic),
    # so the +CMGL that follows first closes the open +CMGR data part
    u.dce(b"\r\n+CMGR: 0,,26\r\n")
    u.dce(PDU + b"\r\n\r\nOK\r\n")
    u.dce(b"\r\n+CMGL: 1,\"REC READ\",,26\r\n" + PDU + b"\r\n\r\nOK\r\n")

    # ---- Heuristic and framing ---------------------------------------
    u.dte(b"AT\r")                                  # bare AT
    u.dce(crlf(b"OK"))                              # Response ACK type
    u.dce(b"\r\r\nOK\r\n")                          # second magic (CR CR LF)
    u.dte(b"AT+CSQ\r\0\0\0\0\0\0\0\0")              # zero padded command
    u.dce(b"\r\nOK\r\n\0\0\0\0\0\0")                # zero padded response
    u.dce(b"\r\nOK\r\n\0\0\x07\0")                  # padding not all zero: not AT
    u.dce(b"\r\nO\0\0\0\0")                         # too few characters: not AT
    u.dce(b"\r\nOK\x01\r\n")                        # control character: not AT
    u.dce(b"hello\r\n")                             # no magic: not AT
    u.dte(b"\r\nAT+CSQ\r")                          # octets before AT ignored
    u.dte(b"\r\nhello\r")                           # host data without AT
    u.dte(b"AT+csq\r")                              # lower case command
    u.dte(b"AT+CSQ")                                # no terminator: generated type
    u.dce(b"\r\nOK")                                # response without CR LF
    u.dce(b"\r\nOK\r")                              # response with CR only
    u.dce(b"\r\n+CSQ: 20,0")                        # parameters up to the end
    u.dce(b"\r\n\r\n")                              # only white space
    u.dce(b"\r\n  +CSQ: 20,0\r\n")                  # blanks before the command
    u.dte(b"AT+CMEE=1;+CSQ;+CIMI;D5551234;A\r")     # several commands
    u.dte(b"AT;\r")                                 # empty command after ';'
    u.dte(b"AT+FOO=1,2\r")                          # unknown command
    u.dce(crlf(b"+BAR: 1"))                         # unknown response
    u.dte(b"AT+CMER = 3, 0,  0 ,1,0\r")             # blanks around parameters
    u.dce(crlf(b"RING", b"RING"))
    u.dce(crlf(b"ERROR"))
    u.dce(crlf(b"+CSQ: 20,0", b"OK"))               # two responses in one transfer

    # ---- Basic commands (DTE only) -----------------------------------
    for c in (b"ATD+31641600986;\r", b"ATD>1;\r", b"ATA\r", b"ATE0\r", b"ATE1\r",
              b"ATI\r", b"ATE0=1\r", b"ATI?\r"):
        u.dte(c)
    u.dce(crlf(b"A"))                               # DTE command from the DCE
    u.dte(b"ATOK\r")                                # DCE result code from the DTE

    # ---- Every command in the table, every form ----------------------
    # +CCWA
    u.dte(b"AT+CCWA=1,1,7\r")
    u.dte(b"AT+CCWA=1,2,1,9\r")                     # 4th parameter unknown
    u.dte(b"AT+CCWA?\r")
    u.dte(b"AT+CCWA=?\r")
    u.dce(crlf(b"+CCWA: \"+31641600986\",145,1,\"Alice\",0,\"12\",128,1"))
    u.dce(crlf(b"+CCWA: \"5551234\",100,1,\"Bob\",1,,,0,9"))   # bad type, extra
    u.dce(crlf(b"+CCWA=1"))                         # action from the DCE
    # +CFUN
    u.dte(b"AT+CFUN=1,0\r")
    u.dte(b"AT+CFUN=5,2\r")                         # reserved fun, bad rst
    u.dte(b"AT+CFUN=128,1,7\r")                     # fun out of range, extra
    u.dte(b"AT+CFUN?\r")
    u.dte(b"AT+CFUN=?\r")
    u.dce(crlf(b"+CFUN: 1"))
    u.dce(crlf(b"+CFUN: 6,3"))
    u.dce(crlf(b"+CFUN: 200,0,1"))
    # +CGDCONT
    u.dte(b"AT+CGDCONT=1,\"IP\",\"internet\",\"10.0.0.1\",0,0,1,0\r")
    u.dte(b"AT+CGDCONT\r")
    u.dte(b"AT+CGDCONT?\r")
    u.dte(b"AT+CGDCONT=?\r")
    u.dce(crlf(b"+CGDCONT: 1,\"IPV6\",\"ims\",\"\",1,2"))
    # +CGMI +CGMM +CGMR +GMI +GMM +GMR
    for c, v in ((b"+CGMI", b"Example Modems"), (b"+CGMM", b"EM-1000"),
                 (b"+CGMR", b"1.2.3"), (b"+GMI", b"Example Modems"),
                 (b"+GMM", b"EM-1000"), (b"+GMR", b"1.2.3")):
        u.dte(b"AT" + c + b"\r")
        u.dte(b"AT" + c + b"=?\r")
        u.dte(b"AT" + c + b"=1\r")                  # action not allowed
        u.dce(crlf(c + b": " + v))
        u.dce(crlf(c + b": " + v + b",x,y"))        # third parameter unknown
    # +CGSN +GSN +CHUP +CLAC +CSUPI (no parameters)
    for c in (b"+CGSN", b"+GSN", b"+CHUP", b"+CLAC", b"+CSUPI"):
        u.dte(b"AT" + c + b"\r")
        u.dte(b"AT" + c + b"=?\r")
        u.dte(b"AT" + c + b"=1\r")
        u.dce(crlf(c + b": 1"))
    # +CHLD
    for m in (b"0", b"1", b"1x", b"2x", b"3x", b"12", b"5x", b"4"):
        u.dte(b"AT+CHLD=" + m + b"\r")
    u.dte(b"AT+CHLD=1,2\r")                         # second parameter
    u.dte(b"AT+CHLD=?\r")
    u.dce(crlf(b"+CHLD: (0,1,1x,2,2x,3,4)"))
    # +CIEV
    u.dte(b"AT+CMER=3,0,0,1\r")
    u.dce(crlf(b"+CIEV: 1,0"))
    u.dce(crlf(b"+CIEV: 3,1"))
    u.dce(crlf(b"+CIEV: 20,5"))
    u.dce(crlf(b"+CIEV: 21,1"))                     # index out of range
    u.dce(crlf(b"+CIEV: 0,1"))                      # index 0
    u.dce(crlf(b"+CIEV: 2,1,7"))                    # third parameter unknown
    u.dte(b"AT+CIEV=1,0\r")                         # from the DTE
    # +CIMI ^CIMI
    for c in (b"+CIMI", b"^CIMI"):
        u.dte(b"AT" + c + b"\r")
        u.dte(b"AT" + c + b"=?\r")
        u.dte(b"AT" + c + b"=1\r")
        u.dce(crlf(c + b": 001010123456789"))
    u.dce(crlf(b"+CIMI: 310150123456789,1"))        # second parameter unknown
    # +CIND
    u.dte(b"AT+CIND?\r")
    u.dte(b"AT+CIND=?\r")
    u.dte(b"AT+CIND=1\r")
    u.dce(crlf(b"+CIND: (\"service\",(0,1)),(\"call\",(0,1)),(\"callsetup\",(0-3)),"
               b"(\"callheld\",(0-2)),(\"signal\",(0-5)),(\"roam\",(0,1)),(\"battchg\",(0-5))"))
    u.dce(crlf(b"+CIND: " + b",".join(str(i % 6).encode() for i in range(21))))
    u.dce(crlf(b"+CIND: (\"a\",(0,1))),(\"b\",(0,1))"))   # unbalanced bracket
    # +CLCC
    u.dte(b"AT+CLCC\r")
    u.dte(b"AT+CLCC=?\r")
    u.dte(b"AT+CLCC=1\r")
    u.dce(crlf(b"+CLCC: 1,0,0,0,0,\"+31641600986\",145,\"Alice\",1",
               b"+CLCC: 2,1,1,1,1,\"5551234\",300,\"Bob\",0,x", b"OK"))
    # +CLIP
    u.dte(b"AT+CLIP=1\r")
    u.dte(b"AT+CLIP=1,2,3\r")
    u.dte(b"AT+CLIP?\r")
    u.dte(b"AT+CLIP=?\r")
    u.dce(crlf(b"+CLIP: \"+31641600986\",145,\"12\",128,\"Alice\",0"))
    u.dce(crlf(b"+CLIP: \"5551234\",99,,,,2,x"))
    # +CME ERROR
    u.dce(crlf(b"+CME ERROR: 10"))
    u.dce(crlf(b"+CME ERROR: 1 3"))
    u.dce(crlf(b"+CME ERROR: SIM failure"))
    u.dce(crlf(b"+CME ERROR: 3,1"))
    u.dte(b"AT+CME ERROR: 3\r")
    # +CMEE
    u.dte(b"AT+CMEE=2\r")
    u.dte(b"AT+CMEE=1,1\r")
    u.dte(b"AT+CMEE\r")
    u.dte(b"AT+CMEE?\r")
    u.dte(b"AT+CMEE=?\r")
    u.dce(crlf(b"+CMEE: 1"))
    # +CMER
    u.dte(b"AT+CMER=3,0,0,1,0\r")
    u.dte(b"AT+CMER=4,3,3,3,2,9\r")                 # every value out of range
    u.dte(b"AT+CMER?\r")
    u.dte(b"AT+CMER=?\r")
    u.dce(crlf(b"+CMER: 3,0,0,1,0"))
    # +CMGL
    u.dte(b"AT+CMGL=4\r")
    u.dte(b"AT+CMGL=\"ALL\",1\r")
    u.dte(b"AT+CMGL?\r")
    u.dte(b"AT+CMGL=?\r")
    u.dce(b"\r\n+CMGL: 1,1,,26\r\n" + PDU + b"\r\n"
          b"+CMGL: 2,\"REC READ\",\"Alice\",24\r\n" + PDU2 + b"\r\n\r\nOK\r\n")
    u.dce(b"\r\n+CMGL: 3,1,,26,9\r\n" + PDU + b"\r\n\r\nOK\r\n")   # extra parameter
    u.dce(b"\r\n+CMGL: 4,1,,26\r\n" + PDU[:-1] + b"\r\n\r\nOK\r\n")  # odd length
    u.dce(b"\r\n+CMGL: 5,1,,0\r\n\r\n\r\nOK\r\n")                   # empty
    u.dce(b"\r\n+CMGL: 6,1,,8\r\n" + b"00" * 8 + b"\r\n\r\nOK\r\n")  # header only
    u.dce(b"\r\n+CMGL: 7,1,,26\r\n" + b"0" * 16 + b"04ZZ\r\n\r\nOK\r\n")  # not hex
    # +CMGL with its PDU in the next transfer: that one must start with
    # heuristic magic, so the data part is "AT" + 14 hex digits + PDU
    u.dce(b"\r\n+CMGL: 8,1,,26\r\n")
    u.dce(b"AT" + b"0" * 14 + SMS + b"\r\n\r\nOK\r\n")
    # +CMGR
    u.dte(b"AT+CMGR=1\r")
    u.dce(b"\r\n+CMGR: 1,,26\r\n" + PDU + b"\r\n\r\nOK\r\n")
    u.dte(b"AT+CMGR=2,1\r")
    u.dce(b"\r\n+CMGR: 0,\"Alice\",24,5\r\n" + PDU2 + b"\r\n\r\nOK\r\n")
    u.dte(b"AT+CMGR=3,0,7\r")
    u.dce(b"\r\n+CMGR: 1,,26,5,9\r\n" + PDU[:-1] + b"\r\n\r\nOK\r\n")
    u.dce(b"\r\n+CMGR: 1,,0\r\n\r\n\r\nOK\r\n")
    u.dce(b"\r\n+CMGR: 1,,4\r\n" + b"00" * 4 + b"\r\n\r\nOK\r\n")
    u.dce(b"\r\n+CMGR: 1,,26\r\n" + b"0" * 16 + b"0G\r\n\r\nOK\r\n")
    u.dce(b"\r\n+CMGR: 1,,26\r\n")                  # PDU in the next transfer
    u.dce(b"AT" + b"0" * 14 + SMS + b"\r\n\r\nOK\r\n")
    u.dte(b"AT+CMGR=?\r")
    u.dte(b"AT+CMGR?\r")
    # +CMUX
    u.dte(b"AT+CMUX=0,0,5,31,10,3,30,10,2\r")
    u.dte(b"AT+CMUX=1,2,6,64,20,5,40,20,7,9\r")     # tenth parameter unknown
    u.dte(b"AT+CMUX=0,,\r")
    u.dte(b"AT+CMUX?\r")
    u.dte(b"AT+CMUX=?\r")
    u.dce(crlf(b"+CMUX: 0,,5,31,10,3,30,10,2"))    # subset missing
    u.dce(crlf(b"+CMUX: 1,1,4"))
    # +CNUM
    u.dte(b"AT+CNUM\r")
    u.dte(b"AT+CNUM=1\r")
    u.dce(crlf(b"+CNUM: \"Voice\",\"+31641600986\",145,0,4,1",
               b"+CNUM: \"Fax\",\"5551234\",100,9600,6,2,x", b"OK"))
    # +COPS
    u.dte(b"AT+COPS=1,2,\"20408\",7\r")
    u.dte(b"AT+COPS=0,0,\"x\",7,1\r")
    u.dte(b"AT+COPS?\r")
    u.dte(b"AT+COPS=?\r")
    u.dce(crlf(b"+COPS: 0,0,\"Example, Inc\",7"))
    # +CPIN
    u.dte(b"AT+CPIN=\"1234\"\r")
    u.dte(b"AT+CPIN=\"12345678\",\"4321\",1\r")
    u.dte(b"AT+CPIN?\r")
    u.dte(b"AT+CPIN=?\r")
    u.dce(crlf(b"+CPIN: READY"))
    u.dce(crlf(b"+CPIN: SIM PIN"))
    u.dce(crlf(b"+CPIN: SIM PUK,1"))
    # +CPMS
    u.dte(b"AT+CPMS=\"SM\",\"ME\",\"MT\"\r")
    u.dte(b"AT+CPMS=\"SM\",\"SM\",\"SM\",\"X\"\r")
    u.dte(b"AT+CPMS?\r")
    u.dte(b"AT+CPMS=?\r")
    u.dce(crlf(b"+CPMS: 1,20,2,30,3,40"))
    u.dce(crlf(b"+CPMS: 1,20,2,30,3,40,9"))
    # +CSCS
    u.dte(b"AT+CSCS=\"GSM\"\r")
    u.dte(b"AT+CSCS=\"UCS2\",1\r")
    u.dte(b"AT+CSCS?\r")
    u.dte(b"AT+CSCS=?\r")
    u.dce(crlf(b"+CSCS: \"IRA\""))
    # +CSIM: SELECT DF GSM and its status word, quoted and unquoted
    u.dte(b"AT+CSIM=14,\"A0A40000027F20\"\r")
    u.dce(crlf(b"+CSIM: 4,\"9F22\""))
    u.dte(b"AT+CSIM=10,A0F2000016\r")
    u.dce(crlf(b"+CSIM: 4,9000,1"))                 # third parameter ignored
    u.dte(b"AT+CSIM=3,\"A0A\"\r")                   # odd length
    u.dte(b"AT+CSIM=0,\"\"\r")                      # empty
    u.dte(b"AT+CSIM=4,\"A0XY\"\r")                  # not hex
    u.dte(b"AT+CSIM=?\r")
    u.dte(b"AT+CSIM?\r")
    # +CSQ
    u.dte(b"AT+CSQ=?\r")
    u.dce(crlf(b"+CSQ: 31,7"))
    u.dce(crlf(b"+CSQ: 99,99"))
    u.dce(crlf(b"+CSQ: 40,8"))
    u.dce(crlf(b"+CSQ: 1,2,3"))
    u.dce(crlf(b"+CSQ=1"))                          # action from the DCE
    u.dce(crlf(b"+CSQ?"))                           # read from the DCE
    u.dte(b"AT+CSQ: 1\r")                           # response from the DTE
    # +VTS
    u.dte(b"AT+VTS=1\r")
    u.dte(b"AT+VTS=12,5\r")
    u.dte(b"AT+VTS=#,10,1\r")
    u.dte(b"AT+VTS=?\r")
    u.dce(crlf(b"+VTS: 1"))
    # +ZPAS
    u.dte(b"AT+ZPAS?\r")
    u.dce(crlf(b"+ZPAS: \"LTE\",\"CS_PS\""))
    u.dce(crlf(b"+ZPAS: \"LTE\",\"CS_PS\",x"))
    # +ZUSIM
    u.dte(b"AT+ZUSIM=?\r")
    u.dce(crlf(b"+ZUSIM: 1"))
    u.dce(crlf(b"+ZUSIM: 0,1"))
    # Every command in the table as an action from the DCE, a type no
    # command allows in that role
    for c in (b"+CCWA", b"+CFUN", b"+CGDCONT", b"+CGMI", b"+CHLD", b"+CIEV",
              b"+CIMI", b"+CIND", b"+CLCC", b"+CLIP", b"+CME ERROR", b"+CMEE",
              b"+CMER", b"+CMGL", b"+CMGR", b"+CMUX", b"+CNUM", b"+COPS",
              b"+CPIN", b"+CPMS", b"+CSCS", b"+CSIM", b"+VTS", b"+ZPAS",
              b"+ZUSIM", b"OK", b"E1"):
        u.dce(crlf(c + b"=1"))
    # A whole session in the end: dial, ring, read an SMS
    u.dte(b"ATE0;+CMEE=2;+CSCS=\"GSM\";+CMGR=1\r")
    u.dce(b"\r\n+CMGR: 1,,26\r\n" + PDU + b"\r\n\r\nOK\r\n")
    return u.pkts


def malformed_capture():
    u = Usb()
    # GSM SMS: TP-UDL larger than the user data
    u.dce(b"\r\n+CMGR: 1,,26\r\n" + b"0" * 16 + b"040B911346610089F600002080629173140820C8F7\r\n\r\nOK\r\n")
    # GSM SMS: address that runs past the PDU
    u.dce(b"\r\n+CMGL: 1,1,,26\r\n" + b"0" * 16 + b"04FF91\r\n\r\nOK\r\n")
    # GSM SIM: APDU shorter than its header
    u.dte(b"AT+CSIM=4,\"A0A4\"\r")
    u.dte(b"AT+CSIM=14,\"A0A400000A7F20\"\r")
    # E.212: IMSI that is not digits
    u.dce(crlf(b"+CIMI: ABCDEF"))
    u.dce(crlf(b"+CIMI: 1"))
    # Snaplen-truncated transfers
    u.dte(b"AT+CSIM=14,\"A0A40000027F20\"\r", caplen=12)
    u.dce(crlf(b"+CMGL: 1,1,,26") + PDU + b"\r\n", caplen=30)
    return u.pkts


def exppdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    hdr = struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad
    hdr += struct.pack('>HH', 0, 0)
    return hdr + payload


def exppdu_capture():
    # The direction is unknown here, so the dissector takes the DCE role
    # and has no conversation to keep data part state in.
    pl = [crlf(b"+CSQ: 20,0", b"OK"),
          b"\r\n+CMGR: 1,,26\r\n" + PDU + b"\r\n\r\nOK\r\n",
          b"\r\n+CMGR: 1,,26\r\n", PDU + b"\r\n",
          b"AT+CSQ\r", crlf(b"+CIEV: 1\x00,1"), b"AT\x00+CSIM=4,\"A0\x00\x00\"\r",
          b"\x00\x00\x00", b"",
          # TAB is not printable, so the USB heuristic never passes it
          b"\r\n\t+CSQ: 20,0\r\n", b"AT+CMER=3,\t0,0,1,0\r"]
    return [(exppdu("at", p), None) for p in pl]


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'at-coverage.pcap'), 220, main_capture())
    write_pcap(os.path.join(out, 'at-coverage-malformed.pcap'), 220, malformed_capture())
    write_pcap(os.path.join(out, 'at-coverage-exppdu.pcap'), 252, exppdu_capture())
