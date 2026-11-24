#!/usr/bin/env python3
# APRS coverage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""APRS (packet-aprs.c).

APRS is carried in AX.25 UI frames with PID 0xF0 (no layer 3); the
ax25_nol3 dissector hands them to APRS only with -o ax25_nol3.showaprs:TRUE.
All callsigns are made up (N0CALL, TEST, ...); Mic-E frames carry the
latitude in the AX.25 destination address.

Usage: mkaprs.py [<output directory>]

Writes:
  aprs-coverage.pcap            (AX.25, linktype 3) every data type indicator,
                                position formats, extensions, Mic-E, weather,
                                messages, items, objects; decodes without
                                malformed frames
  aprs-coverage-malformed.pcap  (AX.25) frames that end in an exception, and
                                a random corpus read from aprs_fuzz.pcap
                                (next to this script)
  aprs-coverage-kiss.pcap       (AX.25 KISS, linktype 202) APRS through KISS
  aprs-coverage-epdu.pcap       (Exported PDU, linktype 252) APRS called by
                                name: no AX.25 destination address, and data
                                type indicators ax25_nol3 never passes on

Every packet is built here (aprs_fuzz.pcap is random bytes); nothing comes
from a real network.
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))
















from capgen import exported_pdu, read_pcap, write_pcap  # noqa: E402
from repro import reproducer_dir

LINKTYPE_AX25, LINKTYPE_AX25_KISS, LINKTYPE_EPDU = 3, 202, 252


class Pcap:
    def __init__(self, linktype):
        self.linktype = linktype
        self.frames = []
        self.marks = []          # (first frame, last frame, description)
        self._start = None

    def add(self, data):
        self.frames.append(data)
        return len(self.frames)

    def section(self, name=None):
        """section('text') before the first frame of a section, section() after the last."""
        if name is not None:
            self._start = (len(self.frames) + 1, name)
        else:
            self.marks.append((self._start[0], len(self.frames), self._start[1]))

    def write(self, path):
        write_pcap(path, self.frames, linktype=self.linktype, snaplen=65535,
                   ts=lambda i: (1700000000 + i // 10, (i % 10) * 100000))


# ---------------------------------------------------------------------------
# AX.25

def ax25_addr(call, ssid=0, last=False, cmd=False, raw=None):
    """An AX.25 address: six shifted characters and the SSID octet."""
    if raw is None:
        raw = bytes(ord(c) << 1 for c in call.ljust(6)[:6])
    return bytes(raw) + bytes([(0x80 if cmd else 0) | 0x60 | ((ssid & 0xf) << 1) | (1 if last else 0)])


def ax25(info, dst='APRS', dst_ssid=0, src='N0CALL', src_ssid=1, via=(), ctl=0x03, pid=0xF0,
         dstraw=None):
    """An AX.25 frame, a UI frame with PID 0xF0 (no layer 3) by default."""
    a = ax25_addr(dst, dst_ssid, cmd=True, raw=dstraw)
    a += ax25_addr(src, src_ssid, last=not via)
    for i, (call, ssid) in enumerate(via):
        a += ax25_addr(call, ssid, last=(i == len(via) - 1))
    return a + bytes([ctl, pid]) + info


def b(s):
    return s.encode('latin-1') if isinstance(s, str) else s


# ---------------------------------------------------------------------------
# Main capture

def mice_info(dti, deg, mins, hund, sp, dc, se, sym=b'>/', rest=b''):
    """Mic-E information field from the raw (already offset) octets."""
    return dti + bytes([deg, mins, hund, sp, dc, se]) + sym + rest


def build_main():
    cap = Pcap(LINKTYPE_AX25)

    def A(info, **kw):
        return cap.add(ax25(b(info), **kw))

    # -- further cases ------------------------------------------------------
    cap.section("Review reproducers: compressed course 'z' (356 degrees), "
                "Mic-E course 251 (DC=30, SE=79, destination S32U6T), item "
                "name of nine 0x80 octets")
    A('!/5L!!<*e7>z!T comment')
    cap.add(ax25(bytes([0x60, 28 + 112, 28 + 20, 28 + 50, 30, 30, 79]) + b'>/', dst='S32U6T'))
    cap.add(ax25(b')' + b'\x80' * 9 + b'!' + b'4903.50N/07201.75W>comment'))
    cap.section()

    # -- uncompressed positions without timestamp ----------------------------
    cap.section("'!' and '=' uncompressed positions: course/speed, PHG, RNG, "
                "DFS, area object, DF bearing, weather, storm, plain comments, "
                "Ultimeter 2000, digipeater path")
    A('!4903.50N/07201.75W>088/036 moving north')
    A('!4903.50N/07201.75W#PHG5132 digipeater', via=(('WIDE1', 1), ('WIDE2', 2)))
    A('!4903.50N/07201.75W#RNG0050 range 50 miles')
    A('!4903.50N/07201.75W\\DFS2360 direction finding')
    A('!4903.50N\\07201.75Wl T1A/C12 area object')
    A('!4903.50N/07201.75W\\088/036/270/729 DF report')
    A('!4903.50N/07201.75W-Hello world, a home station')
    A('!4903.50N/07201.75W_220/004g005t077r000p000P000h50b09900wRSW')
    A('!4903.50N/07201.75W@088/036/HC/150^200/0980>090&050%040 storm')
    A('!4903.50N\\07201.75W@088/036/TS/090^120/0995>000&030%020 storm')
    A('!!0000005B00ED013A2733037B000E----0000002800000000')
    A('=4903.50N/07201.75W-PHG2360/A=001234 messaging station')
    A('=4903.  N/07201.  W-ambiguous position 01')
    A('=4903.50N/07201.75WyRNG0010 yagi')
    A('=4903.50S\\07201.75E&DFS2360 DF South-East')
    A('=4903.50N/07201.75W\\Tyy/Cxx area')
    A('=4903.50N/07201.75W\\Comment that is not an extension')
    cap.section()

    # -- positions with timestamp -------------------------------------------
    cap.section("'/' and '@' positions with every timestamp format: DHM zulu, "
                "DHM local, DHM unknown zone, HMS, MDHM")
    A('/092345z4903.50N/07201.75W>088/036 DHM zulu')
    A('/092345/4903.50N/07201.75W>088/036 DHM local')
    A('/092345x4903.50N/07201.75W>088/036 DHM unknown zone')
    A('/234517h4903.50N/07201.75W>088/036 HMS')
    A('/100923454903.50N/07201.75W>088/036 MDHM')
    A('@092345z4903.50N/07201.75W>088/036 with messaging')
    A('@234517h4903.50N/07201.75W_220/004g005t077r000p000P000h50b09900wRSW')
    A('@092345z4903.50N/07201.75W@088/036/HC/150^200/0980>090&050%040 storm')
    A('@092345/4903.50N/07201.75W\\088/036/270/729 DF with timestamp')
    A('/092345z/5L!!<*e7>7P[ compressed with timestamp')
    A('@092345z/5L!!<*e7>{?! compressed with radio range')
    cap.section()

    # -- compressed positions ------------------------------------------------
    cap.section("Compressed positions: course/speed (including '!' and 'z'), "
                "radio range, no course/speed, other cs octet, every "
                "compression type bit (GPS fix, NMEA source, origin), DF "
                "bearing, weather, storm")
    for c in '!7Pz':
        A('!/5L!!<*e7>' + c + 'P[ compressed course ' + c)
    A('=/5L!!<*e7>{?! compressed radio range')
    A('=/5L!!<*e7>  T compressed, no course/speed')
    A('=/5L!!<*e7>|!T compressed, cs octet outside the table')
    A('=\\5L!!<*e7v7P[ compressed alternate table')
    A('=A5L!!<*e7#7P[ compressed overlay A')
    # Compression type octet T = 33 + value; one frame for each origin,
    # each NMEA source and both GPS fix values
    for v in (0x00, 0x09, 0x12, 0x1b, 0x24, 0x2d, 0x36, 0x3f):
        A('!/5L!!<*e7>7P' + chr(33 + v) + ' compression type %02x' % v)
    A('=/5L!!<*e7\\7P[/270/729 compressed DF bearing')
    A('=/5L!!<*e7_7P[g005t077r000p000P000h50b09900wRSW')
    A('=/5L!!<*e7@7P[/HC/150^200/0980>090&050%040 storm')
    A('=\\5L!!<*e7@7P[/TS/090^120/0995>000&030%020 storm')
    cap.section()

    # -- Mic-E ---------------------------------------------------------------
    cap.section("Mic-E: four data type indicators; every destination "
                "character (digits, A-K custom, L, P-Z standard, other); "
                "the eight standard and custom message codes; longitude "
                "offsets and the 180-199 degree ranges; minutes over 60; "
                "speed over 800, course over 400; status, telemetry "
                "(',' and 0x1d) and nothing after the symbol")
    # Standard (P-Z) and custom (A-K) message bits in the first three
    # destination characters: all eight combinations of each
    for dst in ('PPP3', 'PP03', 'P0P3', 'P003', '0PP3', '0P03', '00P3', '0003'):
        cap.add(ax25(mice_info(b'`', 28 + 72, 28 + 1, 28 + 75, 28 + 2, 28 + 2, 28 + 51,
                               rest=b'Std msg'), dst=dst + 'P0'))
    for dst in ('ABC3', 'DE13', 'F2G3', 'H453', '6IJ3', '7K93', '89A3'):
        cap.add(ax25(mice_info(b'`', 28 + 72, 28 + 1, 28 + 75, 28 + 2, 28 + 2, 28 + 51,
                               rest=b'Custom msg'), dst=dst + 'P0'))
    # Every remaining destination character, the N/S, longitude offset and
    # E/W columns, and characters not in the table ('M', 'O')
    for dst in ('QRSTUV', 'WXYZLL', '45678L', 'L9ZZZZ', 'MO0MOM', '123K5J'):
        cap.add(ax25(mice_info(b'`', 28 + 12, 28 + 30, 28 + 0, 28 + 10, 28 + 10, 28 + 0,
                               rest=b' table'), dst=dst, dst_ssid=2))
    # Longitude degrees: 0-109 with offset 0, 180-189 (100-109) and
    # 190-199 (0-9) after adding 100 or not
    for deg, dst in ((28 + 50, 'S32U0T'), (28 + 10, 'S32UPT'), (28 + 80, 'S32UPT'),
                     (28 + 90, 'S32UPT'), (28 + 180, 'S32U0T'), (28 + 195, 'S32U0T')):
        cap.add(ax25(mice_info(b'`', deg, 28 + 61, 28 + 99, 28 + 0, 28 + 0, 28 + 0,
                               rest=b'degrees'), dst=dst))
    # Speed over 800 (SP=108+) and course over 400 (DC units 4+)
    cap.add(ax25(mice_info(b'`', 28 + 72, 28 + 1, 28 + 75, 28 + 81, 28 + 45, 28 + 11,
                           rest=b'fast'), dst='S32U6T'))
    # The other data type indicators, telemetry after the symbol, no status
    cap.add(ax25(mice_info(b"'", 28 + 72, 28 + 1, 28 + 75, 28 + 2, 28 + 2, 28 + 51,
                           rest=b',1234567890'), dst='T2SP0W', via=(('WIDE2', 2),)))
    cap.add(ax25(mice_info(b'\x1c', 28 + 72, 28 + 1, 28 + 75, 28 + 2, 28 + 2, 28 + 51,
                           rest=b'\x1d\x01\x02\x03\x04\x05'), dst='T2SP0W'))
    cap.add(ax25(mice_info(b'\x1d', 28 + 72, 28 + 1, 28 + 75, 28 + 2, 28 + 2, 28 + 51),
                 dst='T2SP0W'))
    cap.add(ax25(mice_info(b'`', 28 + 72, 28 + 1, 28 + 75, 28 + 2, 28 + 2, 28 + 51,
                           sym=b'k/', rest=b']=Kenwood status'), dst='T2SP0W', dst_ssid=7))
    cap.section()

    # -- weather without position --------------------------------------------
    cap.section("'_' weather reports without position: every weather field "
                "(c s g t r P p h b l L S #) and the software/unit tail, wind "
                "as DDD/SSS, every timestamp format")
    A('_10090556c220s004g005t077r000p000P000h50b09900wRSW')
    A('_10090556c220s004g005t-05r001p010P020h00b10132L123S010#123xDvs')
    A('_10090556l999t077x')
    A('_092345z220/004g005t077r000p000P000h50b09900wRSW')
    A('_092345/c220s004g005t077')
    A('_234517hc220s004g005t077')
    cap.section()

    # -- items and objects ---------------------------------------------------
    cap.section("')' items and ';' objects: live and killed names, "
                "'_' before '!', '!' before '_', a ten character name with "
                "no terminator, compressed and uncompressed positions, "
                "high octets in the name")
    A(')AID #2!4903.50N/07201.75WA first aid')
    A(')ITEM_4903.50N/07201.75W>killed item')
    A(')AB_/5L!!<*e7>7P[ killed, \'!\' later in the name window')
    A(')AB!/_L!!<*e7>7P[ live, \'_\' later in the name window')
    A(')TENCHARSXX4903.50N/07201.75W>no terminator')
    A(')MOBIL!/5L!!<*e7>7P[ compressed item')
    A(')G1!4903.50N/07201.75W_220/004g005t077r000p000P000h50b09900wRSW')
    cap.add(ax25(b')' + b'\xc3\xa9t\xc3\xa9_' + b'4903.50N/07201.75W>killed, high octets'))
    A(';LEADER   *092345z4903.50N/07201.75W>088/036 object')
    A(';LEADER   _092345z4903.50N/07201.75W>088/036 killed object')
    A(';OBJ-1    *234517h/5L!!<*e7>7P[ compressed object')
    A(';STORM    *100923454903.50N/07201.75W@088/036/HC/150^200/0980>090&050%040')
    A(';WX       *092345z4903.50N/07201.75W_220/004g005t077r000p000P000h50b09900wRSW')
    cap.section()

    # -- messages ------------------------------------------------------------
    cap.section("':' messages, acknowledgements, rejects, bulletins, "
                "announcements, NWS, telemetry parameters")
    A(':TEST-1   :Hello there{001')
    A(':N0CALL-1 :ack001')
    A(':N0CALL-1 :rej001')
    A(':TEST-1   :Reply ack{MM}AA')
    A(':BLN1     :Bulletin number one')
    A(':BLNA     :Announcement A')
    A(':BLN1GRP  :Group bulletin')
    A(':NWS-WARN :092345z,THUNDER_STORM,AR_ASHLEY{S9JbA')
    A(':N0CALL-1 :PARM.Battery,Btemp,Air,Pres,Alt,Camra,Chut,Sun,10m,ATV')
    A(':N0CALL-1 :UNIT.Volts,deg.F,deg.F,Mbar,Kft,Click,OPEN,on,on,hi')
    A(':N0CALL-1 :EQNS.0,5.2,0,0,.53,-32,3,4.39,49,-32,3,18,1,2,3')
    A(':N0CALL-1 :BITS.10110000,N0CALL test balloon')
    A(':N0CALL-1 :?APRSP')
    cap.section()

    # -- the other data type indicators --------------------------------------
    cap.section("Status (with and without timestamp, short, empty), "
                "capabilities, queries, raw GPS and Ultimeter, Agrelo, "
                "telemetry, Maidenhead, test data, user defined, third "
                "party, Peet Bros, reserved types, empty frames")
    A('>092345zNet Control Center')
    A('>IO91SX/G Status text')
    A('>short')
    A('>')
    A('<IGATE,MSG_CNT=43,LOC_CNT=14')
    A('?APRS?')
    A('?WX?')
    A('?IGATE?')
    A('$GPRMC,013244,A,4903.50,N,07201.75,W,000.0,000.0,101025,013.5,E*69')
    A('$ULTW0031003702CE0069----000086A00001----011901CC00000005')
    A('%\x01\x02\x03\x04 DF')
    A('T#005,199,000,255,073,123,01101001')
    A('T#MIC199,000,255,073,123,01101001')
    A('[IO91SX] 35 miles NNW of London')
    A(',test data \x00\xff')
    A('{Q1qwerty')
    A('}TEST-2>APRS,TCPIP,N0CALL*::N0CALL-1 :Third party message{01')
    A('#W1\x01\x02\x03')
    A('*\x00\x01\x02\x03\x04')
    A('&map feature')
    A('+shelter 092345z')
    A('.space weather')
    A('}')
    A('<')
    A('?')
    A(',')
    cap.section()

    # -- not APRS ------------------------------------------------------------
    cap.section("Not APRS: an I frame with PID 0xF0 that starts with '!', "
                "and a UI frame whose first octet is no data type indicator")
    A('!4903.50N/07201.75W>088/036 in an I frame', ctl=0x10)
    A('Hello, plain text beacon')
    cap.section()

    # -- positions with no or a short comment --------------------------------
    cap.section("Uncompressed positions with no comment and with 1-6 octet "
                "comments ('!', '=', '/', '@', item, object): no extension "
                "is read; a storm report after a '/' timestamp; a status of six "
                "octets")
    for dti, ts in (('!', ''), ('=', ''), ('/', '092345z'), ('@', '234517h')):
        for comment in ('', 'A', 'PHG51', '088/03'):
            A(dti + ts + '4903.50N/07201.75W>' + comment)
    A(')NOCMT!4903.50N/07201.75W>')
    A(';NOCMT    *092345z4903.50N/07201.75W>')
    A('/092345z4903.50N/07201.75W@088/036/HC/150^200/0980>090&050%040')
    A('>09234')                             # status shorter than a timestamp
    cap.section()
    return cap


# ---------------------------------------------------------------------------
# Malformed capture: paths that throw

def build_malformed(corpus_dir):
    cap = Pcap(LINKTYPE_AX25)

    def A(info, **kw):
        return cap.add(ax25(b(info), **kw))

    cap.section('Truncated compressed positions, weather, timestamps, Mic-E, items, objects')
    A('=/5L!!<*e7>7')                       # compressed, no T octet
    A('=/5L!!<*e7\\7P[088/03')              # compressed DF, short bearing
    A('_10090556c22')                       # weather field cut short
    A('_10090556b0990')                     # pressure cut short
    A('_1009')                              # timestamp cut short
    A('_10090556')                          # no weather data
    A('`(_f')                               # Mic-E too short
    A(')ITEM')                              # item with no position
    A(';OBJ')                               # object cut short
    A('!4903.50N/07201.75W_')               # weather symbol, no weather data
    A('!4903.50N/07201.75W@088/036/HC/15')  # storm report cut short
    cap.section()

    # Random corpus written by aprs_gen.py
    path = os.path.join(corpus_dir, 'aprs_fuzz.pcap')
    if os.path.exists(path):
        cap.section('Random corpus from aprs_fuzz.pcap')
        for frame in read_pcap(path):
            cap.add(frame)
        cap.section()
    return cap


# ---------------------------------------------------------------------------
# KISS and Exported PDU captures

def build_kiss():
    cap = Pcap(LINKTYPE_AX25_KISS)
    cap.section('APRS in KISS data frames (port 0 and 1)')
    cap.add(b'\x00' + ax25(b'!4903.50N/07201.75W>088/036 via KISS'))
    cap.add(b'\x10' + ax25(b'>Status via KISS port 1'))
    cap.add(b'\x00' + ax25(mice_info(b'`', 28 + 72, 28 + 1, 28 + 75, 28 + 2, 28 + 2, 28 + 51,
                                     rest=b'Mic-E via KISS'), dst='S32U6T'))
    cap.section()
    return cap


def epdu_frame(payload):
    return exported_pdu(payload, proto='aprs')


def build_epdu():
    cap = Pcap(LINKTYPE_EPDU)
    cap.section('APRS called by name: Mic-E without an AX.25 destination, '
                'data type indicators ax25_nol3 does not pass on')
    cap.add(epdu_frame(mice_info(b'`', 28 + 72, 28 + 1, 28 + 75, 28 + 2, 28 + 2, 28 + 51,
                                 rest=b'no destination')))
    cap.add(epdu_frame(b'Aunknown data type'))
    cap.add(epdu_frame(b'!4903.50N/07201.75W>088/036 by name'))
    cap.section()
    return cap


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    here = os.path.dirname(os.path.abspath(__file__))
    for name, cap in (('aprs-coverage.pcap', build_main()),
                      ('aprs-coverage-malformed.pcap', build_malformed(reproducer_dir(here, ['aprs_gen.py']))),
                      ('aprs-coverage-kiss.pcap', build_kiss()),
                      ('aprs-coverage-epdu.pcap', build_epdu())):
        cap.write(os.path.join(out, name))
        print('%s: %d frames' % (name, len(cap.frames)))
        for first, last, text in cap.marks:
            print('  %4d-%-4d %s' % (first, last, text))


if __name__ == '__main__':
    main()
