#!/usr/bin/env python3
# Generates test/captures/telnet_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generator for the Telnet coverage captures.  Usage: mktelnet.py <outdir> [-v]
import struct
import sys
import os
from pcaplib import TcpFlow, write_pcap

IAC, DONT, DO, WONT, WILL, SB, GA, EL, EC, AYT, AO, IP, BRK, DM, NOP, SE, EOR, ABORT, SUSP, EOF = \
    255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244, 243, 242, 241, 240, 239, 238, 237, 236

def cmd(*b):
    return bytes([IAC]) + bytes(b)

def sb(opt, data=b''):
    return bytes([IAC, SB, opt]) + data + bytes([IAC, SE])

pk = []
marks = []
def mark(name):
    marks.append((len(pk) + 1, name))

CL = [192, 0, 2, 11]
SV = [192, 0, 2, 10]

class Flow(TcpFlow):
    def __init__(self, cport, sport=23):
        TcpFlow.__init__(self, cport, sport, CL, SV)
    def cl(self, data):
        pk.append(self.c2s(data))
    def sv(self, data):
        pk.append(self.s2c(data))

# ===== text
mark('text: lines, CR LF, CR NUL, bare CR, long lines, escaped IAC')
f = Flow(40000)
f.sv(b'Welcome to the test host\r\nlogin: ')
f.cl(b'root\r\n')
f.sv(b'Password: ')
f.cl(b'secret\r\x00')
f.sv(b'Last login: Mon Nov  9 10:00:00\r\n$ ')
f.cl(b'ls -l\r')
f.cl(b'abc\rdef\r\nxyz\rpqr\r\x00end\r\n')
f.cl(b'echo one\necho two\r\necho three\r\x00echo four\r\n')
f.sv(b'a' * 600 + b'\r\n' + b'b' * 100)
f.sv(b'text with an escaped IAC: \xff\xff and more text\r\n')
f.sv(b'\xff\xffstarting with an escaped IAC\r\n')
f.sv(b'ending with an escaped IAC\xff\xff')
f.cl(b'\r\n')
f.cl(b'\r')
f.cl(b'x')
f.sv(b'\r\n\r\n\r\n')
f.sv(b'no newline at the end')
f.sv(b'\x00\x01\x02 binary \x7f\x80\xfe')

# ===== commands without options
mark('commands: NOP, DM, BRK, IP, AO, AYT, EC, EL, GA, EOR, ABORT, SUSP, EOF, SE')
g = Flow(40001)
for c in (NOP, DM, BRK, IP, AO, AYT, EC, EL, GA, EOR, ABORT, SUSP, EOF, SE, 200):
    g.cl(cmd(c))
g.sv(cmd(NOP) + b'text after a command' + cmd(GA) + b'more\r\n')
g.sv(b'before' + cmd(AYT))
g.sv(cmd(IP) + cmd(AO) + cmd(AYT) + cmd(EC) + cmd(EL) + cmd(GA) + cmd(NOP))         # more than five items in the Info column
g.sv(cmd(NOP))

# ===== WILL/WONT/DO/DONT for every known option, an unknown one and VMware
mark('WILL, WONT, DO, DONT for options 0-49, unknown options and VMware (232)')
h = Flow(40002)
for opt in list(range(0, 50)) + [100, 255 - 1 - 0, 232]:
    if opt == 255:
        continue
    h.sv(cmd(DO, opt))
    h.cl(cmd(WILL, opt))
h.sv(cmd(DONT, 1) + cmd(WONT, 3))
h.cl(cmd(WONT, 1) + cmd(DONT, 3) + cmd(WILL, 24) + cmd(DO, 31) + cmd(WILL, 31) + cmd(DO, 24))

# ===== suboptions
mark('suboptions: terminal type, X display, NAWS, speed, environment, linemode, ...')
s = Flow(40003)
s.sv(sb(24, b'\x01'))                                   # TERMINAL-TYPE SEND
s.sv(sb(24, b'\x01extra'))                              # SEND with extra data
s.cl(sb(24, b'\x00xterm-256color'))                     # IS
s.cl(sb(24, b'\x00'))                                   # IS without a name
s.sv(sb(24, b'\x05bogus'))                              # invalid subcommand
s.sv(sb(24, b'\x07'))
s.cl(sb(35, b'\x00workstation:0.0'))                    # X DISPLAY LOCATION IS
s.sv(sb(35, b'\x01'))
s.cl(sb(31, b'\x00\x50\x00\x18'))                       # NAWS 80x24
s.cl(sb(31, b'\x00\x50\x00'))                           # NAWS too short
s.cl(sb(31, b'\xff\xff\x00\x18\x00'))                   # NAWS with an escaped IAC: 255x24 (+1)
s.cl(sb(31, b'\x01\xff\xff\x00\xff\xff'))               # NAWS 511 x 255 with escapes
s.cl(sb(32, b'\x00' + b'38400,38400'))                  # TERMINAL-SPEED (no dissector)
s.sv(sb(32, b'\x01'))
s.cl(sb(36, b'\x00\x03USER\x01root'))                   # ENVIRON
s.cl(sb(39, b'\x00\x00USER\x01root\x03CUSTOM\x01x'))     # NEW-ENVIRON
s.sv(sb(34, b'\x01\x07'))                               # LINEMODE
s.sv(sb(33, b'\x01'))                                   # remote flow control ON
s.sv(sb(33, b'\x00'))
s.sv(sb(33, b'\x03'))
s.sv(sb(33, b'\x09'))
s.sv(sb(33, b'\x01\x00'))                               # wrong length
s.sv(sb(5, b'\x01\x00'))                                # STATUS
s.sv(sb(5))                                             # empty suboption
s.sv(sb(5, b''))
s.sv(sb(10, b'\x00\x00'))                               # fixed length options without a dissector
s.sv(sb(10, b'\x00'))                                   # fixed length, wrong length
s.sv(sb(26, b'\x01\x02\x03\x04'))
s.sv(sb(0, b'\x01'))                                    # option without suboptions
s.sv(sb(1, b'\x01\x02'))
s.sv(sb(200, b'\x01\x02\x03'))                          # unknown option
s.sv(sb(200, b'\x01\xff\xff\x03'))
s.sv(sb(19, b'\x01'))                                   # variable, shorter than the minimum
s.sv(sb(19, b'\x01\x02\x03'))
s.sv(sb(23, b'where'))
s.sv(sb(42, b'\x01;UTF-8'))
s.sv(sb(41, b'\x00'))
s.sv(sb(47, b'\x01\x02'))                               # KERMIT
s.sv(sb(48, b'http://x'))

mark('suboptions: tab stops, output marking, 3270 regime, remote flow control, STARTTLS')
t = Flow(40004)
t.sv(sb(11, b'\x01'))                                   # HTSTOPS SEND
t.cl(sb(11, b'\x00\x00\x08\x10\xff\xff\xfb\xfc\xfd\xfe'))   # IS with all kinds of values
t.cl(sb(11, b'\x00\x08\x10\x18'))
t.cl(sb(11, b'\x02xyz'))                                # invalid subcommand
t.cl(sb(11, b'\x03'))
t.sv(sb(27, b'\x06'))                                   # OUTMARK
t.sv(sb(27, b'DTopsecret\x1dBBottom banner\x1dL'))
t.sv(sb(27, b'\x15R'))
t.sv(sb(27, b'Tbanner without a separator'))
t.cl(sb(29, b'\x00'))                                   # TN3270 regime IS
t.cl(sb(29, b'\x00ASCII'))
t.cl(sb(29, b'\x05\x06\x00data'))                       # unknown commands before IS
t.sv(sb(29, b'\x05\x06'))                               # only bogus values
t.sv(sb(46, b'\x01\x02'))                               # wrong length
tl = Flow(40013)
tl.sv(sb(46, b'\x01'))                                  # START_TLS FOLLOWS
tl.cl(sb(46, b'\x01'))                                  # the other side answers: TLS would follow

# ===== authentication
mark('authentication option')
a = Flow(40005)
a.sv(sb(37, b'\x01\x02\x03\x07\x00'))                    # SEND: KRB5 one-way/client-to-server, SSL
a.sv(sb(37, b'\x01\x02\x03\x0f\x1f\x01\x0e\x04'))        # more types, modifiers
a.sv(sb(37, b'\x01'))
a.sv(sb(37, b'\x01\x02'))                                # a type without a modifier
a.cl(sb(37, b'\x00\x00\x00'))                            # IS NULL
a.cl(sb(37, b'\x00\x07\x00\x01'))                        # IS SSL START
a.cl(sb(37, b'\x02\x07\x00\x03'))                        # REPLY SSL REJECT
a.cl(sb(37, b'\x03' + b'jdoe'))                          # NAME
a.cl(sb(37, b'\x03'))
a.cl(sb(37, b'\x00\x02\x00\x01'))                        # IS KRB5 REJECT-type message
a.cl(sb(37, b'\x00\x02\x00\x05'))
a.cl(sb(37, b'\x02\x02\x00\x02'))                        # REPLY KRB5 ACCEPT
a.cl(sb(37, b'\x00\x01\x00\x00\x01\x02\x03'))            # KRB4: unhandled data
a.cl(sb(37, b'\x00\x05\x00'))                            # SRP, no data
a.cl(sb(37, b'\x09\x01\x00'))                            # unknown command

a2 = Flow(40026)
a2.cl(sb(37, b'\x02\x07\x00\x02'))                       # REPLY SSL ACCEPT: TLS follows

# ===== encryption
mark('encryption option')
e = Flow(40006)
e.sv(sb(38, b'\x01\x00\x01\x02\x03\x04\x08\x09\x0a\x0b\x63'))   # SUPPORT with every type and an unknown one
e.sv(sb(38, b'\x01'))
e.cl(sb(38, b'\x00\x01\x01\x02\x03\x04\x05\x06\x07\x08'))      # IS DES_CFB64 with data
e.cl(sb(38, b'\x00'))
e.cl(sb(38, b'\x02\x03\x00\x01'))                             # REPLY
e.cl(sb(38, b'\x02'))
e.sv(sb(38, b'\x03\x01\x00'))                                 # START default key
e.sv(sb(38, b'\x03\x01\x07\x08'))                             # START key id
e.sv(sb(38, b'\x03'))
e.sv(sb(38, b'\x04'))                                         # END
e.sv(sb(38, b'\x05'))                                         # REQUEST-START
e.sv(sb(38, b'\x05\x01\x02'))
e.sv(sb(38, b'\x06'))                                         # REQUEST-END
e.sv(sb(38, b'\x07\x01\x02\x03'))                             # ENC_KEYID
e.sv(sb(38, b'\x08\x01\x02\x03'))                             # DEC_KEYID
e.sv(sb(38, b'\x07'))
e.sv(sb(38, b'\x09'))                                         # unknown command (expert info)

# ===== COM port control
mark('COM port control option (RFC 2217)')
c = Flow(40007)
cpc = [
    (0, b''), (0, b'device 1.0'), (1, struct.pack('>I', 9600)), (1, struct.pack('>I', 0)), (1, b'\x00'),
    (2, b'\x08'), (2, b'\x00'), (2, b'\x03'), (2, b''),
    (3, b'\x01'), (3, b'\x03'), (3, b'\x09'), (3, b''),
    (4, b'\x01'), (4, b'\x03'), (4, b'\x07'), (4, b''),
    (5, b'\x01'), (5, b'\x04'), (5, b'\x13'), (5, b'\x20'), (5, b''),
    (6, b'\x05'), (6, b'\x00'), (6, b'\xff'), (6, b''),
    (7, b'\x91'), (7, b'\xff'), (7, b''),
    (8, b''), (9, b''),
    (10, b'\x0f'), (10, b''), (11, b'\xf0'), (11, b''),
    (12, b'\x01'), (12, b'\x03'), (12, b'\x04'), (12, b''),
    (13, b'\x01'),
]
for code, data in cpc:
    c.cl(sb(44, bytes([code]) + data))
    c.sv(sb(44, bytes([code + 100]) + data))
c.cl(sb(44, bytes([50]) + b'abc'))                              # invalid subcommands
c.sv(sb(44, bytes([150]) + b'abc'))
c.cl(sb(44, bytes([99])))

# ===== VMware
mark('VMware serial port proxy option (232)')
v = Flow(40008)
vm = [
    (0, b'\x28\x29\x2c'), (1, b'\x46'), (2, b'\x2a'), (3, b'\x2a'), (0, b''),
    (40, b'seq-1234'), (41, b'seq-1234' + b'secret'), (43, b'seq-9'), (44, b'seq-1234' + b'secret'),
    (45, b'seq-1234'), (46, b'seq-1234'), (48, b''),
    (70, b'Cuuid://service'), (70, b'S'), (71, b''), (73, b''),
    (80, b'11223344-5566-7788-99aa-bbccddeeff00'), (81, b''), (82, b'my virtual machine'), (83, b''),
    (84, b'aabbccdd-0000-1111-2222-333344445555'), (85, b''), (86, b'52e2aa11-bbbb-cccc-dddd-eeeeffff0000'), (87, b''),
    (99, b'unknown subcommand'), (99, b''), (2, b'\x2a\x2b'),
]
for code, data in vm:
    v.cl(sb(232, bytes([code]) + data))
    v.sv(sb(232, bytes([code]) + data))
# vMotion: the sequence length is learned from the first BEGIN, GOAHEAD and PEER match on the sequence
v2 = Flow(40009)
v2.cl(sb(232, bytes([40]) + b'12345678'))
v2.sv(sb(232, bytes([41]) + b'12345678' + b'cafebabe'))
v3 = Flow(40010)
v3.cl(sb(232, bytes([44]) + b'12345678' + b'cafebabe'))        # the PEER of the destination matches the GOAHEAD of the source
v3.sv(sb(232, bytes([45]) + b'12345678'))
v4 = Flow(40011)
v4.cl(sb(232, bytes([44]) + b'87654321' + b'cafebabe'))        # a PEER without a GOAHEAD
v4.sv(sb(232, bytes([41]) + b'87654321'))
v4.sv(sb(232, bytes([41]) + b''))

# ===== TN3270E (the review's reproducers of the length counter fixes are in this section)
mark('TN3270E suboptions (DEVICE-TYPE, FUNCTIONS, CONNECT, REASON); the reproducers of the length fixes')
n = Flow(40012)
n.sv(sb(40, b'\x02\x04IBM-3278-2\x01LU01'))                      # DEVICE-TYPE IS ... CONNECT ...
n.sv(sb(40, b'\x02\x06\x04'))                                    # REJECT with a reason
n.sv(sb(40, b'\x02\x06\x05\x04'))
n.cl(sb(40, b'\x03\x04\x00\x01'))                                # FUNCTIONS IS
n.cl(sb(40, b'\x01LU02'))                                        # CONNECT
n.cl(sb(40, b'\x01'))
n.cl(sb(40, b'\x05\x03'))                                        # REASON INV-DEVICE-NAME
n.cl(sb(40, b'\x05'))                                            # REASON without a code
n.cl(sb(40, b'\x08\x02'))                                        # SEND DEVICE-TYPE
n.cl(sb(40, b'\x00\x01\x02'))                                    # ASSOCIATE
# a REQUEST creates a TN3270 conversation: each one ends its own flow
for k, data in enumerate((b'\x02\x07IBM-3278-2', b'\x03\x07\x00\x01\x02\x03\x04', b'\x03\x07\x09', b'\x03\x07\x00\x01', b'\x07')):
    Flow(40014 + k).cl(sb(40, data))

# ===== tn3270: terminal type creates a TN3270 conversation; later data goes to the TN3270 dissector
# (the frame that sets it up ends with the suboption: the creating frame itself is not dissected as TN3270)
mark('TN3270 conversation: terminal type IBM-3278-2, regime ARE, IBM-3279-4-E')
t1 = Flow(40020)
t1.sv(sb(24, b'\x01'))
t1.cl(sb(24, b'\x00IBM-3278-2'))
t1.sv(cmd(DO, 40) + cmd(DO, 25))
t1.cl(b'\x7d\x40\x40' + cmd(EOR))                                  # Enter AID in the TN3270 conversation
t1.sv(b'\xf1\xc3\x11\x40\x40' + 'HELLO'.encode('cp037') + cmd(EOR))
t1.cl(cmd(WILL, 25) + cmd(WILL, 0))
t1.sv(b'\xf5\xc3')                                              # data that waits for the next segment
t1.sv(b'\x11\x40\x40' + cmd(EOR))
t2 = Flow(40021)
t2.sv(sb(29, b'\x01'))                                          # TN3270 regime ARE
t2.cl(b'\x7d\x40\x40' + cmd(EOR))
t3 = Flow(40022)
t3.cl(sb(24, b'\x00IBM-3279-4-E'))
t3.sv(b'\xf1\xc3' + cmd(EOR))
t3b = Flow(40023)
t3b.cl(sb(24, b'\x00IBM-3278-5'))
t3c = Flow(40024)
t3c.cl(sb(24, b'\x00IBM-3278-9'))                               # not a known model
t3c.sv(b'\x05\xc3 plain text, not a TN3270 conversation\r\n')
t4 = Flow(40025)
t4.cl(sb(40, b'\x02\x07IBM-3278-3'))                            # TN3270E REQUEST creates the conversation
t4.sv(b'\x00\x00\x00\x00\x00\x00\x00\xf1\xc3' + cmd(EOR))
mark('TN5250 conversation: terminal type IBM-5555-C01 and others')
for i, tt in enumerate((b'IBM-5555-C01', b'IBM-5555-B01', b'IBM-3477-FC', b'IBM-3477-FG', b'IBM-3180-2', b'IBM-3179-2', b'IBM-3196-A1',
                        b'IBM-5292-2', b'IBM-5291-1', b'IBM-5251-11')):
    t5 = Flow(40030 + i)
    t5.cl(sb(24, b'\x00' + tt))
    if i < 3:
        t5.sv(b'\x00\x0c\x12\xa0\x00\x00\x04\x00\x00\x03\x04\x40' + cmd(EOR))   # GDS record with a clear unit command
t6 = Flow(40040)                                                 # not Terminal Type: the X display location is not checked
t6.cl(sb(35, b'\x00IBM-3278-2'))
t6.sv(b'plain text\r\n')

# ===== fix reproducers
mark('fix: plain text without an IAC, a suboption over 10240 octets with an escaped IAC, odd AUTHENTICATION SEND, TN3270E lists')
r = Flow(40050)
r.cl(b'hello world\r\n')                                         # was a Malformed Packet
r.sv(b'prompt$ ')
body = b'\x00' + b'A' * 100 + b'\xff\xff' + b'B' * 10200
r.cl(b'\xff\xfa\x18' + body + b'\xff\xf0')                       # TERMINAL-TYPE with an escaped IAC, over the limit
body2 = b'C' * 100 + b'\xff\xff' + b'D' * 10200
r.cl(b'\xff\xfa\xc8' + body2 + b'\xff\xf0')                      # an option without a dissector
r.cl(b'\xff\xfa\x25\x01\x05\xff\xf0' + b'trailing text\r\n')    # AUTHENTICATION SEND with an odd length
r2 = Flow(40051)
r2.cl(b'\xff\xfa\x28\x03\x07\x00\x01\xff\xf0' + b'trailing text\r\n')   # TN3270E FUNCTIONS list that ends the suboption

# ===== boundary conditions that still decode
mark('suboptions with an escaped IAC at the end and a command followed by text')
b = Flow(40060)
b.sv(bytes([IAC, SB, 24]) + b'\x00ab' + bytes([IAC]) + bytes([SE]) + b'text')
b.sv(bytes([IAC, SB, 24, 1, IAC, IAC, IAC, SE]))
b.sv(bytes([IAC, DO]) + b'a')

mal = []
class MFlow(TcpFlow):
    def __init__(self, cport, sport=23):
        TcpFlow.__init__(self, cport, sport, CL, SV)
    def cl(self, data):
        mal.append(self.c2s(data))
    def sv(self, data):
        mal.append(self.s2c(data))
m = MFlow(41000)
m.cl(b'abc' + bytes([IAC]))
m.sv(b'abc' + bytes([IAC, SB]))
m.sv(b'abc' + bytes([IAC, SB, 24]))
m.sv(bytes([IAC, SB, 24, 1]))
m.sv(bytes([IAC, SB, 31, 0, 80]))
m.sv(bytes([IAC, SB, 37, 1, 2, 3]))
m.sv(bytes([IAC, WILL]))
m.sv(bytes([IAC]) * 4)
m.cl(b'data ending in an IAC' + bytes([IAC]))
m.sv(bytes([IAC, WILL]))                                         # option code missing
m.sv(bytes([IAC, SB]))
m.sv(bytes([IAC, SB, 24]))
m.sv(bytes([IAC, SB, 24]) + b'\x00ab')                           # no IAC SE
m.cl(bytes([IAC, SB, 31, 0, 80]))                                # NAWS missing octets with no end
m.cl(bytes([IAC, SB, 24, 1, 2]) + bytes([IAC]))
m.cl(bytes([IAC, SB, 37, 1]) + bytes([IAC, SE]))                 # AUTHENTICATION SEND without a pair
m.cl(bytes([IAC, SB, 37, 0, 2]) + bytes([IAC, SE]))
m.cl(bytes([IAC, SB, 38]) + bytes([IAC, SE]))
m.cl(bytes([IAC, SB, 44, 1]) + bytes([IAC, SE]))
m.cl(bytes([IAC, SB, 232, 0]) + b'\x01' * 3 + bytes([IAC, SE]))
m.cl(bytes([IAC, SB, 232]) + bytes([IAC, SE]))
m2 = MFlow(41001)
m2.cl(bytes([IAC, SB, 40, 3, 7, 0, 1, 2, 3, 4, 5, 6, 7, 8]) + bytes([IAC, SE]))
m2.cl(bytes([IAC, SB, 40, 2, 4]) + bytes([IAC, SE]))
m2.cl(bytes([IAC, SB, 40, 1]) + bytes([IAC, SE]))
m2.cl(bytes([IAC, SB, 40, 2, 4, 1]) + bytes([IAC, SE]))
m2.cl(bytes([IAC, SB, 40, 5]) + bytes([IAC, SE]))
m2.cl(bytes([IAC, SB, 29, 1]) + bytes([IAC, SE]))
m2.cl(bytes([IAC, SB, 11]) + bytes([IAC, SE]))
m2.cl(bytes([IAC, SB, 27]) + bytes([IAC, SE]))
m2.cl(bytes([IAC, SB, 24]) + bytes([IAC, SE]))
m2.cl(bytes([IAC, SB, 33]) + bytes([IAC, SE]))
mk = MFlow(41020)
mk.cl(sb(37, b'\x00\x02\x00\x00\x6e\x03\x30\x01\x00'))     # IS KRB5 AUTH with a Kerberos message that is cut short
mk.cl(sb(37, b'\x02\x02\x00\x03\x6f\x03\x30\x01\x00'))     # REPLY KRB5 RESPONSE
m5 = MFlow(41010)
m5.cl(sb(24, b'\x00IBM-5555-C01'))
m5.sv(b'\x04\x00\x00\x00' + cmd(EOR))
m5.sv(b'\x04' + cmd(EOR))
m5b = MFlow(41011)
m5b.cl(sb(24, b'\x00IBM-3477-FC'))
m5b.sv(b'\x04\x00' + cmd(EOR))
m3 = MFlow(41002)
m3.cl(b'\x01\xc3')                                               # TN3270 data without a conversation: plain text
m3.cl(bytes([IAC, SB, 24, 0]) + b'IBM-3278-2' + bytes([IAC, SE]) + b'\xff')
m3.cl(b'\x00' * 20 + bytes([IAC]))
m3.sv(b'\xff' * 3 + bytes([SB]))

if len(sys.argv) < 2:
    sys.exit('usage: mktelnet.py <outdir> [-v]')
out = sys.argv[1]
write_pcap(os.path.join(out, 'telnet-coverage.pcap'), pk)
write_pcap(os.path.join(out, 'telnet-coverage-malformed.pcap'), mal)
if '-v' in sys.argv:
    for k, name in marks:
        print(k, name)
    print('main', len(pk), 'malformed', len(mal))
