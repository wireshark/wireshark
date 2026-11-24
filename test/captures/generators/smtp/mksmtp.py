#!/usr/bin/env python3
# Generates test/captures/smtp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the SMTP coverage captures. Usage: mksmtp.py <outdir> [-v]
Writes smtp-coverage.pcap (main) and smtp-coverage-malformed.pcap.
TCP 25 and 587 are registered by default (465 is TLS and needs keys).
The AUTH exchanges use made-up user names and passwords and the NTLMSSP
messages carry zero filled responses; the decoding of the parameters is
the "smtp.decryption" preference (base64 only), off by default.
Everything is synthetic (192.0.2.0/24)."""
import base64
import os
import struct
import sys
from pcaplib import TcpFlow, write_pcap

def b64(b):
    return base64.b64encode(b if isinstance(b, bytes) else b.encode())

MSG = (b'From: alice@example.invalid\r\nTo: bob@example.invalid\r\nSubject: coverage test\r\n'
       b'Date: Tue, 3 Nov 2026 10:00:00 +0000\r\nMessage-ID: <cov1@example.invalid>\r\n\r\n'
       b'Body line 1\r\n..a dot stuffed line\r\nBody line 3\r\n')

def sec(length, off):
    return struct.pack('<HHI', length, length, off)

def ntlm_negotiate():
    return b'NTLMSSP\x00' + struct.pack('<II', 1, 0xe2088297) + sec(0, 0) + sec(0, 0) + b'\x06\x01\xb1\x1d\x00\x00\x00\x0f'

def ntlm_challenge():
    tn = 'EXAMPLE'.encode('utf-16le')
    ti = struct.pack('<HH', 2, len(tn)) + tn + struct.pack('<HH', 0, 0)
    off = 56
    return (b'NTLMSSP\x00' + struct.pack('<I', 2) + sec(len(tn), off) + struct.pack('<I', 0xe2898215)
            + bytes(range(1, 9)) + bytes(8) + sec(len(ti), off + len(tn)) + b'\x06\x01\xb1\x1d\x00\x00\x00\x0f' + tn + ti)

def ntlm_authenticate():
    dom, usr, ws = ['EXAMPLE'.encode('utf-16le'), 'alice'.encode('utf-16le'), 'WS1'.encode('utf-16le')]
    lm, nt = bytes(24), bytes(24)    # zero filled: no real responses
    off = 72
    parts = [lm, nt, dom, usr, ws, b'']
    offs = []
    for p in parts:
        offs.append(off); off += len(p)
    hdr = b'NTLMSSP\x00' + struct.pack('<I', 3)
    for p, o in zip(parts, offs):
        hdr += sec(len(p), o)
    hdr += struct.pack('<I', 0xe2888215) + b'\x06\x01\xb1\x1d\x00\x00\x00\x0f'
    return hdr + b''.join(parts)

def main_frames():
    F = []; R = {}
    def add(name, fr):
        R[name] = len(F) + 1; F.append(fr)
    def addl(name, frs):
        R[name] = len(F) + 1; F.extend(frs)
    # ---- Session 1: a full transaction with DATA (TCP 25) -------------------
    f = TcpFlow(40000, 25)
    addl('s1-handshake', f.handshake())
    add('banner', f.s2c(b'220-mx.example.invalid ESMTP ready\r\n220 second banner line\r\n'))
    add('ehlo', f.c2s(b'EHLO client.example.invalid\r\n'))
    add('ehlo-rsp', f.s2c(b'250-mx.example.invalid\r\n250-SIZE 35882577\r\n250-8BITMIME\r\n250-STARTTLS\r\n250-AUTH LOGIN PLAIN NTLM\r\n250-BINARYMIME\r\n250 CHUNKING\r\n'))
    add('mail', f.c2s(b'MAIL FROM:<alice@example.invalid> SIZE=200\r\n'))
    add('mail-rsp', f.s2c(b'250 2.1.0 Sender ok\r\n'))
    add('rcpt', f.c2s(b'RCPT TO:<bob@example.invalid>\r\nRCPT TO:<carol@example.invalid>\r\n'))
    add('rcpt-rsp', f.s2c(b'250 2.1.5 Recipient ok\r\n250 2.1.5 Recipient ok\r\n'))
    add('data', f.c2s(b'DATA\r\n'))
    add('data-rsp', f.s2c(b'354 Start mail input; end with <CRLF>.<CRLF>\r\n'))
    # message over three segments, the third ends in the EOM and the next command
    ml0 = MSG.split(b'\r\n')
    cut = lambda lo, hi: b'\r\n'.join(ml0[lo:hi]) + b'\r\n'
    add('data-1', f.c2s(cut(0, 3)))
    add('data-2', f.c2s(cut(3, 6)))
    add('data-3', f.c2s(cut(6, len(ml0) - 1) + b'.\r\nQUIT\r\n'))
    add('data-rsp2', f.s2c(b'250 2.0.0 Message accepted\r\n221 2.0.0 Bye\r\n'))
    addl('s1-fin', f.fin())
    # ---- Session 2: commands, odd responses, RSET, BDAT, STARTTLS -------------
    f = TcpFlow(40001, 25)
    addl('s2-handshake', f.handshake())
    add('s2-banner', f.s2c(b'220 mx2.example.invalid ESMTP\r\n'))
    add('s2-helo', f.c2s(b'HELO client\r\n'))
    add('s2-misc-rsp', f.s2c(b'250 mx2\r\n'))
    add('s2-cmds', f.c2s(b'VRFY bob\r\nEXPN list\r\nHELP\r\nNOOP\r\nX-EXPS GSSAPI\r\nX-LINK2STATE CHUNK=1\r\nXEXCH50 5\r\n'))
    add('s2-short', f.c2s(b'QUI\r\nrandomtext\r\nHI\r\n'))
    add('s2-cmds-rsp', f.s2c(b'252 Cannot VRFY\r\n550-first\r\n551-second code\r\n551 last\r\n250 ok\r\n251 forward\r\n214 help\r\n211 status\r\n421 closing\r\n451 local error\r\n452 storage\r\n454 temp\r\n500 syntax\r\n501 args\r\n502 no\r\n503 bad seq\r\n504 param\r\n530 auth\r\n534 weak\r\n535 invalid\r\n538 enc\r\n552 alloc\r\n553 name\r\n554 failed\r\n999 unknown code\r\n'))
    add('s2-mixed-multiline', f.s2c(b'250-line one\r\n251-different code\r\n250 end\r\n'))
    add('s2-short-rsp', f.s2c(b'25\r\n250\r\n250-\r\nplain text\r\n'))
    ml = MSG.split(b'\r\n')
    c1 = ml[0] + b'\r\n'
    c2a = ml[1] + b'\r\n'
    c2b = ml[2] + b'\r\n'
    last = b'\r\n'.join(ml[3:])
    add('s2-bdat1', f.c2s(b'BDAT %d\r\n' % len(c1) + c1))
    add('s2-bdat1-rsp', f.s2c(b'250 %d octets received\r\n' % len(c1)))
    add('s2-bdat2', f.c2s(b'BDAT %d\r\n' % (len(c2a) + len(c2b)) + c2a))
    add('s2-bdat2b', f.c2s(c2b))
    add('s2-bdat2-rsp', f.s2c(b'250 chunk received\r\n'))
    add('s2-bdat3', f.c2s(b'BDAT %d LAST\r\n' % len(last) + last + b'NOOP\r\n'))
    add('s2-bdat3-rsp', f.s2c(b'250 message accepted\r\n250 ok\r\n'))
    add('s2-bdat0', f.c2s(b'BDAT 0 LAST\r\n'))
    add('s2-rset', f.c2s(b'RSET\r\n'))
    add('s2-bdat-after-rset', f.c2s(b'BDAT 7\r\nabcde\r\n'))
    add('s2-rset2', f.c2s(b'RSET\r\n'))
    add('s2-starttls', f.c2s(b'STARTTLS\r\n'))
    add('s2-starttls-rsp', f.s2c(b'220 2.0.0 Ready to start TLS\r\n'))
    # after the 220 everything is TLS (an alert record, nothing to decrypt)
    add('s2-tls', f.c2s(bytes([0x15, 3, 3, 0, 2, 1, 0])))
    addl('s2-fin', f.fin())
    # ---- Session 3: STARTTLS refused, command split over segments (TCP 587) -----
    f = TcpFlow(40002, 587)
    addl('s3-handshake', f.handshake())
    add('s3-banner', f.s2c(b'220 submit.example.invalid\r\n'))
    add('s3-starttls', f.c2s(b'STARTTLS\r\n'))
    add('s3-starttls-rsp', f.s2c(b'454 TLS not available\r\n'))
    add('s3-split-1', f.c2s(b'MAIL FROM:<alice@exa'))
    add('s3-split-2', f.c2s(b'mple.invalid>\r\n'))
    add('s3-split-3', f.c2s(b'RCPT TO:<bob@example.invalid>\r\n'))
    add('s3-split-4', f.c2s(b'DA'))
    add('s3-split-5', f.c2s(b'TA\r\n'))
    add('s3-data-rsp', f.s2c(b'354 go ahead\r\n'))
    # DATA text with the CRLF at the end of one frame and the ".CRLF" at the start of the next
    add('s3-msg-1', f.c2s(b'Subject: split eom\r\n\r\nbody\r\n'))
    add('s3-msg-eom', f.c2s(b'.\r\n'))
    add('s3-eom-rsp', f.s2c(b'250 queued\r\n'))
    addl('s3-fin', f.fin())
    # ---- Session 4: AUTH LOGIN in separate frames --------------------------------
    f = TcpFlow(40003, 25)
    addl('s4-handshake', f.handshake())
    add('s4-banner', f.s2c(b'220 auth1.example.invalid\r\n'))
    add('s4-auth', f.c2s(b'AUTH LOGIN\r\n'))
    add('s4-user-req', f.s2c(b'334 ' + b64('Username:') + b'\r\n'))
    add('s4-user', f.c2s(b64('alice') + b'\r\n'))
    add('s4-pass-req', f.s2c(b'334 ' + b64('Password:') + b'\r\n'))
    add('s4-pass', f.c2s(b64('secret1') + b'\r\n'))
    add('s4-ok', f.s2c(b'235 2.7.0 Authentication successful\r\n'))
    add('s4-mail', f.c2s(b'MAIL FROM:<alice@example.invalid>\r\n'))
    add('s4-text', f.c2s(b'randomtext after the authentication\r\n'))
    addl('s4-fin', f.fin())
    # ---- Session 5: AUTH LOGIN with the user name on the command line, failure ---
    f = TcpFlow(40004, 25)
    addl('s5-handshake', f.handshake())
    add('s5-banner', f.s2c(b'220 auth2.example.invalid\r\n'))
    add('s5-auth', f.c2s(b'AUTH LOGIN ' + b64('bob') + b'\r\n'))
    add('s5-pass-req', f.s2c(b'334 ' + b64('Password:') + b'\r\n'))
    add('s5-pass', f.c2s(b64('wrong') + b'\r\n'))
    add('s5-fail', f.s2c(b'535 5.7.8 Authentication credentials invalid\r\n'))
    add('s5-quit', f.c2s(b'QUIT\r\n'))
    addl('s5-fin', f.fin())
    # ---- Session 6: AUTH PLAIN, separate frame ------------------------------------
    f = TcpFlow(40005, 25)
    addl('s6-handshake', f.handshake())
    add('s6-banner', f.s2c(b'220 auth3.example.invalid\r\n'))
    add('s6-auth', f.c2s(b'AUTH PLAIN\r\n'))
    add('s6-req', f.s2c(b'334 \r\n'))
    add('s6-cred', f.c2s(b64(b'\x00carol\x00secret3') + b'\r\n'))
    add('s6-ok', f.s2c(b'235 2.7.0 Authentication successful\r\n'))
    addl('s6-fin', f.fin())
    # ---- Session 7: AUTH PLAIN inline; the second one is the reproducer of the fix -
    f = TcpFlow(40006, 25)
    addl('s7-handshake', f.handshake())
    add('s7-banner', f.s2c(b'220 mx.example.invalid ESMTP\r\n'))
    add('s7-ehlo', f.c2s(b'EHLO a\r\n'))
    add('s7-ehlo-rsp', f.s2c(b'250 ok\r\n'))
    add('s7-auth', f.c2s(b'AUTH PLAIN ' + b64(b'\x00dave\x00secret4') + b'\r\n'))
    add('s7-ok', f.s2c(b'235 ok\r\n'))
    addl('s7-fin', f.fin())
    f = TcpFlow(40007, 25)
    addl('s7b-handshake', f.handshake())
    add('s7b-banner', f.s2c(b'220 mx.example.invalid ESMTP\r\n'))
    add('s7b-ehlo', f.c2s(b'EHLO a\r\n'))
    add('s7b-ehlo-rsp', f.s2c(b'250 ok\r\n'))
    add('s7b-repro', f.c2s(b'AUTH PLAIN AHVzZXIAcGFzcw==\r\nNOOP12\r\nQUIT\r\n'))
    add('s7b-rsp', f.s2c(b'235 ok\r\n'))
    addl('s7b-fin', f.fin())
    # AUTH PLAIN with the user name only (short credentials), then an empty line
    f = TcpFlow(40008, 25)
    addl('s7c-handshake', f.handshake())
    add('s7c-banner', f.s2c(b'220 mx.example.invalid ESMTP\r\n'))
    add('s7c-auth', f.c2s(b'AUTH PLAIN ' + b64(b'\x00onlyuser') + b'\r\n'))
    add('s7c-rsp', f.s2c(b'535 no\r\n'))
    addl('s7c-fin', f.fin())
    # ---- Session 8: AUTH NTLM ------------------------------------------------------
    f = TcpFlow(40009, 25)
    addl('s8-handshake', f.handshake())
    add('s8-banner', f.s2c(b'220 ntlm.example.invalid\r\n'))
    add('s8-auth', f.c2s(b'AUTH NTLM ' + b64(ntlm_negotiate()) + b'\r\n'))
    add('s8-challenge', f.s2c(b'334 ' + b64(ntlm_challenge()) + b'\r\n'))
    add('s8-response', f.c2s(b64(ntlm_authenticate()) + b'\r\n'))
    add('s8-ok', f.s2c(b'235 2.7.0 Authentication successful\r\n'))
    addl('s8-fin', f.fin())
    # AUTH NTLM whose parameters are not NTLMSSP
    f = TcpFlow(40010, 25)
    addl('s9-handshake', f.handshake())
    add('s9-banner', f.s2c(b'220 ntlm2.example.invalid\r\n'))
    add('s9-auth', f.c2s(b'AUTH NTLM ' + b64('not an ntlm message') + b'\r\n'))
    add('s9-challenge', f.s2c(b'334 ' + b64('plain challenge text') + b'\r\n'))
    add('s9-response', f.c2s(b64('not ntlm either') + b'\r\n'))
    add('s9-fail', f.s2c(b'535 failed\r\n'))
    add('s9-auth2', f.c2s(b'AUTH NTLM\r\n'))
    add('s9-rsp2', f.s2c(b'334 \r\n'))
    addl('s9-fin', f.fin())
    # ---- Sessions 11-14: one-character AUTH parameters (nothing to base64 decode) ----
    f = TcpFlow(40012, 25)
    addl('s11-handshake', f.handshake())
    add('s11-banner', f.s2c(b'220 short1.example.invalid\r\n'))
    add('s11-auth', f.c2s(b'AUTH LOGIN\r\n'))
    add('s11-user-req', f.s2c(b'334 ' + b64('Username:') + b'\r\n'))
    add('s11-user', f.c2s(b'a\r\n'))
    add('s11-pass-req', f.s2c(b'334 ' + b64('Password:') + b'\r\n'))
    add('s11-pass', f.c2s(b'p\r\n'))
    add('s11-ok', f.s2c(b'235 ok\r\n'))
    addl('s11-fin', f.fin())
    f = TcpFlow(40013, 25)
    addl('s12-handshake', f.handshake())
    add('s12-banner', f.s2c(b'220 short2.example.invalid\r\n'))
    add('s12-auth', f.c2s(b'AUTH LOGIN a\r\n'))
    add('s12-pass-req', f.s2c(b'334 ' + b64('Password:') + b'\r\n'))
    add('s12-pass', f.c2s(b'!\r\n'))
    add('s12-fail', f.s2c(b'535 no\r\n'))
    addl('s12-fin', f.fin())
    f = TcpFlow(40014, 25)
    addl('s13-handshake', f.handshake())
    add('s13-banner', f.s2c(b'220 short3.example.invalid\r\n'))
    add('s13-auth', f.c2s(b'AUTH PLAIN\r\n'))
    add('s13-req', f.s2c(b'334 \r\n'))
    add('s13-cred', f.c2s(b'x\r\n'))
    add('s13-fail', f.s2c(b'535 no\r\n'))
    add('s13-auth2', f.c2s(b'AUTH PLAIN x\r\n'))
    add('s13-fail2', f.s2c(b'535 no\r\n'))
    addl('s13-fin', f.fin())
    f = TcpFlow(40015, 25)
    addl('s14-handshake', f.handshake())
    add('s14-banner', f.s2c(b'220 short4.example.invalid\r\n'))
    add('s14-auth', f.c2s(b'AUTH NTLM x\r\n'))
    add('s14-challenge', f.s2c(b'334 y\r\n'))
    add('s14-response', f.c2s(b'z\r\n'))
    add('s14-fail', f.s2c(b'535 no\r\n'))
    addl('s14-fin', f.fin())
    # ---- Session 10: capture that starts in the middle of a session ---------------
    f = TcpFlow(40011, 25)
    f.cseq += 500; f.sseq += 500
    add('s10-body', f.c2s(b'This is the middle of a message body\r\nwith more text\r\n'))
    add('s10-rsp', f.s2c(b'250 ok\r\n'))
    add('s10-cmd', f.c2s(b'QUIT\r\n'))
    return F, R

def malformed_frames():
    F = []; R = {}
    def add(name, fr):
        R[name] = len(F) + 1; F.append(fr)
    f = TcpFlow(41000, 25)
    F += f.handshake()
    add('banner', f.s2c(b'220 x\r\n'))
    add('one-byte', f.c2s(b'x'))
    add('lf-only', f.c2s(b'\n'))
    add('cr-only', f.c2s(b'\r'))
    add('plain-short-line', f.c2s(b'AUTH PLAIN\n'))
    add('bdat-huge', f.c2s(b'BDAT 4294967295\r\n'))
    add('bdat-data', f.c2s(b'abc'))
    add('bdat-garbage', f.c2s(b'BDAT zzz\r\nBDAT\r\n'))
    add('response-nonascii', f.s2c(b'250 \xff\xfe\xfd\r\n\x00\x01\x02\r\n'))
    add('auth-login-bad-b64', f.c2s(b'AUTH LOGIN !!!notbase64!!!\r\n'))
    add('auth-resp', f.s2c(b'334 !!!\r\n'))
    add('auth-pass', f.c2s(b'*not*base64\r\n'))
    add('auth-ok', f.s2c(b'235 ok\r\n'))
    f = TcpFlow(41001, 25)
    F += f.handshake()
    add('s2-banner', f.s2c(b'220 y\r\n'))
    add('ntlm-trunc', f.c2s(b'AUTH NTLM ' + b64(b'NTLMSSP\x00\x01\x00\x00\x00') + b'\r\n'))
    add('ntlm-trunc-rsp', f.s2c(b'334 ' + b64(b'NTLMSSP\x00\x02\x00\x00\x00\xff\xff') + b'\r\n'))
    add('ntlm-trunc-resp', f.c2s(b64(b'NTLMSSP\x00\x03\x00\x00\x00\xff\xff\xff\xff') + b'\r\n'))
    add('ntlm-fin', f.s2c(b'235 ok\r\n'))
    # two AUTH PLAIN attempts with inline credentials in one connection: the state is kept per
    # conversation, so with -2 the first attempt is shown without its credentials (observation)
    f = TcpFlow(41003, 25)
    F += f.handshake()
    add('two-plain-banner', f.s2c(b'220 w\r\n'))
    add('two-plain-1', f.c2s(b'AUTH PLAIN ' + b64(b'\x00first\x00pw1') + b'\r\n'))
    add('two-plain-rsp1', f.s2c(b'535 no\r\n'))
    add('two-plain-2', f.c2s(b'AUTH PLAIN ' + b64(b'\x00second\x00pw2') + b'\r\n'))
    add('two-plain-rsp2', f.s2c(b'235 ok\r\n'))
    f = TcpFlow(41002, 25)
    F += f.handshake()
    add('s3-banner', f.s2c(b'220 z\r\n'))
    add('auth-plain-inline-badb64', f.c2s(b'AUTH PLAIN %%%%%%%%%%%%%\r\n'))
    add('auth-plain-rsp', f.s2c(b'235 ok\r\n'))
    return F, R

if __name__ == '__main__':
    out = sys.argv[1]
    F, R = main_frames()
    write_pcap(os.path.join(out, 'smtp-coverage.pcap'), F)
    G, RM = malformed_frames()
    write_pcap(os.path.join(out, 'smtp-coverage-malformed.pcap'), G)
    if '-v' in sys.argv:
        print(len(F), R); print(len(G), RM)
