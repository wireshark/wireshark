#!/usr/bin/env python3
# Generates test/captures/mrcpv2_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the MRCPv2 coverage captures.  Usage: mkmrcpv2.py <outdir> [-v]
All addresses are from 192.0.2.0/24; nothing comes from a real network."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















from r13_pcaplib import TcpStream, write_pcap

HEADERS = """abort-model abort-phrase-enrollment abort-verification accept accept-charset
active-request-id-list adapt-model audio-fetch-hint cache-control cancel-if-queue capture-on-speech
channel-identifier clash-threshold clear-dtmf-buffer completion-cause completion-reason
confidence-threshold confusable-phrases-uri consistency-threshold content-base content-encoding
content-id content-location content-type dtmf-buffer-time dtmf-interdigit-timeout dtmf-term-char
dtmf-term-timeout early-no-match enroll-utterance failed-uri failed-uri-cause fetch-hint
fetch-timeout final-silence hotword-max-duration hotword-min-duration input-type input-waveform-uri
interpret-text jump-size kill-on-barge-in lexicon-search-order load-lexicon logging-tag max-time
media-type min-verification-score n-best-list-length new-audio-channel new-phrase-id
no-input-timeout num-max-verification-phrases num-min-consistent-pronunciations
num-min-verification-phrases personal-grammar-uri phrase-id phrase-nl prosody-contour
prosody-duration prosody-pitch prosody-range prosody-rate prosody-volume proxy-sync-id
recognition-mode recognition-timeout recognizer-context-block record-uri repository-uri
save-best-waveform save-waveform sensitivity-level set-cookie speak-length speak-restart
speaker-profile speech-complete-timeout speech-incomplete-timeout speech-language speech-marker
speed-vs-accuracy start-input-timers trim-length vendor-specific-parameters ver-buffer-utterance
verification-mode voice-age voice-gender voice-name voice-variant voiceprint-exists
voiceprint-identifier waveform-uri weight""".split()

def title(h): return '-'.join(w.capitalize() for w in h.split('-'))

def mrcp(first, headers=(), body=b'', ver='MRCP/2.0', fixlen=True):
    """first: the rest of the start line after the length, with a {} where the
    length goes is not needed: the line is ver SP len SP first CRLF."""
    hdr = b''.join(h.encode() + b'\r\n' for h in headers)
    if body or headers:
        hdr += b'\r\n'
    rest = (first + '\r\n').encode() + hdr + body
    n = len(rest) + len(ver) + 1
    for _ in range(3):
        line = ('%s %d ' % (ver, n)).encode()
        total = len(line) + len(rest)
        if total == n: break
        n = total
    return line + rest

frames = []; marks = []
def mark(n): marks.append((n, len(frames) + 1))
def new(cport, sport=6075):
    st = TcpStream(cport=cport, sport=sport)
    frames.extend(st.handshake())
    return st
def C(st, d): frames.append(st.pkt(d))
def S(st, d): frames.append(st.pkt(d, True))

def build_main():
    mark('requests, default port 6075')
    st = new(40000)
    CH = 'Channel-Identifier: 32AECB23433802@speechsynth'
    C(st, mrcp('SPEAK 543257', [CH, 'Content-Length: 0']))                 # reproducer of the dead dissector
    C(st, mrcp('SPEAK 543258', [CH, 'Content-Type: application/ssml+xml', 'Content-Length: 40'], b'<speak>Hello, this is MRCP v2.</speak>\n'[:40].ljust(40)))
    for i, m in enumerate(['STOP', 'PAUSE', 'RESUME', 'BARGE-IN-OCCURRED', 'CONTROL', 'DEFINE-LEXICON',
                           'SET-PARAMS', 'GET-PARAMS', 'RECOGNIZE', 'GET-RESULT', 'START-INPUT-TIMERS',
                           'STOP', 'START-PHRASE-ENROLLMENT', 'RECORD', 'VERIFY']):
        C(st, mrcp('%s %d' % (m, 600 + i), [CH]))
    mark('responses')
    for code in ['200', '201', '401', '402', '403', '404', '405', '406', '407', '408', '409', '410',
                 '501', '502', '503', '504', '599']:
        S(st, mrcp('543257 %s %s' % (code, 'COMPLETE' if code != '200' else 'IN-PROGRESS'), [CH]))
    S(st, mrcp('543258 200 PENDING', [CH, 'Active-Request-Id-List: 543257,543258']))
    mark('events')
    for ev, state in [('SPEECH-MARKER', 'IN-PROGRESS'), ('SPEAK-COMPLETE', 'COMPLETE'),
                      ('START-OF-INPUT', 'IN-PROGRESS'), ('RECOGNITION-COMPLETE', 'COMPLETE'),
                      ('RECORD-COMPLETE', 'COMPLETE'), ('VERIFICATION-COMPLETE', 'COMPLETE')]:
        S(st, mrcp('%s 543257 %s' % (ev, state), [CH, 'Completion-Cause: 000 success']))
    mark('every header')
    # one request per ten headers; values are made up
    for i in range(0, len(HEADERS), 10):
        hs = [title(h) + ': value-' + h for h in HEADERS[i:i + 10] if h != 'content-length']
        C(st, mrcp('SET-PARAMS %d' % (700 + i), hs))
    # lower and upper case names, no space after the colon, values with spaces
    C(st, mrcp('SET-PARAMS 800', ['channel-identifier:1234@speechrecog', 'VOICE-NAME:   Paul  ', 'SPEECH-LANGUAGE: en-GB']))
    C(st, mrcp('SET-PARAMS 801', ['Content-Length: 5', 'Content-Type: text/plain'], b'hello'))
    mark('unknown and odd headers')
    C(st, mrcp('SET-PARAMS 802', ['X-Vendor-Header: something', 'a line without a colon', CH]))
    C(st, mrcp('SET-PARAMS 803', [CH, 'Content-Length: 12'], b'line1\nline2\r\n'[:12]))   # body, lines end in LF
    mark('PDUs in one segment, reassembly')
    r = mrcp('SPEAK 900', [CH, 'Content-Length: 0'])
    C(st, r + mrcp('STOP 901', [CH]) + mrcp('PAUSE 902', [CH]))               # three PDUs in one segment
    big = mrcp('SPEAK 903', [CH, 'Content-Type: text/plain', 'Content-Length: 3000'], (b'abcdefghij' * 300))
    C(st, big[:20]); C(st, big[20:700]); C(st, big[700:])
    # a PDU that ends in the middle of the next segment: PDU 2 starts in the segment of PDU 1
    a = mrcp('RECOGNIZE 904', [CH, 'Content-Type: application/srgs+xml', 'Content-Length: 100'], b'x' * 100)
    b = mrcp('STOP 905', [CH])
    C(st, a + b[:15]); C(st, b[15:])
    mark('other ports and versions')
    st2 = new(40001, 30100)                                                # second default port range
    C(st2, mrcp('SPEAK 1', [CH]))
    S(st2, mrcp('1 200 COMPLETE', [CH]))
    st3 = new(40002)
    C(st3, mrcp('SPEAK 2', [CH], ver='MRCP/02.0'))                          # two digit major version
    C(st3, mrcp('SPEAK 3', [CH], ver='MRCP/2.0000'))                        # minor version with no space in the first ten octets

def build_malformed():
    global frames, marks
    frames = []; marks = []
    CH = 'Channel-Identifier: 1@x'
    st = new(41000)
    mark('Content-Length not a number (expert error)')
    C(st, mrcp('SPEAK 1', [CH, 'Content-Length: abc'], b'body'))
    C(st, mrcp('SPEAK 2', [CH, 'Content-Length: -1']))
    mark('not MRCP, rejected by the start test (one stream each: HTTP takes over a stream otherwise)')
    for i, junk in enumerate([b'GET / HTTP/1.1\r\n\r\n', b'MRCP/3.0 20 x\r\n', b'MRCP/2.1 20 SPEAK 1\r\n\r\n',
                              b'MRCP/222.0 20 SPEAK 1\r\n\r\n', b'MRCP/2000000 20 SPEAK 1\r\n\r\n',
                              b'X' * 20, b'MRCP', b'HTTP/2.0 20 SPEAK 1\r\n\r\n', b'ABC/12345678']):
        st = new(41100 + i)
        C(st, junk)
    mark('bad PDU lengths and start lines')
    st = new(41001)
    C(st, b'MRCP/2.0 abc SPEAK 1\r\n' + b'Channel-Identifier: 1@x\r\n\r\n')    # non-numeric length
    st = new(41002)
    C(st, b'MRCP/2.0 4000000000 SPEAK 1\r\n')                                  # length larger than the data
    st = new(41003)
    C(st, b'MRCP/2.0 5 SPEAK 1\r\n' + b'x' * 40)                                # length shorter than the start line
    st = new(41004)
    C(st, b'MRCP/2.0 50 SPEAK\r\n' + b'Channel-Identifier: 1@x\r\n\r\n')         # three fields only
    st = new(41005)
    C(st, b'MRCP/2.0 60 SPEAK 1 2 3 4\r\n' + b'x' * 40)
    st = new(41008)
    C(st, mrcp('SPEAK 1', [CH]) + b'X' * 29 + b' SPEAK 1\r\n' + b'Y' * 20)           # second PDU: first token of 29 octets
    st = new(41006)
    C(st, b'MRCP/2.0' + b' ' * 40 + b'1')                                      # long run of spaces
    st = new(41007)
    C(st, b'MRCP/2.0 ' + b'9' * 60 + b' SPEAK 1\r\n')
    C(st, b'MRCP/2.0 40 ' + b'S' * 5 + b'\r\n' + b'Channel-Identifier: 1@x\r\n\r\n')

if __name__ == '__main__':
    out = sys.argv[1]
    build_main()
    write_pcap(os.path.join(out, 'mrcpv2-coverage.pcap'), frames)
    if '-v' in sys.argv: print(len(frames), 'frames'); print(marks)
    frames = []
    build_malformed()
    write_pcap(os.path.join(out, 'mrcpv2-coverage-malformed.pcap'), frames)
    if '-v' in sys.argv: print(len(frames), 'malformed frames'); print(marks)
