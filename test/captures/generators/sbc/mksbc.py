#!/usr/bin/env python3
# Generates test/captures/sbc_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the SBC coverage captures: mksbc.py <outdir> [-v].  All data is synthetic.

SBC (the Bluetooth A2DP codec, packet-sbc.c) is reached the way a real capture
reaches it: Bluetooth HCI H4 with direction, an AVDTP signaling procedure that
configures an SBC stream (SET_CONFIGURATION, OPEN, START), and RTP media packets
on the L2CAP media channel, which the A2DP dissector hands to SBC with the
codec information.  btavdtp_lib.py holds the packet builders of the AVDTP
coverage generator (HCI, L2CAP, AVDTP, RTP, SBC frames)."""
import os
import sys
import btavdtp_lib as L

def cfg(freq, blocks, mode, alloc, subbands):
    return (freq << 6) | (blocks << 4) | (mode << 2) | (alloc << 1) | subbands

def frame_cfg(c, bitpool, sync=0x9c):
    f = bytearray(L.sbc_frame(c, bitpool))
    f[0] = sync
    return bytes(f)

def main(out, verbose=False):
    marks = []
    cap = L.Pcapng()
    def mark(t):
        marks.append((cap.count + 1, t))
    mark('Handle 1: DISCOVER, GET_CAPABILITIES, SET_CONFIGURATION (SBC), OPEN, media channel, START (AVDTP signaling that sets up the A2DP stream)')
    s = L.Session(cap, 1)
    s.cmd(L.DISCOVER)
    s.rsp(L.ACC, L.DISCOVER, L.sep(1, 0, True))
    s.cmd(L.GET_CAP, L.seid(1))
    s.rsp(L.ACC, L.GET_CAP, L.TRANSPORT + L.SBC_ALL)
    s.cmd(L.SET_CONF, L.seid(1) + L.seid(7) + L.TRANSPORT + L.SBC_CFG)
    s.rsp(L.ACC, L.SET_CONF)
    s.cmd(L.OPEN, L.seid(1))
    s.rsp(L.ACC, L.OPEN)
    s.connect('media', (0x41, 0x51))
    s.cmd(L.START, L.seid(1))
    s.rsp(L.ACC, L.START)
    mark('SBC media packets: every sampling frequency, block count, channel mode, allocation method and subband count; odd and even bitpools (a bitpool that leaves bits in the last octet), several frames per packet')
    seq = [0]
    def media(frames, hdr_extra=0):
        seq[0] += 1
        payload = L.sbc_payload(frames)
        if hdr_extra:
            payload = bytes([payload[0] | hdr_extra]) + payload[1:]
        s.media_pkt(L.rtp(seq[0], seq[0] * 256, payload))
    for freq in range(4):
        for mode in range(4):
            c = cfg(freq, (freq + mode) % 4, mode, (freq + mode) & 1, (freq * mode) & 1)
            media([frame_cfg(c, 20 + freq), frame_cfg(c, 33 + mode)])
    for blocks in range(4):
        for sub in range(2):
            media([frame_cfg(cfg(2, blocks, 3, 0, sub), 3 + 2 * blocks)])
    media([frame_cfg(cfg(0, 0, 0, 0, 0), 3)])                 # mono, 4 blocks, odd bitpool
    media([frame_cfg(cfg(1, 1, 1, 1, 0), 5)])                 # dual channel, odd bitpool
    media([frame_cfg(cfg(3, 3, 2, 0, 1), 53) for _ in range(4)])   # four frames
    mark('Packets with the fragmentation bits of the SBC payload header (fragmented, starting packet, last packet, RFA)')
    for bits in (0x80, 0xc0, 0xa0, 0x10, 0xf0):
        media([frame_cfg(cfg(2, 3, 3, 0, 1), 53)], hdr_extra=bits)
    mark('The last packet (delta time, cumulative durations and the difference to the elapsed time computed from the previous packets)')
    media([frame_cfg(cfg(2, 3, 3, 0, 1), 40)])
    main_n = cap.count
    cap.write(os.path.join(out, 'sbc-coverage.pcapng'))

    mcap = L.Pcapng()
    s2 = L.Session(mcap, 2)
    s2.cmd(L.DISCOVER)
    s2.rsp(L.ACC, L.DISCOVER, L.sep(1, 0, True))
    s2.cmd(L.SET_CONF, L.seid(1) + L.seid(7) + L.TRANSPORT + L.SBC_CFG)
    s2.rsp(L.ACC, L.SET_CONF)
    s2.cmd(L.OPEN, L.seid(1))
    s2.rsp(L.ACC, L.OPEN)
    s2.connect('media', (0x41, 0x51))
    s2.cmd(L.START, L.seid(1))
    s2.rsp(L.ACC, L.START)
    # a frame with a wrong syncword (warning), a frame cut short (exception), a packet with
    # only the header octet, and a frame whose header is cut after the sync word
    s2.media_pkt(L.rtp(1, 0, L.sbc_payload([frame_cfg(cfg(2, 3, 3, 0, 1), 53, sync=0x00)])))
    good = L.sbc_payload([frame_cfg(cfg(2, 3, 3, 0, 1), 53)])
    s2.media_pkt(L.rtp(2, 256, good[:20]))
    s2.media_pkt(L.rtp(3, 512, bytes([1])))
    s2.media_pkt(L.rtp(4, 768, bytes([1, 0x9c])))
    s2.media_pkt(L.rtp(5, 1024, good + b'\x9c'))
    mcap.write(os.path.join(out, 'sbc-coverage-malformed.pcapng'))
    if verbose:
        for n, tx in marks:
            print(n, tx)
        print(main_n, 'frames')

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)
