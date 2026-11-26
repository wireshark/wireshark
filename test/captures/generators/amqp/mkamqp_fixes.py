#!/usr/bin/env python3
# Generates the third part of test/captures/amqp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Frames for the AMQP decoding and robustness fixes, appended by mkamqp.py
after the AMQP 0-x (10.0.0.0/24) and AMQP 1.0 (10.1.0.0/24) parts.

All hosts are in 10.2.0.0/24 (decoded cleanly) and 10.3.0.0/24 (values that
decode with an expert info), the broker listens on TCP port 5672. Every
packet is built here; nothing comes from a real network.

Usage: mkamqp_fixes.py [<output directory>]

Writes amqp-fixes.pcap with:
  10.2.0.1 -> 10.2.0.2  AMQP 0-9-1, 300 unacked basic.publish frames on a
                        channel, then single, repeated, unknown and
                        multiple basic.ack frames (the unacked list is
                        indexed by delivery tag)
  10.2.0.3 -> 10.2.0.2  AMQP 0-9-1, 120 basic.deliver frames that repeat
                        40 delivery tags, acked, nacked and rejected
  10.2.0.4 -> 10.2.0.2  AMQP 0-9-1, content headers of different media
                        types on two channels, each body decoded by the
                        media type of its own header (also on a second
                        pass)
  10.2.0.5 -> 10.2.0.2  AMQP 0-10, exchange.bind/unbind/bound with a
                        binding-key, message.release and acquire with
                        sequence sets of an even and an odd value count
  10.2.0.6 -> 10.2.0.2  AMQP 1.0, transfers with 300 data sections
  10.3.0.1 -> 10.3.0.2  AMQP 0-9-1 connection.start with a long string
                        and a byte array longer than the field table
  10.3.0.3 -> 10.3.0.2  AMQP 1.0 transfer with a vbin32 delivery tag of
                        length 0xffffffff
"""

import os
import sys

import mkamqp0 as m0
import mkamqp10 as m10
from mkamqp0 import (Pcap, TcpStream, ip, method, header, body, bits, sstr, lstr, table,
                     fv_S, fv_x, fv_I, u8, u16, u32, u64, basic_props, command, seqset, pack,
                     str8, map010, frame09, BASIC, CONNECTION, CHANNEL)

N_PUBLISH = 300     # publishes of the unacked-delivery stream
N_DELIVER = 120     # deliveries of the repeated-tag stream
N_TAGS = 40         # distinct delivery tags among them
N_SECTIONS = 300    # data sections of a transfer


def ip2(last):
    return (10, 2, 0, last)


def ip3(last):
    return (10, 3, 0, last)


def packed(pdus, per_segment):
    """Several PDUs in each TCP segment."""
    return [b''.join(pdus[i:i + per_segment]) for i in range(0, len(pdus), per_segment)]


def publish():
    return method(1, BASIC, 40, u16(0) + sstr('') + sstr('jobs') + bits(0, 0))


def ack(ch, tag, multiple=False):
    return method(ch, BASIC, 80, u64(tag) + bits(multiple))


def unacked_publishes(cap):
    """Many unacked publishes, then acks in the ways that find deliveries
    by tag. The broker confirms to the publisher, so the acks travel in
    the other direction."""
    st = TcpStream(cap, ip2(1), ip2(2), 42001)
    st.c(b'AMQP\x00\x00\x09\x01')
    st.c(*packed([publish() for _ in range(N_PUBLISH)], 50))
    st.s(ack(1, 7))                 # one delivery
    st.s(ack(1, 7))                 # the same tag again: nothing left
    st.s(ack(1, 100, True))         # 1 to 100 except 7
    st.s(*packed([ack(1, 10 ** 12 + i) for i in range(N_PUBLISH)], 50))   # unknown tags
    st.s(ack(1, 250))
    st.s(method(1, BASIC, 120, u64(251) + bits(0, 1)))   # nack
    st.s(ack(1, 0, True))           # everything that is left
    st.s(ack(1, 1))                 # nothing is left
    st.close()


def repeated_tags(cap):
    """Deliveries that repeat their tags: a single ack takes every
    delivery with the tag, a multiple ack the newest one with the tag and
    all older ones."""
    st = TcpStream(cap, ip2(3), ip2(2), 42002)
    st.c(b'AMQP\x00\x00\x09\x01')
    deliveries = [method(2, BASIC, 60, sstr('ctag') + u64(i % N_TAGS + 1) + bits(0) +
                         sstr('amq.direct') + sstr('jobs')) for i in range(N_DELIVER)]
    st.s(*packed(deliveries, 20))
    st.c(ack(2, 7))                 # three deliveries
    st.c(ack(2, 5, True))           # the newest tag 5 and everything older
    st.c(ack(2, 3))                 # was taken by the multiple ack
    st.c(ack(2, 6))                 # only the newest tag 6 is left
    st.c(method(2, BASIC, 120, u64(9) + bits(0, 1)))      # nack
    st.c(method(2, BASIC, 90, u64(11) + bits(1)))         # reject
    st.c(ack(2, 1000))              # unknown tag
    st.c(ack(2, 0, True))           # all that is left
    # new deliveries after everything was acked, with a tag that is back
    st.s(*packed([method(2, BASIC, 60, sstr('ctag') + u64(t) + bits(0) +
                         sstr('amq.direct') + sstr('jobs')) for t in (2, 2, 1)], 3))
    st.c(ack(2, 2))
    st.c(ack(2, 1))
    st.close()


JSON = b'{"order": 1}'
TEXT = b'plain text\n'


def content_params(cap):
    """The body of each content goes to the media type of its own header,
    also when the frames are dissected again."""
    st = TcpStream(cap, ip2(4), ip2(2), 42003)
    st.c(b'AMQP\x00\x00\x09\x01')
    st.c(method(1, CHANNEL, 10, sstr('')))
    st.c(method(2, CHANNEL, 10, sstr('')))

    def content(ch, data, ctype):
        return (header(ch, BASIC, len(data), *basic_props(ctype)) + body(ch, data))

    pub = lambda ch: method(ch, BASIC, 40, u16(0) + sstr('') + sstr('jobs') + bits(0, 0))
    st.c(pub(1) + content(1, JSON, 'application/json'))          # json
    st.c(pub(2) + content(2, TEXT, 'text/plain'))                # text
    # header and body in different segments, the other channel's header
    # in between
    st.c(header(1, BASIC, len(JSON), *basic_props('Application/JSON')))
    st.c(header(2, BASIC, len(TEXT), *basic_props('text/plain')))
    st.c(body(1, JSON))                                           # json (upper case type)
    st.c(body(2, TEXT))                                           # text
    st.c(pub(1) + content(1, JSON, 'application/json'))          # json
    st.c(pub(2) + content(2, JSON, 'application/json'))          # json
    # the last header of the connection is text/plain
    st.c(pub(1) + content(1, TEXT, 'text/plain'))                # text
    st.close()


def seq_body(*pairs):
    return seqset(*pairs)


def exchange_and_sets(cap):
    st = TcpStream(cap, ip2(5), ip2(2), 42004)
    st.c(b'AMQP\x01\x01\x00\x0a')
    # exchange.bind, unbind and bound with a binding-key (str8)
    st.c(command(7, 4, pack(0x0f) + str8('q.fix') + str8('fix.ex') + str8('fix.key.one') +
                 map010()))
    st.c(command(7, 5, pack(0x07) + str8('q.fix') + str8('fix.ex') + str8('fix.key.two')))
    st.c(command(7, 6, pack(0x0f) + str8('fix.ex') + str8('q.fix') + str8('fix.key.three') +
                 map010(), sync=1))
    st.c(command(7, 4, pack(0x05) + str8('q.fix') + str8('')))     # empty binding-key
    # message.release and message.acquire: the set belongs to "transfers"
    st.c(command(4, 4, pack(0x01) + seq_body((1, 5), (8, 9))))
    st.c(command(4, 4, pack(0x03) + seq_body((3, 3))))             # with set-redelivered
    st.c(command(4, 5, pack(0x01) + seq_body((10, 20))))
    st.c(command(4, 5, pack(0x01) + seq_body((1, 2), (4, 5), (7, 8))))
    # odd value counts: one value and three values, and a length that is
    # not a multiple of four
    st.c(command(4, 4, pack(0x01) + u16(4) + u32(77)))
    st.c(command(4, 5, pack(0x01) + u16(12) + u32(1) + u32(2) + u32(3)))
    st.c(command(4, 4, pack(0x01) + u16(6) + u32(5) + b'\0\0'))
    st.c(command(4, 5, pack(0x01) + u16(0)))                       # empty set
    st.close()


def data_sections(cap):
    """Transfers with hundreds of data sections. The "to" address of a
    transfer decides, with a Message Decoding entry, which sections are
    handed to another dissector, and it must not be taken from another
    transfer."""
    st = TcpStream(cap, ip2(6), ip2(2), 42005)
    st.c(m10.HDR_AMQP)
    st.s(m10.HDR_AMQP)

    def sections(n, fill):
        return b''.join(m10.described(m10.DATA, m10.vbin8(bytes([fill, i & 0xff])))
                        for i in range(n))

    def transfer(delivery_id, to, n, fill, more=False):
        msg = b''
        if to is not None:
            msg += m10.properties(message_id=m10.smalluint(delivery_id), to=to)
        msg += sections(n, fill)
        return m10.perf(m10.TRANSFER, m10.list8(m10.UINT0, m10.smalluint(delivery_id),
                                                m10.vbin8(b'dt%d' % delivery_id), m10.UINT0,
                                                m10.FALSE, m10.FALSE, m10.ubyte(0), m10.NULL,
                                                m10.TRUE if more else m10.FALSE),
                        payload=msg)

    st.c(transfer(1, 'sensors/equal', N_SECTIONS, 0xa1))        # decoded with the entry
    st.c(transfer(2, 'other/address', N_SECTIONS, 0xa2))        # not decoded
    st.c(transfer(3, None, N_SECTIONS, 0xa3))                   # no properties at all
    # two transfers in one segment: the "to" of the first must not be used
    # for the second
    st.c(transfer(4, 'sensors/equal', 40, 0xa4) + transfer(5, 'other/address', 40, 0xa5) +
         transfer(6, 'sensors/equal', 40, 0xa6))
    # sections of different types around the data sections
    st.c(m10.perf(m10.TRANSFER, m10.list8(m10.UINT0, m10.smalluint(7), m10.vbin8(b'dt7'),
                                          m10.UINT0, m10.FALSE),
                  payload=m10.properties(message_id=m10.smalluint(7), to='sensors/equal') +
                  m10.described(m10.DATA, m10.vbin8(b'one')) +
                  m10.described(m10.SEQUENCE, m10.list8(m10.smalluint(1))) +
                  m10.described(m10.DATA, m10.vbin32(b'two')) +
                  m10.described(m10.FOOTER, m10.map8((m10.sym8('x'), m10.smalluint(1))))))
    st.close()


def damaged(cap):
    """Values that are longer than what is left. They decode, with an
    expert info and the rest of the data consumed."""
    st = TcpStream(cap, ip3(1), ip3(2), 43001)
    st.c(b'AMQP\x00\x00\x09\x01')
    mech = b'PLAIN'
    loc = b'en_US'

    def start(entries):
        return method(0, CONNECTION, 10, u8(0) + u8(9) + table(*entries) +
                      lstr(mech) + lstr(loc))

    # a long string of five octets in a table that has room for three
    entry = b'\x01a' + b'S' + u32(5) + b'hello'
    st.s(method(0, CONNECTION, 10, u8(0) + u8(9) + u32(len(entry) - 2) + entry[:-2] +
                lstr(mech) + lstr(loc)))
    # the same for a byte array
    entry = b'\x01b' + b'x' + u32(9) + b'bytearray'
    st.s(method(0, CONNECTION, 10, u8(0) + u8(9) + u32(len(entry) - 4) + entry[:-4] +
                lstr(mech) + lstr(loc)))
    # a long string that fits, after one that does not
    st.s(start([('ok', fv_S('fits')), ('arr', fv_x(b'\x01\x02'))]))
    st.close()

    st = TcpStream(cap, ip3(3), ip3(2), 43002)
    st.c(m10.HDR_AMQP)
    # delivery-tag vbin32 with length 0xffffffff, then a data section
    items = m10.UINT0 + m10.UINT0 + b'\xb0\xff\xff\xff\xff'
    lst = b'\xc0' + bytes([1 + len(items), 3]) + items
    msg = b'\x00\x53\x77\xa1\x02hi'
    st.c(m10.frame(b'\x00\x53\x14' + lst + msg))
    # a data section whose length runs past the end of the frame
    st.c(m10.perf(m10.TRANSFER, m10.list8(m10.UINT0, m10.UINT0, m10.vbin8(b'dt')),
                  payload=b'\x00\x53\x75\xb0\x00\x00\x01\x00abc'))
    st.close()


def build_main():
    cap = Pcap()
    for gen in (unacked_publishes, repeated_tags, content_params, exchange_and_sets,
                data_sections, damaged):
        gen(cap)
    return cap


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    build_main().write(os.path.join(out, 'amqp-fixes.pcap'))


if __name__ == '__main__':
    main()
