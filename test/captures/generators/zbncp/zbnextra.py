# Helper module for the zbncp capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Hand-made frames: status categories, ACKs, fragments, dump info headers and
# the reproducers of the fixed bugs.
import struct
from zbnlib import dump, frame, IND, ll, REQ, RSP
from zbntable import BODIES, CALL_IDS

ID = {n: c for c, n in CALL_IDS}


def extra_clean():
    F = []
    A = lambda n, f: F.append((n, f))
    # Status of a response: every category and the "other" branch.
    for cat, sts in ((0, (0, 1, 4, 200)), (1, (0, 2)), (2, (0xe0, 0xe1, 0)), (3, (0xa0, 1, 0)),
                     (4, (0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xb0, 0xb1, 0, 0xff)),
                     (5, (0, 1)), (6, (0, 1, 2, 3)), (7, (0x42,)), (0xff, (1,))):
        for st in sts:
            A('status_%d_%d' % (cat, st), frame(RSP, 0x0004, b'\x01', cat=cat, status=st))
    # ACK frames: only the low level header, ack bit set.
    A('ack', ll(b'', flags=0x01))
    A('ack_seq', ll(b'', flags=0x01 | 0x08 | 0x20))
    A('retrans', frame(REQ, 0x0004, b'', flags=0xC2))
    # Fragments: first fragment, middle and last, then a first fragment of
    # another call and its last fragment.
    A('first_fragment', frame(REQ, 0x0001, b'\x11' * 8, flags=0x40))
    A('fragment', ll(b'\x00\x00' + b'\x22' * 8, flags=0x00))
    A('last_fragment', ll(b'\x00\x00' + b'\x33' * 4, flags=0x80))
    A('first_fragment_2', frame(RSP, 0x0004, b'\x01', flags=0x40))
    A('last_fragment_2', ll(b'\x00\x00' + b'\x44' * 4, flags=0x80))
    A('last_fragment_orphan', ll(b'\x00\x00' + b'\x55' * 4, flags=0x80))
    A('fragment_crc_only', ll(b'\x00\x00', flags=0x00))
    # Dump info header (Wireshark's own pre-header for NCP traffic).
    A('dump_to_host', dump(frame(IND, 0x0001, b''), options=0x01))
    A('dump_from_host', dump(frame(REQ, 0x0004, b''), options=0x00))
    A('dump_int_state', dump(frame(REQ, 0x0004, b''), options=0x02))
    A('dump_tx_conflict', dump(frame(REQ, 0x0004, b''), options=0x05))
    A('dump_other_type', dump(frame(REQ, 0x0004, b''), ncp_type=0x07))
    # Not a ZBNCP frame (wrong signature) and a bare signature.
    A('unknown_call_id', b'\xde\xad\x0c\x00\x06\xc0\x00' + b'\x00' * 8)
    A('bad_signature', b'\x00\x00\x0c\x00\x06\xc0\x00' + b'\x00' * 8)
    # Reproducer: APS_GET_GROUP_TABLE response with three groups (each
    # group is one 16 bit item; before the fix this was one item of
    # length 6 with an expert info).
    A('group_table_rsp', frame(RSP, 0x0309, bytes([3, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00])))
    A('group_table_rsp_one', frame(RSP, 0x0309, bytes([1, 0x34, 0x12])))
    A('group_table_rsp_none', frame(RSP, 0x0309, bytes([0])))
    A('group_table_rsp_many', frame(RSP, 0x0309, bytes([200]) + b''.join(struct.pack('<H', 0x100 + i) for i in range(200))))
    # Messages whose body is a status category and status (the same switch
    # as the status of a response): rejoin failed, CBKE server finished and
    # the response of Start Key Exchange.
    for name, pt in (('NWK_REJOIN_FAILED_IND', IND), ('SECUR_CBKE_SRV_FINISHED_IND', IND), ('SECUR_START_KE', RSP)):
        for cat, st in ((0, 0), (0, 4), (2, 0xe1), (3, 0xa0), (4, 0xa0), (4, 0xa9), (6, 1), (5, 0), (0x20, 7)):
            A('%s_status_%d_%d' % (name.lower(), cat, st), frame(pt, ID[name], bytes([cat, st]) + (struct.pack('<HQ', 0x1234, 0x00124b0001020304) if name == 'SECUR_CBKE_SRV_FINISHED_IND' else b'')))
    # ZDO device authorized indication: legacy, TCLK and another type.
    for t, st in ((0, 0), (0, 1), (0, 9), (1, 0), (1, 1), (1, 7), (2, 0)):
        A('dev_authorized_ind_%d_%d' % (t, st), frame(IND, ID['ZDO_DEV_AUTHORIZED_IND'],
          struct.pack('<QHB', 0x00124b0001020304, 0x1234, t) + (bytes([st]) if t < 2 else b'')))
    # Big packet to NCP and debug write (text and binary).
    A('manuf_send_single_packet', frame(REQ, ID['NCP_HL_MANUF_SEND_SINGLE_PACKET'], bytes([4]) + bytes(range(1, 5))))
    A('manuf_send_single_packet_short', frame(REQ, ID['NCP_HL_MANUF_SEND_SINGLE_PACKET'], bytes([10]) + bytes(range(1, 4))))
    A('debug_write_text', frame(REQ, ID['DEBUG_WRITE'], b'\x00' + b'hello ncp'))
    A('debug_write_bin', frame(REQ, ID['DEBUG_WRITE'], b'\x01' + bytes(range(1, 9))))
    A('debug_write_other', frame(REQ, ID['DEBUG_WRITE'], b'\x02' + bytes(range(1, 4))))
    # Certificates: crypto suite 1 (22/48/21 octets) and 2 (37/74/36).  The
    # octets are repeated filler, not real keys or certificates.
    for cs, (a, b, c) in ((1, (22, 48, 21)), (2, (37, 74, 36)), (3, (0, 0, 0))):
        tail = bytes([0x11]) * a + bytes([0x22]) * b + (bytes([0x33]) * c if cs != 3 else b'')
        A('add_cert_cs%d' % cs, frame(REQ, ID['SECUR_ADD_CERT'], bytes([cs]) + tail))
        A('get_cert_rsp_cs%d' % cs, frame(RSP, ID['SECUR_GET_CERT'], bytes([cs]) + bytes([0x11]) * a + bytes([0x22]) * b))
    # Frames of "Empty: only common headers" calls with one octet of
    # padding after the header, so that the switch is reached (a frame
    # without any body returns before the switch).
    for name in EMPTY_BODY_CALLS:
        A('%s_padded' % name.lower(), frame(REQ, ID[name], b'\x00'))
    return F


EMPTY_BODY_CALLS = (
    'APSME_CLEAR_BIND_TABLE', 'PIM_START_FAST_POLL', 'PIM_START_POLL', 'PIM_STOP_POLL',
    'PIM_DISABLE_TURBO_POLL', 'NWK_START_WITHOUT_FORMATION', 'PIM_SINGLE_POLL',
    'PARENT_LOST_IND', 'PIM_TURBO_POLL_CONTINUOUS_LEAVE', 'PIM_TURBO_POLL_PACKETS_LEAVE',
    'STOP_CONCENTRATOR_MODE', 'PIM_TURBO_POLL_CANCEL_PACKET', 'SECUR_KE_WHITELIST_DEL_ALL',
    'SECUR_CLEAR_KEY_TABLE', 'SECUR_NWK_INITIATE_KEY_SWITCH_PROCEDURE', 'SECUR_REMOVE_ALL_IC',
    'MANUF_MODE_END', 'MANUF_START_TONE', 'MANUF_STOP_TONE', 'MANUF_STOP_STREAM_RANDOM',
    'MANUF_START_TEST_RX', 'MANUF_STOP_TEST_RX', 'OTA_RUN_BOOTLOADER', 'OTA_START_UPGRADE_IND',
)


def extra_malformed():
    F = []
    # Length fields larger than the data: exceptions with a tree.
    # BIG_PKT_TO_NCP: the "Packet" item is an FT_UINT_BYTES added with ENC_NA
    # and the packet length as its length argument, so it throws on every
    # frame (length 6, 0 and 2 shown; see the README).
    F.append(frame(REQ, 0x0020, struct.pack('<H', 6) + bytes(range(1, 7))))
    F.append(frame(REQ, 0x0020, struct.pack('<H', 0)))
    F.append(frame(REQ, 0x0020, struct.pack('<H', 2) + struct.pack('<H', 3) + bytes(range(1, 4))))
    F.append(frame(RSP, 0x0006, bytes([200, 1, 2, 3])))              # channel list
    F.append(frame(RSP, 0x0309, bytes([255, 1, 2])))                  # group table
    F.append(ll(b'\x00\x00\x00', flags=0xC0))                         # header cut in the high level header
    F.append(ll(b'\x00\x00\x00\x00\x00', flags=0xC0))
    F.append(ll(b'', flags=0xC0))                                     # no body at all
    F.append(ll(b'\x00', flags=0xC0))                                 # one octet of the CRC
    F.append(b'\xde\xad')                                             # signature only
    F.append(b'\xde')
    F.append(b'ZBNCP\x01\x06')                                        # dump header cut
    F.append(b'ZBNCP\x01')
    return F


main_ = None
