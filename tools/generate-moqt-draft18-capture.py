#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the native QUIC fixture for TestDissectMoqt.

Requires aioquic, only when regenerating the fixture. Normal Wireshark tests
read the checked-in capture and need no additional Python packages.

An aioquic client and server exchange real encrypted QUIC datagrams in memory.
Packet comments identify each MoQT scenario; TLS secrets are embedded in the
PCAPNG. This makes the stream offsets, reassembly and second-pass tests visible
without depending on a live server, network timing or external key-log files.
"""

import argparse
import datetime
import gzip
import io
import ipaddress
import ssl
import struct

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def vi64(value):
    length = max(1, min(9, (value.bit_length() + 6) // 7))
    if length == 9:
        return b'\xff' + value.to_bytes(8, 'big')
    encoded = bytearray(value.to_bytes(length, 'big'))
    encoded[0] |= ((1 << (length - 1)) - 1) << (9 - length)
    return bytes(encoded)


def message(message_type, body):
    return vi64(message_type) + len(body).to_bytes(2, 'big') + body


def pad32(data):
    return data + bytes((-len(data)) % 4)


def block(block_type, body):
    length = len(body) + 12
    return struct.pack('<II', block_type, length) + body + struct.pack('<I', length)


def comment_option(comment):
    data = comment.encode('utf-8')
    return struct.pack('<HH', 1, len(data)) + pad32(data) + bytes(4)


def ipv4_udp(payload, source_port, destination_port, packet_id):
    loopback = ipaddress.IPv4Address('127.0.0.1').packed
    udp = struct.pack('!HHHH', source_port, destination_port, len(payload) + 8, 0)
    header = struct.pack(
        '!BBHHHBBH4s4s', 0x45, 0, len(payload) + 28, packet_id,
        0x4000, 64, 17, 0, loopback, loopback)
    checksum = sum(struct.unpack('!10H', header))
    checksum = (checksum & 0xffff) + (checksum >> 16)
    checksum = (checksum & 0xffff) + (checksum >> 16)
    header = header[:10] + struct.pack('!H', (~checksum) & 0xffff) + header[12:]
    return header + udp + payload


class Exchange:
    client_address = ('127.0.0.1', 50000)
    server_address = ('127.0.0.1', 4433)

    def __init__(self):
        self.now = 1_793_044_800.0
        self.packets = []
        self.secrets = io.StringIO()
        client_config = QuicConfiguration(
            is_client=True, alpn_protocols=['moqt-18'],
            verify_mode=ssl.CERT_NONE, secrets_log_file=self.secrets)
        server_config = QuicConfiguration(
            is_client=False, alpn_protocols=['moqt-18'])
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
        valid_from = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
        server_config.certificate = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(valid_from)
            .not_valid_after(valid_from + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA256()))
        server_config.private_key = key
        self.client = QuicConnection(configuration=client_config)
        self.server = QuicConnection(
            configuration=server_config,
            original_destination_connection_id=
                self.client.original_destination_connection_id)
        self.client.connect(self.server_address, self.now)
        self.flush('handshake')

    def flush(self, label):
        """Deliver datagrams and due timers, including delayed ACKs."""
        for _ in range(20):
            for sender, receiver, source, destination, suffix in (
                    (self.client, self.server, self.client_address,
                     self.server_address, 'client'),
                    (self.server, self.client, self.server_address,
                     self.client_address, 'server')):
                timer = sender.get_timer()
                if timer is not None and timer <= self.now:
                    sender.handle_timer(self.now)
                for data, _ in sender.datagrams_to_send(self.now):
                    packet = ipv4_udp(data, source[1], destination[1],
                                      len(self.packets))
                    self.packets.append((self.now, packet, f'{label}: {suffix}'))
                    receiver.receive_datagram(data, source, self.now)
                while sender.next_event() is not None:
                    pass
            self.now += 0.01

    def send(self, side, stream_id, data, label, fin=False):
        connection = self.server if side == 'server' else self.client
        connection.send_stream_data(stream_id, data, end_stream=fin)
        self.flush(label)

    def capture(self):
        data = block(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1))
        data += block(1, struct.pack('<HHI', 101, 0, 65535))  # DLT_RAW
        secrets = self.secrets.getvalue().encode('ascii')
        data += block(10, struct.pack('<II', 0x544c534b, len(secrets)) +
                      pad32(secrets) + bytes(4))
        for timestamp, packet, comment in self.packets:
            ticks = int(timestamp * 1_000_000)
            packet_header = struct.pack(
                '<IIIII', 0, ticks >> 32, ticks & 0xffffffff,
                len(packet), len(packet))
            data += block(6, packet_header + pad32(packet) +
                          comment_option(comment))
        return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', help='PCAPNG or PCAPNG.GZ output file')
    args = parser.parse_args()
    exchange = Exchange()

    # Native QUIC control streams start with SETUP, not a separate stream type.
    exchange.send('client', 2, message(0x2f00, b''), 'client-setup')
    exchange.send('server', 3, message(0x2f00, b''), 'server-setup')
    # A standalone FETCH request on a bidirectional stream: Request ID 4,
    # namespace ("example"), name "audio", Start (10,0), End (12,0), no params.
    fetch_request = bytes.fromhex('04 01 01 07') + b'example'
    fetch_request += bytes.fromhex('05') + b'audio' + bytes.fromhex('0a 00 0c 00 00')
    exchange.send('client', 0, message(0x16, fetch_request), 'fetch-request')
    exchange.send('server', 0, message(0x18, bytes.fromhex('00 0c 00 00')),
                  'fetch-ok')
    # The exact namespace-prefix regression from section 10.2.14.
    exchange.send('client', 4, message(0x02, bytes.fromhex('02 01 34 01 01 78')),
                  'namespace-prefix')
    exchange.send('server', 4, message(0x07, b'\x00'), 'request-ok')
    # Coalesced request-stream messages and a control-stream GOAWAY exercise
    # the shared framing loop and GOAWAY's context-dependent Request ID.
    exchange.send('client', 4,
                  message(0x02, bytes.fromhex('06 00')) +
                  message(0x10, bytes.fromhex('00 64')), 'request-goaway')
    exchange.send('server', 3, message(0x10, bytes.fromhex('00 64 0c')),
                  'control-goaway')
    # A complete error response spans packets and ends with a non-empty FIN.
    # The reassembled PDU starts at offset zero, unlike its final fragment.
    exchange.send('client', 8, message(0x03, bytes.fromhex('08 00 01 61 00')),
                  'fin-message-request')
    exchange.send('server', 8, bytes.fromhex('05 00 06 01'),
                  'fin-message-start')
    exchange.send('server', 8, bytes.fromhex('00 03 62 61 64'),
                  'fin-message-end', fin=True)

    # Review's original byte trace: Alias 1, Group 2, Object 0, payload "a".
    exchange.send('server', 7, bytes.fromhex('30 01 02 00 01 61'),
                  'subgroup-start')
    exchange.send('server', 7, bytes.fromhex('00 01 62'),
                  'subgroup-continuation')
    # Implicit Subgroup ID equals the first Object ID (7); next Object ID is 8.
    exchange.send('server', 11, bytes.fromhex('32 08 0b 07 01 7a'),
                  'implicit-subgroup-start')
    exchange.send('server', 11, bytes.fromhex('00 01 79'),
                  'implicit-subgroup-continuation')

    # A header and an object each span packets. Header: Alias 2, Group 3,
    # explicit Subgroup 4, default priority, per-object Properties field.
    exchange.send('server', 15, bytes.fromhex('35'), 'split-header-start')
    exchange.send('server', 15, bytes.fromhex('02 03 04 00 02 02'),
                  'split-header-and-object')
    exchange.send('server', 15, bytes.fromhex('0a 03 61 62 63'),
                  'split-object-end')
    exchange.send('server', 15, bytes.fromhex('00 00 00 03'),
                  'empty-end-of-group', fin=True)

    # FETCH Request ID 4, full first object, inherited fields on continuation,
    # then a split End of Non-Existent Range indicator.
    exchange.send('server', 19, bytes.fromhex('05 04 1c 0a 00 05 02 aa bb'),
                  'fetch-start')
    exchange.send('server', 19, bytes.fromhex('00 01 cc'),
                  'fetch-continuation')
    exchange.send('server', 19, vi64(0x8c) + b'\x0b', 'fetch-range-start')
    exchange.send('server', 19, b'\x00', 'fetch-range-end')
    exchange.send('server', 19, bytes.fromhex('00 01 dd'), 'fetch-after-range')

    exchange.send('server', 23, vi64(0x132b3e28) + bytes(2), 'padding-start')
    exchange.send('server', 23, bytes(3), 'padding-continuation')
    # FIN-only STREAM frames must not turn following QUIC frames into objects.
    for stream_id in (7, 11, 19, 23):
        exchange.server.send_stream_data(stream_id, b'', end_stream=True)
    exchange.server.send_ping(1)
    exchange.flush('fin-only')

    capture = exchange.capture()
    open_output = gzip.open if args.output.endswith('.gz') else open
    with open_output(args.output, 'wb') as output:
        output.write(capture)
    print(f'Wrote {len(exchange.packets)} packets to {args.output}')


if __name__ == '__main__':
    main()
