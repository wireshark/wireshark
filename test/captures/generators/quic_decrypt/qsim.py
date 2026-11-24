# Helper module for the quic_decrypt capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""In-memory aioquic client/server pairs written as IPv4/UDP over 127.x.
aioquic does all the QUIC/TLS crypto; nothing here touches protected bytes."""
import datetime
import struct
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.packet import (encode_quic_retry, encode_quic_version_negotiation,
                                 pull_quic_header)
from aioquic.quic.retry import QuicRetryTokenHandler
from aioquic.buffer import Buffer
from aioquic import tls
from aioquic.quic.packet import QuicPacketType


class XConn(QuicConnection):
    """A QuicConnection that can add frames aioquic never sends (the frame bytes are put
    into packets built and protected by aioquic's own packet builder)."""
    extra = None

    def _write_application(self, builder, network_path, now):
        if self.extra and self._cryptos[tls.Epoch.ONE_RTT].send.is_valid():
            builder.start_packet(QuicPacketType.ONE_RTT, self._cryptos[tls.Epoch.ONE_RTT])
            while self.extra:
                ft, pl = self.extra[0]
                buf = builder.start_frame(ft, capacity=len(pl) + 8)
                buf.push_bytes(pl)
                self.extra.pop(0)
        super()._write_application(builder, network_path, now)


def make_cert():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA256()))
    return cert, key


def ip_udp(src, dst, payload):
    udp = struct.pack('!HHHH', src[1], dst[1], 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0x4000, 64, 17, 0,
                     bytes(map(int, src[0].split('.'))), bytes(map(int, dst[0].split('.'))))
    return ip + udp


class Sim:
    def __init__(self, keylog_path):
        self.cert, self.key = make_cert()
        self.keylog = open(keylog_path, 'w')
        self.frames = []          # (time, packet, label)
        self.t = 1794139200.0   # 2026-11-08 12:00 UTC, inside the validity of the self-signed certificate
        self.marks = []           # (first frame number, text)
        self.retry = QuicRetryTokenHandler()

    def mark(self, text):
        self.marks.append((len(self.frames) + 1, text))

    def record(self, src, dst, data):
        self.frames.append((self.t, ip_udp(src, dst, data)))

    def write_pcap(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101))
            for ts, pkt in self.frames:
                f.write(struct.pack('<IIII', int(ts), int(ts * 1e6) % 1000000, len(pkt), len(pkt)) + pkt)

    def ccfg(self, alpn, **kw):
        c = QuicConfiguration(is_client=True, alpn_protocols=alpn, server_name='localhost',
                              verify_mode=0, secrets_log_file=self.keylog, **kw)
        return c

    def scfg(self, alpn, **kw):
        c = QuicConfiguration(is_client=False, alpn_protocols=alpn,
                              secrets_log_file=self.keylog, **kw)
        c.certificate = self.cert
        c.private_key = self.key
        return c

    def advance(self, dt=0.001):
        self.t += dt


class Pair:
    """A client connection and its server connection (created on the first datagram)."""

    def __init__(self, sim, ccfg, scfg, caddr, saddr, retry=False, ticket_handler=None,
                 ticket_fetcher=None, cls=QuicConnection, ctor_kw=None, autostart=True):
        self.cls = cls
        self.sim, self.ccfg, self.scfg = sim, ccfg, scfg
        self.caddr, self.saddr = caddr, saddr
        self.client = cls(configuration=ccfg, **(ctor_kw or {}))
        self.server = None
        self.retry = retry
        self.ticket_handler = ticket_handler
        self.ticket_fetcher = ticket_fetcher
        self.cevents, self.sevents = [], []
        self.policy = None        # fn(direction, n, data) -> 'ok' | 'drop' | 'hold' | 'dup'
        self.counts = {'c': 0, 's': 0}
        self.held = []
        self.retried = False
        self.on_event = None      # fn(is_client, event)
        if autostart:
            self.start()

    def start(self):
        self.client.connect(self.saddr, now=self.sim.t)

    def _act(self, d, data):
        self.counts[d] += 1
        return self.policy(d, self.counts[d], data) if self.policy else 'ok'

    def _deliver(self, d, data):
        s = self.sim
        if d == 'c':
            self._to_server(data)
        else:
            self.client.receive_datagram(data, self.saddr, now=s.t)

    def _to_server(self, data):
        s = self.sim
        if self.server is None:
            hdr = pull_quic_header(Buffer(data=data), host_cid_length=8)
            odcid = hdr.destination_cid
            rsc = None
            if self.retry:
                if not hdr.token:
                    scid = os.urandom(8)
                    tok = s.retry.create_token(address=self.caddr,
                                               original_destination_connection_id=odcid,
                                               retry_source_connection_id=scid, now=s.t)
                    rdata = encode_quic_retry(version=hdr.version, source_cid=scid,
                                              destination_cid=hdr.source_cid,
                                              original_destination_cid=odcid, retry_token=tok)
                    s.record(self.saddr, self.caddr, rdata)
                    self.client.receive_datagram(rdata, self.saddr, now=s.t)
                    return
                odcid = s.retry.validate_token(address=self.caddr, destination_cid=hdr.destination_cid,
                                               token=hdr.token, now=s.t)
                rsc = hdr.destination_cid
            self.server = self.cls(configuration=self.scfg,
                                         original_destination_connection_id=odcid,
                                         retry_source_connection_id=rsc,
                                         session_ticket_fetcher=self.ticket_fetcher,
                                         session_ticket_handler=self.ticket_handler)
        self.server.receive_datagram(data, self.caddr, now=s.t)

    def pump(self, rounds=200, timers=False, quiet_rounds=3):
        """Move datagrams until quiet. With timers, advance the clock to pending timers."""
        s = self.sim
        idle = 0
        for _ in range(rounds):
            moved = False
            for d in ('c', 's'):
                conn = self.client if d == 'c' else self.server
                if conn is None:
                    continue
                for data, addr in conn.datagrams_to_send(now=s.t):
                    src, dst = (self.caddr, self.saddr) if d == 'c' else (self.saddr, addr)
                    a = self._act(d, data)
                    if a != 'hold':
                        s.record(src, dst, data)
                    if a == 'drop':
                        pass
                    elif a == 'hold':
                        self.held.append((d, data, src, dst))
                    else:
                        self._deliver(d, data)
                        if a == 'dup':
                            s.record(src, dst, data)
                            self._deliver(d, data)
                    moved = True
                s.advance(0.0005)
            self._events()
            if not moved:
                if timers:
                    ts = []
                    for c in (self.client, self.server):
                        x = c.get_timer() if c is not None else None
                        if x is not None and x < s.t + 3.0:
                            ts.append(x)
                    if ts and idle < quiet_rounds:
                        s.t = max(s.t, min(ts)) + 0.0001
                        for c in (self.client, self.server):
                            if c is not None and c.get_timer() is not None and c.get_timer() < s.t:
                                c.handle_timer(now=s.t)
                        idle += 1
                        continue
                break
            idle = 0
            s.advance(0.001)

    def release(self, order=None):
        """Deliver held datagrams (optionally reordered by index list)."""
        h = self.held
        if order is not None:
            h = [h[i] for i in order]
        self.held = []
        for d, data, src, dst in h:
            self.sim.record(src, dst, data)
            self.sim.advance(0.0002)
            self._deliver(d, data)
        self._events()

    def _events(self):
        for conn, lst, isc in ((self.client, self.cevents, True), (self.server, self.sevents, False)):
            if conn is None:
                continue
            while (ev := conn.next_event()) is not None:
                lst.append(ev)
                if self.on_event:
                    self.on_event(isc, ev)
