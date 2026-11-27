#
# Wireshark tests
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
"""NVMe-MI dissector tests.

The captures come from tools/gen-nvme-mi-test-capture.py, which holds each
section's frame map.  Most captures hold several builders' output, one pcapng
section per builder; a class names its SECTION and the section_span fixture
sets SPAN from frame.section_number.

Ordinary fixtures set IC and carry a real CRC-32C MIC (MI 2.2 3.1.1); the
IC = 0 vectors are in the MIC integrity section of nvme-mi-types.pcapng.
nvme-mi.mic shows the canonical CRC-32C value, as Appendix B prints it.
"""

import json
import re
import runpy
import struct
import subprocess
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from functools import partial
from pathlib import Path
from typing import ClassVar

import dissection_helpers as helpers
import pytest
from dissection_helpers import FRAME_LINKS, column, frame_in
from dissection_helpers import field as pdml_field

section = partial(helpers.section, links=FRAME_LINKS)
pdml_section = partial(helpers.pdml_section, links=FRAME_LINKS)
to_capture = partial(helpers.to_capture, links=FRAME_LINKS)
at = partial(helpers.at, links=FRAME_LINKS)
in_section = partial(helpers.in_section, links=FRAME_LINKS)


def decimal_forms(text):
    '''text with '.' and with ',' as the decimal separator: tshark prints
    computed decimals with the separator of the locale.'''
    return text, re.sub(r'(?<=\d)\.(?=\d)', ',', text)


# Every MI Get Log Page request shows this text, not as an expert info
# (NVMe-MI 2.2 Figure 137).
RAE_TEXT = ('Management Endpoint ignores RAE; if RAE is supported and this log'
            ' page is used with Asynchronous Events, it processes the command'
            " as if RAE=1 (NVMe-MI 'List of NVMe Admin Commands Supported using"
            " the Out-of-Band Mechanism', note 2)")

# Every NVMe-MI capture this suite reads.  nvme-mi-types.pcapng F600-F603 need
# a Lua shim to reach the dissector and are checked in TestNvmeMiMessageFraming.
CAPTURES = (
    'nvme-mi-admin-features.pcapng', 'nvme-mi-admin-identify.pcapng',
    'nvme-mi-admin-logpage.pcapng', 'nvme-mi-security.pcapng', 'nvme-mi-control.pcapng',
    'nvme-mi-mi-commands.pcapng', 'nvme-mi-sliced-context.pcapng', 'nvme-mi-spec-revisions.pcapng',
    'nvme-mi-mi4.pcapng', 'nvme-mi-pel.pcapng', 'nvme-mi-pel-events.pcapng', 'nvme-mi-transactions.pcapng', 'nvme-mi-tcg.pcapng',
    'nvme-mi-tcg-cross-layer.pcapng', 'nvme-mi-types.pcapng', 'nvme-mi-features-sel.pcapng',
    'nvme-mi-identify-win.pcapng', 'nvme-mi-logpage-fixed.pcapng',
    'nvme-mi-logpage-desc.pcapng', 'nvme-mi-p2-5.pcapng',
    'nvme-mi-csi-candidate.pcapng', 'nvme-mi-admin-transfer.pcapng',
    'nvme-mi-csi-lid-names.pcapng', 'nvme-mi-decode-correctness.pcapng',
    'nvme-mi-frame-rules.pcapng', 'nvme-mi-identify-underlying.pcapng',
    'nvme-mi-mfr-defaults.pcapng', 'nvme-mi-pda.pcapng', 'nvme-mi-rate-limiting.pcapng',
    'nvme-mi-ror-tag-owner.pcapng', 'nvme-mi-spec-revisions-fields.pcapng',
    'nvme-mi-voltage.pcapng', 'nvme-mi-tcg-failed-send.pcapng',
    'nvme-tcp-tcg-failed-send.pcapng',
)


@pytest.mark.parametrize('capture', CAPTURES)
def test_no_dissector_exceptions(fields_table, capture):
    t = fields_table(capture, ('_ws.malformed.expert', '_ws.dissector_bug'))
    assert column(t, '_ws.malformed.expert') == column(t, '_ws.dissector_bug') == {}


@pytest.mark.parametrize('capture', CAPTURES)
def test_second_pass_matches_first(assert_pass_parity, capture):
    assert_pass_parity(capture)


# mctp-transport is the control: the tap reports its experts without NVMe-MI.
@pytest.mark.parametrize('capture', CAPTURES + ('mctp-transport.pcapng',))
def test_null_tree_experts(dissect_pdml, expert_tap_counts, capture):
    """The expert tap, which builds no tree, sees exactly the tree's experts."""
    p = dissect_pdml(capture)
    assert expert_tap_counts(capture) == Counter(m for n in p.packets for m in p.experts(n))


# Only standard columns: plain summary requests no protocol tree.  In
# mctp-version-state, an invalid v2 SOM|EOM cannot replace F1 on this path.
@pytest.mark.parametrize('capture', ('nvme-mi-csi-candidate.pcapng', 'mctp-version-state.pcapng',
                                     'nvme-mi-tcg-cross-layer.pcapng'))
def test_null_tree_summary_matches_full_tree(cmd_tshark, capture_file, test_env, capture):
    command = [cmd_tshark, '-n', '-r', capture_file(capture),
               '-o', 'gui.column.format:"Protocol","%p","Info","%i"']
    tree = subprocess.check_output(
        command + ['-Tfields', '-e', '_ws.col.protocol', '-e', '_ws.col.info'],
        encoding='utf-8', env=test_env)
    for extra in ([], ['-2']):
        summary = subprocess.check_output(command + extra, encoding='utf-8', env=test_env)
        assert summary.split() == tree.split()


class TestNvmeMiPersistentEventHeader:
    """MI-5a header: Base 2.3 Fig 230, timestamp Base 2.4 Fig 480."""

    FILE = 'nvme-mi-pel.pcapng'
    PREFIX = 'nvme.cmd.get_logpage.pel.'

    @pytest.mark.parametrize('suffix,pos,size,value', [
        ('lid', 0, 1, 0x0d), ('tnev', 4, 4, 0x01020304),
        ('tll', 8, 8, 0x0102030405060708), ('lrev', 16, 1, 3),
        ('lhl', 18, 2, 492), ('timestamp', 20, 6, 0x010203040506),
        ('synch', 26, 1, 1), ('origin', 26, 1, 1),
        ('pwrcc', 44, 8, 0x1122334455667788),
        ('vid', 52, 2, 0x1234), ('ssvid', 54, 2, 0x5678),
        ('gnum', 372, 2, 0xabcd), ('rcpid', 374, 4, 0x5a),
        ('rcpit', 374, 4, 2), ('rce', 374, 4, 1),
    ])
    def test_numeric_fields(self, dissect_pdml, suffix, pos, size, value):
        node = dissect_pdml(self.FILE).field(2, self.PREFIX + suffix)
        assert (int(node['pos']), int(node['size'])) == (40 + pos, size)
        if suffix in ('synch', 'rce'):
            assert node['show'] == 'True'
            assert int(node['value'], 16) == value
        else:
            assert int(node['show'], 0) == value

    @pytest.mark.parametrize('suffix,pos,size,value', [
        ('poh', 28, 16, '1032547698badcfe0123456789abcdef'),
        ('sn', 56, 20, b'PEL-SERIAL-012345678'.hex()),
        ('mn', 76, 40, b'PEL MODEL'.ljust(40, b' ').hex()),
        ('seb', 480, 32, 'feff' + '00' * 25 + 'c0' + '00' * 4),
    ])
    def test_byte_fields(self, dissect_pdml, suffix, pos, size, value):
        node = dissect_pdml(self.FILE).field(2, self.PREFIX + suffix)
        assert (int(node['pos']), int(node['size']), node['value']) == (
            40 + pos, size, value)

    def test_seb_event_types(self, dissect_pdml):
        # Base 2.4 Figure 233: bit n is event type n; 0xfe 0xff set 1-15,
        # 0xc0 in byte 27 sets 222 and 223 (Vendor Specific, TCG Defined).
        p = dissect_pdml(self.FILE)
        got = [int(n.rsplit('(', 1)[1].rstrip(')'), 16)
               for n in p.shownames(2, self.PREFIX + 'seb.event')]
        assert got == [*range(1, 16), 0xde, 0xdf]
        assert p.label(2, self.PREFIX + 'seb').endswith('(17 supported)')

    def test_nqn(self, dissect_pdml):
        p = dissect_pdml(self.FILE)
        node = p.field(2, self.PREFIX + 'subnqn')
        assert node['show'] == 'nqn.2026-11.org.example:pel'
        assert (node['pos'], node['size']) == ('156', '256')
        assert p.field(54, self.PREFIX + 'subnqn')['show'] == 'nqn.2026-11.org.example:caf\u00e9'

    def test_rcpit_labels(self, dissect_pdml):
        # LOG-4: Base 2.4 Figure 233.
        p = dissect_pdml(self.FILE)
        for frame, text in ((20, 'No Reporting Context (0)'), (22, 'NVM Subsystem Port (1)'),
                            (10, 'Management Endpoint (2)'), (24, 'Reserved (3)')):
            assert p.label(frame, self.PREFIX + 'rcpit') == text

    def test_window_values(self, assert_frames_match):
        p = self.PREFIX
        assert_frames_match(self.FILE, [
            (4, f'{p}lhl == 492 && !{p}timestamp && !{p}invalid_header'),
            (6, f'{p}timestamp == 0x010203040506 && {p}origin == 1'),
            (8, f'{p}pwrcc == 0x1122334455667788 && {p}sn == "PEL-SERIAL-012345678"'),
            (10, f'{p}gnum == 0xabcd && {p}rce == 1 && {p}rcpit == 2 && {p}rcpid == 0x5a'),
            (12, f'{p}seb && !{p}gnum'),
            (14, f'!{p}poh && {p}vid == 0x1234 && {p}ssvid == 0x5678'),
            (16, f'!{p}timestamp && {p}origin == 1 && {p}synch == 1'),
            (18, f'{p}gnum == 0xabcd && {p}rcpid == 0x5a'),
            (20, f'{p}rce == 0 && {p}rcpit == 0 && {p}rcpid == 0'),
            (22, f'{p}rce == 1 && {p}rcpit == 1 && {p}rcpid == 0x1234'),
            (24, f'{p}rce == 1 && {p}rcpit == 3 && {p}rcpid == 0xab'),
            (26, f'{p}synch == 0 && {p}origin == 0'),
            (28, f'{p}synch == 1 && {p}origin == 0'),
            (30, f'{p}synch == 0 && {p}origin == 1'),
            (32, f'{p}synch == 0 && {p}origin == 6'),
            (34, f'{p}invalid_header && !{p}timestamp'),
            (36, f'{p}invalid_header && !{p}timestamp'),
            (38, f'{p}invalid_header && !{p}timestamp'),
            (40, f'{p}lrev == 4 && nvme.window_decode_skipped && !{p}timestamp'),
            (42, f'{p}tnev == 0 && {p}tll == 512 && !{p}events && !_ws.expert'),
            # A 4-byte event cannot hold its 24-byte header (Figure 231).
            (44, f'{p}extension == de:ad:be:ef && {p}event && {p}invalid_event'),
            (46, f'{p}tll == 512 && !{p}events && !_ws.expert'),
            # Same endpoint, no new context: frame 46's TLL of 512 still holds.
            (48, f'{p}past_tll == 01:02:03:04 && !_ws.expert'),
            (50, f'!{p}lid && !{p}timestamp && nvme.window_decode_skipped'),
            (52, f'!{p}lid && !{p}timestamp && nvme.window_decode_skipped'),
            (56, f'!{p}subnqn && !_ws.expert'),
            (58, f'{p}tll == 512 && {p}seb && !{p}events && !_ws.expert'),
        ])

    def test_partial_field_anchors(self, dissect_pdml):
        p = dissect_pdml(self.FILE)
        for frame, suffix, pos, size in (
                (6, 'timestamp', 40, 6), (10, 'rcpid', 42, 4),
                (12, 'seb', 40, 32), (14, 'vid', 60, 2),
                (16, 'origin', 42, 1), (18, 'rcpid', 42, 4),
                (44, 'extension', 552, 4), (44, 'event', 556, 4)):
            node = p.field(frame, self.PREFIX + suffix)
            assert (int(node['pos']), int(node['size'])) == (pos, size)


class TestNvmeMiPersistentEvents:
    """MI-5a/5b events: Base 2.3 Figures 229-256, Base 2.4 Figure 257.

    Frames 20-50 read one log in windows over one endpoint, whose reporting
    context carries event boundaries from one read to the next; frames 58-60
    do the same for a Set Feature event, whose SFEL lays out the rest.
    """

    FILE = 'nvme-mi-pel-events.pcapng'
    P = 'nvme.cmd.get_logpage.pel.'
    E = 'nvme.cmd.get_logpage.pel.event.'

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_events(self, assert_frames_match, two_pass):
        p, e = self.P, self.E
        aer_tlp = ':'.join(f'{b:02x}' for b in range(0x40, 0x50))
        cqe = ':'.join(f'{b:02x}' for b in range(0xa0, 0xb0))
        skipped = f'{p}events && nvme.window_decode_skipped && !{p}event'
        assert_frames_match(self.FILE, [
            (2, (f'count({p}event) == 5 && {e}et == 0x01 && {e}etr == 1 && {e}ehl == 21'
                f' && {e}etstp == 0x030405060708 && {e}synch == 1 && {e}pelpid == 0x0010'
                f' && nvme.cmd.get_logpage.smart.cw == 0x01 && nvme.cmd.get_logpage.smart.ct == 310'
                f' && {e}fwc.ofr == "OLDFW001" && {e}fwc.nfr == "NEWFW002" && {e}fwc.fslt == 2'
                f' && {e}fwc.vafcrc == 0x1234 && {e}tsc.ptstp == 0x010203040506'
                f' && {e}tsc.origin == 1 && {e}tsc.msr == 0x1122334455667788'
                f' && {e}por.frev == "FREV0003" && count({e}por.desc) == 2 && {e}por.fa == 2'
                f' && {e}por.rdnf == 1 && {e}por.cpwrc == 7 && {e}por.pom == 0x99'
                f' && {e}por.ctstp == 0x060504030201 && {e}hwe.code == 1 && {e}hwe.pciedsr == 0x10'
                f' && {e}hwe.pcieas.aers == 1 && {e}hwe.pcieatplr == {aer_tlp} && !_ws.expert')),
            (4, (f'count({e}hwe.code) == 10 && {e}hwe.pcieas.aers == 0 && !{e}hwe.pcieaes'
                f' && {e}hwe.lnksta == 0x1043 && nvme.cmd.get_logpage.smart.cw == 0x05'
                f' && nvme.cmd.get_logpage.egroup.cw == 0x0c && {e}hwe.egid == 3'
                f' && {e}hwe.upl && {e}hwe.upli.uploa == 1 && {e}hwe.cqe == {cqe}'
                f' && {e}hwe.cst.cnr == 1 && {e}hwe.cst.acmnr == 1 && {e}hwe.cst.nnr == 0'
                f' && {e}hwe.cst.crime == 1 && {e}hwe.ahei == ca:fe:f0:0d && !_ws.expert')),
            (6, (f'count({p}event) == 4 && {e}et == 0xdf && {e}et == 0x11 && {e}pit == 2'
                f' && {e}data == 01:02:03:04:05 && {e}hdr_ext == e0:e1:e2:e3'
                f' && {e}vsi == 11:22:33:44 && {e}tsc.msr == 5 && !_ws.expert')),
            (8, f'count({p}event) == 5 && {p}tnev_mismatch'),
            (10, f'count({p}event) == 2 && {p}invalid_event && {p}events'),
            (12, f'{p}invalid_event && !{e}data && !{p}tnev_mismatch'),
            (14, f'{p}invalid_event && {p}events'),
            (16, (f'count({p}event_revision) == 2 && !{e}hwe.code'
                 f' && !nvme.cmd.get_logpage.smart.cw')),
            (18, f'count({p}event_length) == 2 && !{e}fwc.ofr && !{e}por.frev'),
            (20, f'{p}tll == 666 && !{p}event && !_ws.expert'),
            (22, skipped),
            (24, f'{e}et == 3 && {e}tsc.msr == 5 && !_ws.expert'),
            (26, f'{e}et == 4 && {e}cntlid == 1 && !{e}etstp && !_ws.expert'),
            (28, f'{e}el == 44 && {e}data && !{e}por.frev && !_ws.expert'),
            (30, (f'count({p}event) == 2 && count({e}et) == 1 && {e}et == 2'
                 f' && {e}por.pom == 4 && {e}fwc.vafcrc == 0x1234 && !_ws.expert')),
            (32, f'{e}et == 3 && {e}tsc.msr == 5 && !_ws.expert'),
            (34, (f'{p}event && !{e}et && !{e}fwc.nfr && {e}fwc.vafcrc == 0x1234'
                 f' && {p}past_tll == de:ad:be:ef:01:02 && !_ws.expert')),
            (36, f'{p}tll == 666 && {p}rce == 1 && !{p}event'),
            (38, f'{e}fwc.nfr == "NEWFW002" && !_ws.expert'),
            (40, f'{p}rce == 0 && !{p}event'),
            (42, skipped),
            (44, f'{e}et == 3 && !_ws.expert'),
            (46, f'{p}gnum == 2'),
            (48, skipped),
            (50, f'nvme.window_decode_skipped && !{p}lid'),
            # MI-5b: Base 2.3 Figures 244-256, Base 2.4 Figure 257.
            (52, (f'count({p}event) == 10 && {e}cns.nmcdw10.sel == 1 && {e}cns.nsze == 4096'
                 f' && {e}cns.ncap == 2048 && nvme.cmd.identify.ns.flbas == 2'
                 f' && nvme.cmd.identify.ns.dps == 1 && nvme.cmd.identify.ns.nmic == 1'
                 f' && {e}cns.anagrpid == 5 && {e}cns.nvmsetid == 1 && {e}cns.endgid == 2'
                 f' && {e}nsid == 0xffffffff && nvme.cmd.identify.ctrl.fna == 0x05'
                 f' && nvme.cmd.format_nvm.dword10 == 0x203 && {e}fmc.fnvms.fnvme == 1'
                 f' && {e}fmc.fnvms.incpltf == 1 && {e}cinfo == 0xbeef && {e}fmc.info.p == 1'
                 f' && {e}fmc.info.sc == 0x81 && {e}fmc.info.sct == 2'
                 f' && nvme.cmd.identify.ctrl.sanicap == 0x60000007'
                 f' && nvme.cmd.sanitize.dword10.sanact == 2 && nvme.cmd.sanitize.ovrpat == 0xa5a5a5a5'
                 f' && nvme.cmd.get_logpage.sanitize.sprog == 0xffff'
                 f' && nvme.cmd.get_logpage.sanitize.sstat == 0x0101 && {e}cinfo == 0x42'
                 f' && {e}te.otmp == 7 && {e}te.thresh == 2 && {e}et == 0x0e'
                 f' && {e}cdp.ps.cdprfs == 1 && {e}cdp.ps.cdpce == 0 && {e}cdp.perid == 3'
                 f' && {e}cdp.ped == c0:c1:c2 && {e}ensc.esubid == 7 && {e}ensc.otyp == 2'
                 f' && {e}ensc.eeid.nsid == 0x11 && {e}ensc.ueid.nsid == 0x22'
                 f' && {e}ensc.otyp == 5 && {e}ensc.eeid.cntlid == 0x33'
                 f' && {e}ensc.ueid.cntlid == 0x44 && !_ws.expert')),
            (54, (f'count({p}event) == 4 && {e}sfe.sfel.dwc == 2 && {e}sfe.sfel.lccdw0 == 1'
                 f' && {e}sfe.sfel.mbc == 4 && count({e}sfe.cdw) == 2 && {e}sfe.cdw == 4'
                 f' && {e}sfe.cdw == 0x15e && {e}sfe.mbuf == "MBUF" && {e}sfe.ccdw0 == 0x12345678'
                 f' && nvme.cmd.get_logpage.telemetry.li == 7 && nvme.cmd.get_logpage.telemetry.da1b == 3'
                 f' && count({e}vse.desc) == 3 && {e}vse.vsedt == 1 && {e}vse.vsed.str == "THERMAL"'
                 f' && {e}vse.vsed.int == -5 && {e}vse.uidx == 1 && {e}vse.vsed == 0a:0b'
                 f' && {e}et == 0xdf && {e}data == d0:d1 && !_ws.expert')),
            (56, (f'count({p}event_length) == 4 && count({p}event_revision) == 1'
                 f' && !{e}sfe.cdw && count({e}vse.desc) == 1 && !{e}vse.vsed'
                 f' && !{e}nsid && !{e}te.otmp && !{p}invalid_event')),
            (58, f'{e}sfe.sfel.dwc == 2 && !{e}sfe.cdw && !_ws.expert'),
            (60, (f'count({e}sfe.cdw) == 2 && {e}sfe.mbuf == "MBUF"'
                 f' && {e}sfe.ccdw0 == 0x12345678 && !{e}sfe.sfel && !_ws.expert')),
        ], two_pass=two_pass)

    def test_anchors(self, dissect_pdml):
        p = dissect_pdml(self.FILE)
        for frame, name, pos, size in (
                (2, 'event', 552, 536), (26, 'event', 40, 10),
                (30, 'event', 40, 40), (30, 'event.por.desc', 44, 36),
                (34, 'past_tll', 46, 6)):
            node = p.field(frame, self.P + name)
            assert (int(node['pos']), int(node['size'])) == (pos, size)

    def test_tnev_message(self, dissect_pdml):
        messages = dissect_pdml(self.FILE).shows(8, '_ws.expert.message')
        assert 'TNEV is 7 but the log holds 5 events' in messages

    def test_ns_mgmt_sel_labels(self, dissect_pdml):
        # LOG-1: Base 2.4 Figure 446.
        s = dissect_pdml(self.FILE).shownames(62, self.E + 'cns.nmcdw10.sel')
        assert len(s) == 4
        assert s[0].endswith('Select: Create (0x0)')
        assert s[1].endswith('Select: Delete (0x1)')
        assert s[2].endswith('Select: Restore Default Namespace Configuration (0x2)')
        assert s[3].endswith('Select: Reserved (0x3)')


class TestNvmeMiMessageFraming:
    """NVMe-MI message header and Control Primitive framing (MI 2.2 Figures 20, 29-47)."""

    FILE = 'nvme-mi-types.pcapng'
    SECTION = 9
    EXPERTS = (
        # Body length reasons; frames cut by the capture are short instead.
        ('nvme-mi.control.truncated', [110, 365]),
        ('nvme-mi.control.excess_body', [106, 109, 353, 359, 373, 375, 377, 379, 381]),
        ('nvme-mi.oob_response_ic', [4, 7]),
        ('nvme-mi.message_too_large', [117, 250]),
        ('nvme-mi.duplicate_mpr', [323, 329, 342, 347]),
        ('nvme-mi.mic_bad', [345]),
        ('mctp.tu.mismatch', [113, *range(251, 320), 394]),
        ('mctp.assembly.orphan', [395]),
        # Figure 20 header rules and section 4.1.2's MPR prohibition.
        ('nvme-mi.aem_header', [9, 10, 11, 11]),
        ('nvme-mi.control.mpr', [83, 367]),
        ('nvme-mi.unable_to_abort_not_abort', [377]),
        ('nvme-mi.reserved_status', [383, 385, 387, 389]),
        ('nvme-mi.control.orphan_response', [410, 411]),
    )
    UNVERIFIED_MIC: ClassVar = [111, 112, 351, 355, 357, 361, 363, 367, 369, 371, 413]
    # frame -> (field, captured position, byte extent, extracted value)
    RUNS = (
        (13, ('nvme-mi.header.reserved1', 20, 4, 3)),
        (15, ('nvme-mi.header.reserved2', 20, 4, 63)),
        (17, ('nvme-mi.header.reserved3', 20, 4, 255)),
        (20, ('nvme-mi.control.cpsp.reserved', 26, 2, 65535)),
        (24, ('nvme-mi.control.cpsp.reserved', 26, 2, 65535)),
        (28, ('nvme-mi.control.cpsp.reserved', 26, 2, 65535)),
        (32, ('nvme-mi.control.cpsp.get_state_reserved', 26, 2, 32767)),
        (36, ('nvme-mi.control.cpsp.replay_reserved', 26, 2, 255)),
        (41, ('nvme-mi.control.cpsr.high_reserved', 26, 2, 16383)),
        (45, ('nvme-mi.control.cpsr.reserved', 26, 2, 65535)),
        (49, ('nvme-mi.control.cpsr.high_reserved', 26, 2, 16383)),
        (53, ('nvme-mi.control.mes.reserved', 26, 2, 1)),
        (57, ('nvme-mi.control.cpsr.replay_reserved', 26, 2, 32767)),
        (63, ('nvme-mi.control.cpas', 26, 2, 3)),
        (69, ('nvme-mi.pel.reserved', 25, 1, 31)),
        (73, ('nvme-mi.resp_reserved', 25, 3, 1)),
        (77, ('nvme-mi.mpr.reserved', 25, 1, 165)),
        (81, ('nvme-mi.mpr.reserved', 25, 1, 165)),
        (86, ('nvme-mi.admin.flags.reserved', 25, 1, 31)),
        (90, ('nvme-mi.admin.mptr', 40, 8, 165)),
        (94, ('nvme-mi.admin.reserved', 56, 8, 165)),
        (98, ('nvme-mi.admin.reserved', 56, 8, 165 << 32)),
        (103, ('nvme-mi.admin.resp_reserved', 25, 3, 165)),
        (349, ('nvme-mi.admin.reserved', 56, 8, (165 << 32) | 165)),
    )

    def test_decode(self, assert_frames_match):
        assert_frames_match(self.FILE, at(self.SPAN, [
            # IC is shown as sent, request or response.
            (1, 'nvme-mi.mctp-ic == 0 && !(_ws.expert.message contains "IC bit")'),
            (4, ('nvme-mi.mctp-ic == 0 &&'
                 ' _ws.expert.message contains "IC bit shall be set"')),
            (7, ('nvme-mi.mctp-ic == 0 &&'
                 ' _ws.expert.message contains "IC bit shall be set"')),
            (65, 'nvme-mi.control.mes.obsolete'),
            (10, ('_ws.expert.message == "CSI shall be cleared to 0 in an'
                  ' Asynchronous Event Message (NVMe-MI \'NVMe-MI Message Fields\')"')),
            # Pause's obsolete bits 0 and 1 are shown, not folded into CPSP.
            (19, 'nvme-mi.control.pause.obsolete0 == 1 && nvme-mi.control.pause.obsolete1 == 1'),
            (59, 'nvme-mi.control.pause.obsolete0 == 0 && nvme-mi.control.pause.obsolete1 == 1'),
            (61, 'nvme-mi.control.pause.obsolete0 == 1 && nvme-mi.control.pause.obsolete1 == 0'),
            # A CP MPR is prohibited: its bytes are raw, not an MPRT layout.
            (83, ('nvme-mi.control.data == a5:0a:00'
                  ' && !nvme-mi.mprt && !nvme-mi.mpr.reserved && !nvme-mi.response_is_mpr'
                  ' && !nvme-mi.control.cpsr')),
            (104, ('nvme-mi.control.opcode == 3 && !(_ws.expert.message contains "expected exactly 4")'
                   ' && !nvme-mi.control.excess_body && !nvme-mi.control.truncated')),
            (106, ('nvme-mi.control.opcode == 3 && nvme-mi.control.excess == a5'
                   ' && nvme-mi.control.excess_body && !nvme-mi.control.truncated'
                   ' && (_ws.expert.message contains "expected exactly 4") && !(_ws.expert.message contains "payload truncated")')),
            (109, ('nvme-mi.control.mes.ssta == 2 && nvme-mi.control.excess == a5'
                   ' && nvme-mi.control.excess_body && !nvme-mi.control.truncated')),
            (110, ('(_ws.expert.message contains "payload truncated") && nvme-mi.mic.status == 1 && !_ws.short'
                   ' && nvme-mi.control.truncated && !nvme-mi.control.excess_body')),
            (111, ('nvme-mi.control.opcode == 3 && nvme-mi.mic_unverified && _ws.short'
                   ' && !nvme-mi.control.truncated')),
            (112, 'nvme-mi.mic_unverified && _ws.short && !nvme-mi.control.truncated'),
            (114, ('mctp.fragment.count == 2'
                   ' && nvme-mi.control.opcode == 3 && nvme-mi.mic.status == 1')),
            (115, 'nvme-mi.response_to == 114'),
            # 4,224 bytes is the largest NVMe-MI Message; 4,225 is too large.
            (116, 'nvme-mi && nvme-mi.mic.status == 1 && !nvme-mi.message_too_large'),
            (117, 'nvme-mi.message_too_large && nvme-mi.mic.status == 1'),
            (183, ('mctp.fragment.count == 66 && mctp.reassembled.length == 4224'
                   ' && nvme-mi.mic.status == 1 && !nvme-mi.message_too_large')),
            (250, ('mctp.fragment.count == 67 && mctp.reassembled.length == 4225'
                   ' && nvme-mi.message_too_large && nvme-mi.mic.status == 1')),
            (320, ('mctp.fragment.count == 70 && mctp.reassembled.length == 70'
                   ' && nvme-mi.mic.status == 1 && !nvme-mi.message_too_large')),
            # MPR, replay and duplicate-MPR admission.
            (323, 'nvme-mi.response_to == 321 && nvme-mi.response_is_mpr'),
            (328, 'nvme-mi.response_to == 326 && !nvme-mi.duplicate_mpr'),
            (329, 'nvme-mi.response_to == 325 && nvme-mi.duplicate_mpr'),
            (336, ('nvme-mi.response_to == 332 && nvme-mi.replay_of == 333 && nvme-mi.replay_mpr'
                   ' && !nvme-mi.response_is_mpr && !nvme-mi.duplicate_mpr')),
            (342, 'nvme-mi.response_to == 338 && nvme-mi.duplicate_mpr'),
            (345, 'nvme-mi.mic_bad && !nvme-mi.response_to && !nvme-mi.duplicate_mpr'),
            (346, 'nvme-mi.response_to == 344 && !nvme-mi.duplicate_mpr'),
            (347, 'nvme-mi.response_to == 344 && nvme-mi.duplicate_mpr'),
            (349, 'nvme-mi.admin.reserved0 == 0xa5 && nvme-mi.admin.reserved1 == 0xa5'),
            (351, 'nvme-mi.mic_unverified && !nvme-mi.control.truncated && _ws.short'),
            (395, 'mctp.assembly.orphan && !mctp.reassembled.length && !nvme-mi'),
            (396, 'nvme-mi.control.opcode == 3 && !_ws.expert'),
            (397, 'nvme-mi.response_to == 396 && !_ws.expert'),
        ]))

    def test_control_error_layouts(self, assert_frames_match):
        """A CP error response has Figure 30's body; undefined statuses stay raw."""
        frames = []
        for status, group in ((2, (353, 355, 357)), (4, (359, 361, 363)), (3, (373,)),
                              (5, (375,)), (8, (377,)), (0x20, (379,)), (0x2a, (381,))):
            for frame in group:
                cond = [f'nvme-mi.control.status == {status}',
                        '!nvme-mi.control.tag', '!nvme-mi.control.cpsr']
                if frame in (355, 357, 361, 363):
                    cond += ['_ws.short', 'nvme-mi.mic_unverified', '!nvme-mi.control.truncated']
                else:
                    cond += ['(_ws.expert.message contains "expected exactly 4")',
                             'nvme-mi.control.excess_body', '!nvme-mi.control.truncated',
                             'nvme-mi.control.excess', '!_ws.short',
                             'nvme-mi.pel.byte == 0' if status == 4 else 'nvme-mi.resp_reserved == 0',
                             '!(_ws.expert.message contains "payload truncated")',
                             'nvme-mi.mic.status == 1']
                frames.append((frame, ' && '.join(cond)))
        for frame, status in ((383, 9), (385, 0x1f), (387, 0x2b), (389, 0xdf), (391, 0xe0),
                              (393, 0xff)):
            frames.append((frame, (f'nvme-mi.control.status == {status}'
                                   ' && !nvme-mi.control.excess && !nvme-mi.control.excess_body'
                                   ' && !(_ws.expert.message contains "expected exactly 4")'
                                   ' && !nvme-mi.control.cpsr && '
                                   + ('nvme-mi.control.data == a5 && nvme-mi.reserved_status'
                                      if status < 0xe0 else
                                      'nvme-mi.control.data == 00:00:00:a5'
                                      ' && count(nvme-mi.control.data) == 1'
                                      ' && !nvme-mi.resp_vendor && !nvme-mi.control.tag'
                                      ' && !_ws.expert'))))
        frames.append((365, (
            'nvme-mi.control.status == 1'
            ' && (_ws.expert.message contains "payload truncated") && nvme-mi.control.data == 01 && !nvme-mi.control.tag'
            ' && !nvme-mi.control.cpsr && !nvme-mi.mprt && !nvme-mi.mpr.reserved'
            ' && !nvme-mi.pel.byte && !nvme-mi.response_is_mpr'
            ' && !(_ws.expert.message contains "expected exactly 4") && !_ws.short'
            ' && nvme-mi.mic.status == 1 && !nvme-mi.mic_unverified')))
        frames.append((367, ('nvme-mi.control.status == 1 && !nvme-mi.control.tag'
                             ' && !nvme-mi.mprt && nvme-mi.mic_unverified && _ws.short')))
        for frame in (369, 371):
            frames.append((frame, (
                'nvme-mi.mic_unverified && !nvme-mi.control.status && !nvme-mi.control.truncated'
                ' && _ws.short')))
        assert_frames_match(self.FILE, at(self.SPAN, frames))

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_control_vendor_status(self, assert_frames_match, two_pass):
        """Figure 29: a Vendor Specific status keeps its body, of any
        length, opaque, and still takes the request's opcode."""
        none = ('!nvme-mi.control.truncated && !nvme-mi.control.excess_body'
                ' && !nvme-mi.control.excess && !nvme-mi.resp_vendor'
                ' && !nvme-mi.control.tag && !nvme-mi.control.cpsr')
        frames = []
        for frame, status, data in ((399, 0xe0, None), (401, 0xe0, '01'),
                                    (403, 0xe0, '01:02'), (405, 0xe0, '01:02:03'),
                                    (407, 0xe0, '01:02:03:04:05'), (409, 0xff, '01')):
            frames.append((frame, ' && '.join((
                f'nvme-mi.control.status == {status:#x}',
                f'nvme-mi.response_to == {frame - 1}', 'nvme-mi.control.opcode == 0x03',
                '_ws.col.info contains "(Get State)"', '!nvme-mi.control.orphan_response',
                none, '!_ws.expert',
                f'nvme-mi.control.data == {data}' if data else '!nvme-mi.control.data'))))
        for frame, data in ((410, None), (411, '01:02:03')):
            frames.append((frame, ' && '.join((
                'nvme-mi.control.status == 0xe0', 'nvme-mi.control.orphan_response',
                '!nvme-mi.control.opcode', '!nvme-mi.response_to', none,
                f'nvme-mi.control.data == {data}' if data else '!nvme-mi.control.data'))))
        frames.append((413, ('_ws.short && nvme-mi.response_to == 412'
                             ' && nvme-mi.control.opcode == 0x03'
                             ' && !nvme-mi.control.truncated && !nvme-mi.control.excess_body')))
        assert_frames_match(self.FILE, at(self.SPAN, frames), two_pass=two_pass)

    def test_expert_censuses(self, fields_table, dissect_pdml):
        t = section(fields_table(self.FILE, (
            *(field for field, _ in self.EXPERTS), 'nvme-mi.mic_unverified',
            '_ws.col.info', 'nvme-mi.response_to',
            'nvme-mi.response_in', 'nvme-mi.response_is_mpr', 'nvme-mi.mprt',
            'nvme-mi.mpr.reserved', 'nvme-mi.resp_reserved', 'nvme-mi.mi.nmresp',
            'nvme-mi.admin.resp_reserved', 'nvme-mi.admin.cqe_dw0'), two_pass=True), self.SPAN)
        for field, frames in self.EXPERTS:
            assert list(column(t, field)) == sorted(set(frames)), field
        assert list(column(t, 'nvme-mi.mic_unverified')) == self.UNVERIFIED_MIC
        # An AEM is neither a request nor a response.
        assert {t[n]['_ws.col.info'] for n in (8, 9, 10, 11)} == {t[8]['_ws.col.info']}
        assert all(t[n][f] == '' for n in (8, 9, 10, 11) for f in (
            'nvme-mi.response_to', 'nvme-mi.response_in', 'nvme-mi.response_is_mpr'))
        assert not any(w in t[8]['_ws.col.info'].lower() for w in ('request', 'response'))
        # MPR, Generic Error, NMRESP and Admin layouts are disjoint (202).
        assert [[t[n][f] for f in ('nvme-mi.mpr.reserved', 'nvme-mi.resp_reserved',
                                   'nvme-mi.mi.nmresp', 'nvme-mi.admin.resp_reserved',
                                   'nvme-mi.admin.cqe_dw0')] for n in (75, 77, 79, 81)] == [
            [reserved, '', '', '', ''] for reserved in ('0x00', '0xa5', '0x00', '0xa5')]
        assert {req: t[req]['nvme-mi.response_in'] for req in (321, 325, 326, 332, 338, 344)} == {
            321: '324', 325: '330', 326: '331', 332: '337', 338: '343', 344: '348'}
        # Every expert accounted for.
        p = pdml_section(dissect_pdml(self.FILE, two_pass=True), self.SPAN)
        assert len(p.packets) == 413
        assert {n: len(p.experts(n)) for n in p.packets if p.experts(n)} == dict(
            Counter(n for _, frames in self.EXPERTS for n in frames))

    def test_reserved_values_and_anchors(self, dissect_pdml):
        p = pdml_section(dissect_pdml(self.FILE, two_pass=True), self.SPAN)
        for frame, (field, pos, size, value) in self.RUNS:
            node, = p.fields(frame, field)[:1]
            assert (int(node.get('pos')), int(node.get('size'))) == (pos, size), frame
            assert int(node.get('show'), 0) == value, frame
            # The zero twin keeps a real zero-valued item (CPAS 3h is an enum).
            if frame != 63:
                twin = 84 if frame == 349 else frame - (1 if frame in (13, 15, 17) else 2)
                zero, = p.fields(twin, field)[:1]
                assert int(zero.get('show'), 0) == 0, twin

    def test_header_flag_extents(self, dissect_pdml):
        p = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        for frame, fields in ((1, ['nvme-mi.mctp-ic']), (4, ['nvme-mi.mctp-ic']),
                              (9, ['nvme-mi.ror']), (10, ['nvme-mi.csi']),
                              (11, ['nvme-mi.ror', 'nvme-mi.csi'])):
            for field in fields:
                node = p.fields(frame, field)[0]
                assert (node.get('pos'), node.get('size')) == ('20', '4'), frame
                assert node.get('show') == ('False' if field == 'nvme-mi.mctp-ic'
                                            else 'True'), (frame, field)

    def test_control_excess_and_truncation_anchors(self, dissect_pdml):
        """The length expert sits on the excess; a short MPR's status carries its own."""
        p = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        for frame in (106, 109, 353, 359, 373, 375, 377, 379, 381):
            node = p.fields(frame, 'nvme-mi.control.excess')[0]
            assert (node.get('pos'), node.get('size'), node.get('value')) == ('28', '1', 'a5'), frame
            length = ('Control Primitive body is 5 bytes; expected exactly 4'
                      " (NVMe-MI 'Control Primitive Fields', 'Control Primitive Success"
                      " Response Fields')")
            assert [m.get('show') for m in node.findall(
                ".//field[@name='_ws.expert.message']")].count(length) == 1
            assert [m.get('show') for m in p.fields(frame, '_ws.expert.message')].count(
                length) == 1
            assert len(node.findall(".//field[@name='nvme-mi.control.excess_body']")) == 1
            assert [int(e.get('show')) for e in node.findall(
                ".//field[@name='_ws.expert.severity']")] == [0x600000]
            assert node.findall(".//field[@name='nvme-mi.control.truncated']") == []
            assert p.fields(frame, 'data.data') == []
        ctl = p[365].find(".//proto[@name='nvme-mi.control']")
        status = p.fields(365, 'nvme-mi.control.status')
        assert len(ctl.findall(".//field[@name='nvme-mi.control.truncated']")) == 1
        messages = [f.get('show') for f in ctl.findall(".//field[@name='_ws.expert.message']")]
        assert [(s.get('pos'), s.get('size'), s.get('show')) for s in status] == [
            ('24', '1', '0x01')]
        raw = ctl.find(".//field[@name='nvme-mi.control.data']")
        assert (raw.get('pos'), raw.get('size'), raw.get('value')) == ('24', '1', '01')
        assert 'Control Primitive payload truncated (less than 4 bytes)' in messages

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_no_mctp_dispatch_is_exempt_from_out_of_band_limits(
            self, cmd_tshark, capture_file, test_env, features, result_file, two_pass):
        """The named decoder's transport guard exempts frames with no MCTP dispatch."""
        if not features.have_lua:
            pytest.skip('The in-band exemption shim requires Lua')
        script = result_file('inband_exemption.lua')
        with open(script, 'w', encoding='utf-8') as output:
            output.write('''
local shim = Proto("inbandshim", "In-band exemption shim")
local mi = Dissector.get("nvme-mi")
function shim.dissector(tvb, pinfo, tree)
    mi:call(tvb, pinfo, tree)
end
DissectorTable.get("wtap_encap"):add(wtap.USER0, shim)
''')
        # The in-band frames are build_inband_pcapng's section, F616-F619.
        command = [
            cmd_tshark, '-X', f'lua_script:{script}', '-r',
            capture_file(self.FILE), '-Tfields',
            '-e', 'frame.number', '-e', 'nvme-mi.type',
            '-e', 'nvme-mi.message_too_large',
            *(['-2'] if two_pass else []),
        ]
        output = subprocess.check_output(command + ['-Y', 'frame.number in {616..619}'],
                                         encoding='utf-8', env=test_env)
        rows = [line.split('\t') for line in output.splitlines()]
        assert rows == [[str(frame), kind, '']
                        for frame, kind in ((616, '0x00000001'), (617, '0x00000001'),
                                            (618, '0x00000000'), (619, '0x00000000'))]
        selected = subprocess.check_output(command + ['-Y', 'frame.number in {618, 619}'],
                                           encoding='utf-8', env=test_env)
        assert [line.split('\t') for line in selected.splitlines()] == rows[2:]

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_mctp_dispatch_context_does_not_leak_to_a_later_named_decode(
            self, cmd_tshark, capture_file, test_env, features, result_file, two_pass):
        """The same frame can call NVMe-MI again after MCTP has returned;
        the later named decode stands on its own bytes."""
        if not features.have_lua:
            pytest.skip('The dispatch-context shim requires Lua')
        script = result_file('dispatch_context.lua')
        with open(script, 'w', encoding='utf-8') as output:
            output.write('''
local shim = Proto("postshim", "Post-dispatch context shim")
local called = ProtoField.bool("m5post.called", "Named decoder called after MCTP")
shim.fields = { called }
local mi = Dissector.get("nvme-mi")
function shim.dissector(tvb, pinfo, tree)
    if pinfo.number == FIRST or pinfo.number == SECOND or pinfo.number == THIRD then
        tree:add(shim, tvb()):add(called, true)
        local message = ByteArray.new("04 00 00 00 03 00 00 00"):tvb("Later Control request")
        mi:call(message, pinfo, tree)
    end
end
register_postdissector(shim)
'''.replace('FIRST', str(frame_in(self.SPAN, 114))).replace(
                'SECOND', str(frame_in(self.SPAN, 395))).replace(
                'THIRD', str(frame_in(self.SPAN, 396))))
        command = [cmd_tshark, '-X', f'lua_script:{script}', '-r', capture_file(self.FILE),
                   *(['-2'] if two_pass else [])]
        fields = ['-Tfields', '-e', 'frame.number', '-e', 'm5post.called',
                  '-e', 'nvme-mi.control.opcode']
        rows = [line.split('\t') for line in subprocess.check_output(
            command + fields, encoding='utf-8', env=test_env).splitlines()]
        expected = [[str(frame_in(self.SPAN, frame)), 'True', opcodes]
                    for frame, opcodes in ((114, '0x03,0x03'), (395, '0x03'),
                                           (396, '0x03,0x03'))]
        assert [rows[int(r[0]) - 1] for r in expected] == expected
        selected = subprocess.check_output(
            command + fields + ['-Y', to_capture(self.SPAN, 'frame.number in {114, 395, 396}')],
            encoding='utf-8', env=test_env)
        assert [line.split('\t') for line in selected.splitlines()] == expected


class TestNvmeMiReqResp:
    """MPR handling and concurrent CSI slots."""

    FILE = 'nvme-mi-types.pcapng'
    SECTION = 2

    def test_links(self, fields_table):
        t = section(fields_table(self.FILE, ('nvme-mi.response_in', 'nvme-mi.response_to',
                                     'nvme-mi.response_is_mpr', 'nvme-mi.response_time'),
                         two_pass=True), self.SPAN)
        # The MPR (F5) links to F3 but does not close it; F7 does.
        assert {n: (r['nvme-mi.response_in'], r['nvme-mi.response_to']) for n, r in t.items()} == {
            1: ('2', ''), 2: ('', '1'), 3: ('7', ''), 4: ('6', ''), 5: ('', '3'),
            6: ('', '4'), 7: ('', '3')}
        assert list(column(t, 'nvme-mi.response_is_mpr')) == [5]
        assert list(column(t, 'nvme-mi.response_time')) == [2, 5, 6, 7]

    def test_decode(self, assert_frames_match):
        # The Admin opcode is carried to both responses.
        assert_frames_match(self.FILE, at(self.SPAN, [
            (3, 'nvme-mi.admin.opcode == 0x06'),
            (5, 'nvme-mi.admin.opcode == 0x06'),
            (7, 'nvme-mi.admin.opcode == 0x06 && nvme-mi.admin.cqe_dw0 == 0xABCD1234'),
        ]))


class TestNvmeMiTypes:
    """Every message type and opcode, MPR, EIDs, MCTP tags, IC, MEB and CP fields."""

    FILE = 'nvme-mi-types.pcapng'
    SECTION = 1
    RESPONSE_IN = (
        (2, 3), (4, 5), (6, 7), (8, 9), (10, 11), (12, 13), (14, 15), (16, 17),
        (18, 21),       # MPR: the final, not the interim
        (22, 23), (24, 25), (28, 29),
        (30, 33), (31, 32),     # two conversations interleaved
        (34, 38),       # tag 0 Admin survives tag 1 traffic
        (35, 36), (39, 40), (41, 42), (43, 44), (45, 46), (47, 48), (49, 50), (51, 52),
        (53, 54), (55, 56), (57, 58), (59, 60),
        (61, 64), (62, 63),     # a CP does not displace the Admin command (4.2.1)
        (65, 66), (67, 68),
        (70, 72),       # a 1-byte MPR does not close the slot
        (73, 74), (75, 76), (77, 78), (79, 80), (81, 82), (83, 84), (85, 86), (87, 88),
        (89, 90), (91, 92), (93, 94), (95, 96), (97, 98), (99, 100),
        (101, 103),     # nor does a sliced MPR
        (104, 105), (106, 107))
    MPR_TO = ((19, 18), (20, 18), (37, 34), (71, 70), (102, 101))

    def test_decode(self, assert_frames_match):
        status_ok = 'nvme-mi.admin.status == 0x00'
        assert_frames_match(self.FILE, at(self.SPAN, [
            # An orphan is still an Admin response.
            (1, 'nvme-mi.type == 0x2 && nvme-mi.ror == 1 && ' + status_ok),
            *[(req, f'nvme-mi.mi.opcode == {op}') for op, req in enumerate((2, 4, 6, 8, 10))],
            *[(rsp, f'nvme-mi.mi.opcode == {op} && nvme-mi.mi.status == 0x00')
              for op, rsp in enumerate((3, 5, 7, 9, 11))],
            (12, 'nvme-mi.admin.opcode == 0x02 && nvme-mi.admin.ctrl-id == 0x0002'),
            (13, ('nvme-mi.admin.opcode == 0x02 && nvme-mi.admin.cqe_dw0 == 0xDEAD0002'
                  ' && nvme-mi.admin.cqe_dw1 == 0 && nvme-mi.admin.cqe_dw3 == 0 && ' + status_ok)),
            (14, ('nvme-mi.admin.opcode == 0x09 && nvme-mi.admin.ctrl-id == 0x0001'
                  ' && nvme-mi.admin.flags.dlenv == 1 && nvme-mi.admin.flags.dofstv == 0'
                  ' && nvme-mi.admin.flags.ish == 0')),
            (15, 'nvme-mi.admin.opcode == 0x09 && ' + status_ok),
            (16, ('nvme-mi.admin.opcode == 0x0a && nvme-mi.admin.ctrl-id == 0x0003'
                  ' && nvme-mi.admin.flags.dlenv == 1 && nvme-mi.admin.flags.dofstv == 1'
                  ' && nvme-mi.admin.dlen == 0x1000')),
            # Inline data goes through the shared NVMe decoder.
            (17, 'nvme-mi.admin.opcode == 0x0a && nvme.data && ' + status_ok),
            # A PCIe command and its response: the body is left as data.
            (24, 'nvme-mi.type == 4 && data'),
            (25, 'nvme-mi.response_to == 24 && data && !_ws.expert'),
            (26, 'nvme-mi.csi == 1 && nvme-mi.admin.opcode == 0x06'),
            (28, 'nvme-mi.admin.opcode == 0x06 && nvme.cmd.identify.dword10.cns == 0x01'),
            *[(n, status_ok) for n in (29, 32, 33)],
            (37, 'nvme-mi.admin.opcode == 0x06 && nvme-mi.admin.status == 0x01'),
            (38, 'nvme-mi.admin.opcode == 0x06 && nvme-mi.admin.cqe_dw0 == 0x12345678 && '
                 + status_ok),
            (40, 'nvme-mi.admin.cqe_dw0 == 0xCAFEBABE && ' + status_ok),
            # The MIC reads little-endian, as Appendix B prints its examples.
            (41, 'nvme-mi.mic == 0x3677d4d2'),
            (43, 'nvme-mi.mi.cdw0 == 0x12345678 && nvme-mi.mi.cdw1 == 0x9ABCDEF0'),
            # RENT 0 selects no entries.
            (46, 'nvme-mi.mi.response_data_length && !nvme-mi.mi.chds.ctlid'),
            (47, ('nvme-mi.admin.flags.dofstv == 1 && nvme-mi.admin.flags.dlenv == 0'
                  ' && nvme-mi.admin.doff == 0x2000')),
            (48, status_ok),
            # A 4-byte Admin response decodes, without CQE dwords.
            (50, (status_ok + ' && !nvme-mi.admin.cqe_dw0 && !nvme-mi.admin.cqe_dw1'
                  ' && !nvme-mi.admin.cqe_dw3')),
            (52, 'nvme-mi.admin.status == 0x03'),
            (54, 'nvme-mi.mi.status == 0x06'),
            (64, ('nvme-mi.admin.opcode == 0x02 && nvme-mi.admin.cqe_dw0 == 0xFEED0009 && '
                  + status_ok)),
            # F95's Reset is answered with an error; F99's Reserved one is
            # answered with Success, which section 5 does not forbid.
            (96, 'nvme-mi.mi.status == 0x02'),
            (100, 'nvme-mi.mi.status == 0x00'),
            (102, 'nvme-mi.mctp-ic == true && _ws.short && nvme-mi.mic_unverified'),
        ]))

    def test_censuses(self, fields_table, dissect_pdml):
        t = section(fields_table(self.FILE, (
            'nvme-mi', 'nvme-mi.type', 'nvme-mi.response_to', 'nvme-mi.response_is_mpr',
            'nvme-mi.response_time', 'nvme-mi.req_superseded', 'nvme-mi.mi.nmresp',
            'nvme-mi.mi.nmresp_reserved', 'nvme-mi.resp_reserved',
            'nvme-mi.mctp-ic', 'nvme-mi.mic',
            'nvme-mi.mic.status', 'frame.cap_len', 'frame.len',
            'nvme-mi.mprt', 'nvme-mi.duplicate_mpr', 'nvme-mi.mpr.reserved',
            'nvme-mi.admin.short_cqe', 'nvme-mi.meb', 'nvme-mi.ciap')), self.SPAN)

        def frames(field, value=None):
            return [n for n, v in column(t, field).items() if value is None or v == value]

        def where_int(field, value):
            return [n for n, v in column(t, field).items() if int(v, 0) == value]

        assert frames('nvme-mi') == list(range(1, 108))
        assert frames('nvme-mi.mctp-ic', 'True') == list(range(1, 108))
        assert where_int('nvme-mi.type', 0) == [22, 23, 35, 36, 57, 58, 59, 60, 62, 63, 65, 66]
        assert where_int('nvme-mi.type', 4) == [24, 25]
        # F1 is an orphan; every MPR and final links back (F102 is sliced
        # before the status byte, so it is not claimed as an MPR).
        assert {n: int(v) for n, v in column(t, 'nvme-mi.response_to').items()} == dict(
            sorted([(rsp, req) for req, rsp in self.RESPONSE_IN] + list(self.MPR_TO)))
        assert frames('nvme-mi.response_is_mpr') == [19, 20, 37, 71]
        assert frames('nvme-mi.response_time') == frames('nvme-mi.response_to')
        # A request finding its slot occupied by an unanswered one.
        assert frames('nvme-mi.req_superseded') == [30, 70, 73]
        # NMRESP exists on Success responses only (Figures 30/32/34); it is
        # Reserved where the command's section says so.  An error response
        # without PEL or MPRT has Reserved bytes 3:1.
        assert sorted(frames('nvme-mi.mi.nmresp') + frames('nvme-mi.mi.nmresp_reserved')) == [
            3, 5, 7, 9, 11, 21, 42, 44, 46, 56, 72, 74, 76, 78, 80, 82, 84, 86, 90, 92, 94,
            98, 100, 103, 105, 107]
        assert frames('nvme-mi.mi.nmresp_reserved') == [
            5, 9, 21, 42, 86, 92, 94, 98, 100, 103, 105]
        assert frames('nvme-mi.resp_reserved') == [52, 54, 96]
        # F69 has no room for a MIC; sliced F102 reports it Not present (3).
        with_mic = [n for n in range(1, 108) if n != 69]
        assert frames('nvme-mi.mic') == frames('nvme-mi.mic.status') == with_mic
        assert where_int('nvme-mi.mic.status', 1) == [n for n in with_mic if n != 102]
        assert where_int('nvme-mi.mic.status', 3) == [102]
        assert [n for n, r in t.items() if int(r['frame.cap_len']) < int(r['frame.len'])] == [102]
        # DOFSTV/DLENV are not used (Figure 139): a note, not an expert.
        p = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        for n in (14, 16, 47):
            assert p.field(n, 'nvme-mi.admin.flags')['showname'].endswith(
                '(DOFSTV/DLENV are not used; ignored by the Management Endpoint'
                ' in implementations compliant with NVMe-MI later than 1.1)'), n
        # MPRT is message bytes 7:6 on every MPR (Figure 34).
        assert frames('nvme-mi.mprt') == where_int('nvme-mi.mpr.reserved', 0) == [19, 20, 37]
        assert frames('nvme-mi.duplicate_mpr') == [20]
        assert frames('nvme-mi.admin.short_cqe') == [50]
        # MEB and CIAP share message byte 2 (Figure 20).
        assert frames('nvme-mi.meb', 'True') == [55]
        assert frames('nvme-mi.ciap', 'True') == [104]

    def test_response_in(self, fields_table):
        """Unanswered F26/F27/F69 and the orphan F1 have no response_in."""
        t = section(fields_table(self.FILE, ('nvme-mi.response_in',), two_pass=True), self.SPAN)
        assert {n: int(v) for n, v in column(t, 'nvme-mi.response_in').items()} == dict(
            self.RESPONSE_IN)

    def test_response_surplus_stays_visible(self, dissect_pdml):
        data = pdml_section(dissect_pdml(self.FILE), self.SPAN).field(46, 'nvme-mi.mi.response_surplus')
        assert (data['pos'], data['size'], data['value']) == ('28', '4', 'aabbccdd')
        assert data.get('hide') != 'yes'


class TestNvmeMiControlPrimitives:
    """Control Primitive request and response bodies."""

    FILE = 'nvme-mi-types.pcapng'
    SECTION = 1

    def test_decode(self, assert_frames_match):
        # The response carries the request's opcode and its own tag.
        exchanges = ((0x00, 0, 22, 23), (0x03, 1, 35, 36), (0x02, 2, 57, 58),
                     (0x04, 3, 59, 60), (0x03, 5, 62, 63))
        extra = {
            # Pause CPSR is 0003h (the obsolete must-be-1 bits).
            23: ' && nvme-mi.control.cpsr == 0x0003',
            35: ' && nvme-mi.control.cesf == 1',
            36: ' && nvme-mi.control.mes.nssro == 1 && nvme-mi.control.mes.ssta == 1',
            58: ' && nvme-mi.control.cpas == 2',
            59: ' && nvme-mi.control.rro == 5',
            60: ' && nvme-mi.control.rr == 1',
            # SSTA 2h (Process): the slot is busy with the Admin command.
            63: ' && nvme-mi.control.mes.ssta == 2',
        }
        frames = []
        for opcode, tag, req, rsp in exchanges:
            frames.append((req, f'nvme-mi.control.opcode == {opcode}'
                                f' && nvme-mi.control.tag == {tag}' + extra.get(req, '')))
            frames.append((rsp, f'nvme-mi.control.opcode == {opcode}'
                                f' && nvme-mi.control.tag == {tag}'
                                ' && nvme-mi.control.status == 0x00' + extra.get(rsp, '')))
        assert_frames_match(self.FILE, at(self.SPAN, frames))

    def test_nssro_registration(self, field_registry):
        """NVMe-MI 2.2 Figures 43-44: bit 14 survives CESF and ME Reset."""
        row = field_registry['nvme-mi.control.mes.nssro']
        assert row[1] == 'NVM Subsystem Reset Occurred (NSSRO)'
        assert (row[3], row[5], row[6]) == ('FT_BOOLEAN', '16', '0x4000')

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_nssro_value(self, dissect_pdml, two_pass):
        p = pdml_section(dissect_pdml(self.FILE, two_pass=two_pass), self.SPAN)
        assert p.values(36, 'nvme-mi.control.mes.nssro') == [1]
        assert p.shownames(36, 'nvme-mi.control.mes.nssro')[0].endswith(
            'NVM Subsystem Reset Occurred (NSSRO): Set')


class TestNvmeMiMiCommands:
    """MI command request dwords, NMRESP subfields and response data structures."""

    FILE = 'nvme-mi-types.pcapng'
    SECTION = 1

    def test_decode(self, assert_frames_match):
        assert_frames_match(self.FILE, at(self.SPAN, [
            (2, 'nvme-mi.mi.rds.dtyp == 0x01 && nvme-mi.mi.rds.portid == 0'),
            (3, ('nvme-mi.mi.rds.rdl == 32'
                 ' && nvme-mi.mi.port.prttyp == 1 && nvme-mi.mi.port.aems == 1'
                 ' && nvme-mi.mi.port.ciaps == 1 && nvme-mi.mi.port.mmtus == 64'
                 ' && nvme-mi.mi.port.mebs == 0x1000'
                 ' && nvme-mi.mi.port.pcie.mps == 0x1 && nvme-mi.mi.port.pcie.cls == 0x4'
                 ' && nvme-mi.mi.port.pcie.mlw == 8 && nvme-mi.mi.port.pcie.nlw == 4')),
            (4, 'nvme-mi.mi.nshsp.cs == 1'),
            # CCS 0211h: CTEMP | NSSRO | RDY.
            (5, ('nvme-mi.mi.nshds.nss.df == 1 && nvme-mi.mi.nshds.nss.rnr == 1'
                 ' && nvme-mi.mi.nshds.nss.p0la == 1 && nvme-mi.mi.nshds.nss.atf == 0'
                 ' && nvme-mi.mi.nshds.sw == 0xFF && nvme-mi.mi.nshds.ctemp == 45'
                 ' && nvme-mi.mi.nshds.pdlu == 5'
                 ' && nvme-mi.mi.hsf.ctemp == 1 && nvme-mi.mi.hsf.nssro == 1'
                 ' && nvme-mi.mi.hsf.rdy == 1 && nvme-mi.mi.hsf.cwarn == 0'
                 ' && nvme-mi.mi.nshds.sw_reserved == 1')),
            (6, ('nvme-mi.mi.chsp.all == 1 && nvme-mi.mi.chsp.maxrent == 1'
                 ' && nvme-mi.mi.chsp.sctlid == 0 && nvme-mi.mi.chsp.ccf == 1'
                 ' && nvme-mi.mi.chsp.csts == 1 && nvme-mi.mi.chsp.cwarn == 0')),
            # Two CHDS entries: CTLID 1 ready; CTLID 2 with FA|CFS|RDY and TAUT.
            (7, ('nvme-mi.mi.chsp.rent == 2'
                 ' && (nvme-mi.mi.chds.ctlid == 1 && nvme-mi.mi.chds.csts.rdy == 1'
                 ' && nvme-mi.mi.chds.ctemp == 310 && nvme-mi.mi.chds.pdlu == 3'
                 ' && nvme-mi.mi.chds.spare == 100)'
                 ' && (nvme-mi.mi.chds.ctlid == 2 && nvme-mi.mi.chds.csts.fa == 1'
                 ' && nvme-mi.mi.chds.csts.cfs == 1 && nvme-mi.mi.chds.cwarn.taut == 1)'
                 ' && (nvme-mi.mi.chds.chsc == 0x1002 && nvme-mi.mi.hsf.cwarn == 1'
                 ' && nvme-mi.mi.hsf.cfs == 1)'
                 ' && count(nvme-mi.mi.chds.cwarn_reserved) == 2'
                 ' && all nvme-mi.mi.chds.cwarn_reserved == 0')),
            (8, ('nvme-mi.mi.config.cid == 0x03 && nvme-mi.mi.config.portid == 1'
                 ' && nvme-mi.mi.config.mtus == 128')),
            (10, 'nvme-mi.mi.config.cid == 0x03 && nvme-mi.mi.config.portid == 1'),
            (11, 'nvme-mi.mi.config.mtus_cur == 64'),
            (73, 'nvme-mi.mi.rds.dtyp == 0x00'),
            (74, ('nvme-mi.mi.rds.rdl == 32'
                  ' && nvme-mi.mi.subsys.nump == 1 && nvme-mi.mi.subsys.mjr == 2'
                  ' && nvme-mi.mi.subsys.mnr == 1 && nvme-mi.mi.subsys.sre == 1')),
            (75, 'nvme-mi.mi.rds.dtyp == 0x02 && nvme-mi.mi.rds.ctrlid == 0'),
            (76, 'nvme-mi.mi.rds.rdl == 8 && nvme-mi.mi.ctrllist.numids == 3'),
            (77, ('nvme-mi.mi.rds.dtyp == 0x04 && nvme-mi.mi.rds.ctrlid == 1'
                  ' && nvme-mi.mi.rds.iocsi == 0')),
            # MI VPD Read (NMIMT 1, 05h) and Admin Device Self-test (2, 14h).
            (78, ('nvme-mi.mi.rds.rdl == 6 && nvme-mi.mi.cmdlist.numcmd == 2'
                  ' && (nvme-mi.mi.cmdlist.nmimt == 1 && nvme-mi.mi.cmdlist.opc == 0x05)'
                  ' && (nvme-mi.mi.cmdlist.nmimt == 2 && nvme-mi.mi.cmdlist.opc == 0x14)')),
            (79, 'nvme-mi.mi.rds.dtyp == 0x01 && nvme-mi.mi.rds.portid == 1'),
            (80, ('nvme-mi.mi.rds.rdl == 32'
                  ' && nvme-mi.mi.port.prttyp == 2 && nvme-mi.mi.port.cvpdaddr == 0x53'
                  ' && nvme-mi.mi.port.mvpdfreq == 0x2 && nvme-mi.mi.port.cmeaddr == 0x1D'
                  ' && nvme-mi.mi.port.i3csprt == 1 && nvme-mi.mi.port.msmbfreq == 0x2'
                  ' && nvme-mi.mi.port.nvmebms == 0')),
            (81, 'nvme-mi.mi.config.cid == 0x01 && nvme-mi.mi.config.portid == 0'),
            (82, 'nvme-mi.mi.config.sfreq_cur == 0x2'),
            (83, ('nvme-mi.mi.config.cid == 0x02 && nvme-mi.mi.config.hsc.cwarn == 1'
                  ' && nvme-mi.mi.config.hsc.ctemp == 1 && nvme-mi.mi.config.hsc.rdy == 1'
                  ' && nvme-mi.mi.config.hsc.spare == 0')),
            (85, 'nvme-mi.mi.config.cid == 0x01 && nvme-mi.mi.config.sfreq == 0x3'),
            # An error response has no NMRESP: bytes 3:1 are only the PEL.
            (88, ('nvme-mi.mi.status == 0x04 && nvme-mi.pel.bit'
                  ' && !nvme-mi.mi.nmresp && !nvme-mi.mi.config.sfreq_cur')),
            (89, 'nvme-mi.mi.rds.dtyp == 0x03 && nvme-mi.mi.rds.ctrlid == 1'),
            (90, ('nvme-mi.mi.rds.rdl == 32'
                  ' && nvme-mi.mi.ctrlinfo.portid == 0 && nvme-mi.mi.ctrlinfo.riv == 1'
                  ' && nvme-mi.mi.ctrlinfo.pri.bus == 0x12'
                  ' && nvme-mi.mi.ctrlinfo.pri.dev == 0x03'
                  ' && nvme-mi.mi.ctrlinfo.pri.fn == 0x01'
                  ' && nvme-mi.mi.ctrlinfo.pcivid == 0x144D'
                  ' && nvme-mi.mi.ctrlinfo.pcidid == 0xA808')),
            (91, ('nvme-mi.mi.opcode == 0x05 && nvme-mi.mi.vpd.dofst == 0'
                  ' && nvme-mi.mi.vpd.dlen == 8')),
            (92, 'nvme-mi.mi.vpd.data == 4e:56:4d:65:01:02:03:04'),
            (93, ('nvme-mi.mi.opcode == 0x06 && nvme-mi.mi.vpd.dofst == 0x10'
                  ' && nvme-mi.mi.vpd.dlen == 4 && nvme-mi.mi.vpd.data == de:ad:be:ef')),
            (95, 'nvme-mi.mi.opcode == 0x07 && nvme-mi.mi.reset.rsttyp == 0x00'),
            (97, 'nvme-mi.mi.opcode == 0x0c && nvme-mi.mi.shutdown.shdntyp == 0x01'),
            # Asynchronous Event Configuration Set: the AE Enable List (Figures
            # 91/92) and the Set-only NMD0 fields (Figure 90) replace the blob.
            (104, ('nvme-mi.mi.config.cid == 0x04'
                   ' && nvme-mi.mi.ae.numaee == 2 && nvme-mi.mi.ae.aeelhl == 5'
                   ' && (nvme-mi.mi.ae.aee == 1 && nvme-mi.mi.ae.id == 0x06)'
                   ' && (nvme-mi.mi.ae.aee == 0 && nvme-mi.mi.ae.id == 0x09)'
                   ' && !nvme-mi.mi.data'
                   ' && nvme-mi.mi.config.ae.encfa == 1 && nvme-mi.mi.config.ae.enpfa == 0'
                   ' && nvme-mi.mi.config.ae.envfa == 0 && nvme-mi.mi.config.ae.aemd == 5'
                   ' && nvme-mi.mi.config.ae.aerd == 10')),
            # The Get returns AEELVER (shall be 0h, Figure 81) and the AE
            # Supported List (Figures 82/83).
            (107, ('nvme-mi.mi.config.aeelver == 0'
                   ' && nvme-mi.mi.aes.numaes == 2 && nvme-mi.mi.aes.aeslhl == 5'
                   ' && (nvme-mi.mi.aes.aese == 1 && nvme-mi.mi.aes.id == 0x06)'
                   ' && (nvme-mi.mi.aes.aese == 0 && nvme-mi.mi.aes.id == 0x0b)'
                   ' && !nvme-mi.mi.data')),
        ]))

    def test_field_values(self, fields_table):
        t = section(fields_table(self.FILE, (
            '_ws.col.info', 'nvme-mi.mi.ctrllist.ctrlid', 'nvme-mi.mi.reserved_dtyp',
            'nvme-mi.mi.reserved_configid', 'nvme-mi.mi.reserved_value',
            'nvme-mi.mi.config.ae.aemd', 'nvme-mi.pel.bit', 'nvme-mi.pel.byte')), self.SPAN)
        assert t[76]['nvme-mi.mi.ctrllist.ctrlid'] == '0x0001,0x0002,0x0005'
        # Only the reserved selectors are flagged.
        assert list(column(t, 'nvme-mi.mi.reserved_dtyp')) == [43]
        assert list(column(t, 'nvme-mi.mi.reserved_configid')) == [87]
        assert list(column(t, 'nvme-mi.mi.reserved_value')) == [99]
        # The Set-only NMD0 fields are reserved on a Get (Figure 80).
        assert list(column(t, 'nvme-mi.mi.config.ae.aemd')) == [104]
        # F88 points at bit 2 of message byte 8, the reserved CONFIGID.
        assert (column(t, 'nvme-mi.pel.bit'), column(t, 'nvme-mi.pel.byte')) == (
            {88: '2'}, {88: '8'})
        for frame, text in (
                (2, 'Read NVMe-MI Data Structure: Port Information'),
                (3, 'Read NVMe-MI Data Structure: Port Information'),
                (10, 'Configuration Get: MCTP Transmission Unit Size'),
                (11, 'Configuration Get: MCTP Transmission Unit Size'),
                (91, 'VPD Read'), (93, 'VPD Write'), (95, 'Reset: Reset NVM Subsystem'),
                (97, 'Shutdown: Abrupt NVM Subsystem Shutdown')):
            assert text in t[frame]['_ws.col.info'], frame

    def test_mi22_labels(self, dissect_pdml):
        p = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        assert p.field(6, 'nvme-mi.mi.chsp.ctemp')['showname'].split(' = ', 1)[-1].startswith(
            'Select on Composite Temperature Change (CTEMP)')
        assert all(name.startswith('Controller Status (CS): ')
                   for name in p.shownames(7, 'nvme-mi.mi.chds.csts'))

    def test_reserved_structure_spans(self, dissect_pdml):
        p = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        for frame, sizes in ((3, [18]), (74, [28]), (80, [14]), (90, [4, 15])):
            assert [int(field.get('size')) for field in
                    p.fields(frame, 'nvme-mi.mi.ds_reserved')] == sizes, frame


class TestNvmeMiMalformed:
    """Malformed frames are flagged, the rest still decodes and slots stay intact."""

    FILE = 'nvme-mi-types.pcapng'
    SECTION = 1

    def test_decode(self, assert_frames_match):
        assert_frames_match(self.FILE, at(self.SPAN, [
            # No opcode is invented for an orphan.
            (1, 'nvme-mi.admin.orphan_response && !nvme-mi.admin.opcode'),
            (65, 'nvme-mi.control.truncated'),
            (66, 'nvme-mi.control.orphan_response && !nvme-mi.control.opcode'),
            # Truncated, but its opcode decodes and reaches the response.
            (67, 'nvme-mi.admin.truncated && nvme-mi.admin.opcode == 0x06'),
            (68, 'nvme-mi.admin.opcode == 0x06 && nvme-mi.admin.cqe_dw0 == 0x0BAD0001'),
            (69, 'nvme-mi.mic_truncated && nvme-mi.mi.opcode == 0x01 && !nvme-mi.mic'),
            (71, 'nvme-mi.mi.truncated && nvme-mi.mi.status == 0x01'),
            # Its MPR status is not captured, so it is not claimed.
            (102, '!nvme-mi.response_is_mpr'),
        ]))

    def test_censuses(self, fields_table):
        t = section(fields_table(self.FILE, ('_ws.malformed.expert', 'nvme-mi.control.tag_mismatch',
                                     'nvme-mi.reserved_type')), self.SPAN)
        # The truncation experts are PI_MALFORMED; nothing throws.
        assert column(t, '_ws.malformed.expert') == {}
        # F66's request was too short to record a tag to compare.
        assert column(t, 'nvme-mi.control.tag_mismatch') == {}
        assert column(t, 'nvme-mi.reserved_type') == {}


class TestNvmeMiAdminCommands:
    """Admin request CDW10-15 decoded by the shared NVMe SQE decoder."""

    FILE = 'nvme-mi-admin-identify.pcapng'
    SECTION = 2

    def test_decode(self, assert_frames_match):
        assert_frames_match(self.FILE, at(self.SPAN, [
            (1, ('nvme.cmd.identify.dword10.cns == 0x01 && nvme.cmd.identify.dword10.cntid == 0x0000'
                 ' && nvme-mi.admin.ctrl-id == 0x0001 && nvme-mi.admin.nsid == 0'
                 ' && nvme-mi.admin.mptr == 0')),
            (2, 'nvme.cmd.get_logpage.dword10.id == 0x02'),
            (3, 'nvme.cmd.set_features.dword10.fid == 0x02'),
            (4, 'nvme.cmd.get_features.dword10.fid == 0x04 && nvme-mi.admin.ctrl-id == 0x0004'),
            (5, ('nvme-mi.admin.opcode == 0x80 && nvme.cmd.format_nvm.dword10.lbafl == 1'
                 ' && nvme.cmd.format_nvm.dword10.mset == 1 && nvme.cmd.format_nvm.dword10.pi == 2'
                 ' && nvme.cmd.format_nvm.dword10.pil == 1 && nvme.cmd.format_nvm.dword10.ses == 1')),
            (6, ('nvme-mi.admin.opcode == 0x10 && nvme.cmd.fw_commit.dword10.fs == 1'
                 ' && nvme.cmd.fw_commit.dword10.ca == 3')),
            (7, ('nvme-mi.admin.opcode == 0x11 && nvme.cmd.fw_download.numd == 0xff'
                 ' && nvme.cmd.fw_download.ofst == 0x100')),
            (8, 'nvme-mi.admin.opcode == 0x14 && nvme.cmd.self_test.dword10.stc == 2'),
            (9, ('nvme-mi.admin.opcode == 0x24 && nvme.cmd.lockdown.dword10.scp == 0'
                 ' && nvme.cmd.lockdown.dword10.prhbt == 1 && nvme.cmd.lockdown.dword10.ifc == 2'
                 ' && nvme.cmd.lockdown.dword10.ofi == 9 && nvme.cmd.lockdown.dword14.uidx == 1')),
            (10, ('nvme-mi.admin.opcode == 0x84 && nvme.cmd.sanitize.dword10.sanact == 2'
                  ' && nvme.cmd.sanitize.dword10.ause == 1 && nvme.cmd.sanitize.dword10.ndas == 1'
                  ' && nvme.cmd.sanitize.ovrpat == 0xdeadbeef')),
            # No per-opcode decoder: the DW-labelled raw dword.
            (11, 'nvme-mi.admin.opcode == 0x08 && nvme.cmd.dword10 == 0x00000000'),
            (13, 'nvme-mi.admin.opcode == 0x1c'),
        ]))

    def test_field_values(self, fields_table, dissect_pdml):
        t = section(fields_table(self.FILE, ('nvme-mi.admin.opcode',
                                             'nvme-mi.admin.prohibited_opcode', '_ws.col.info')),
                    self.SPAN)
        assert list(column(t, 'nvme-mi.admin.opcode')) == list(range(1, 14))
        # Abort and Directive Send are Prohibited (Figure 137); 1Ch is not.
        assert list(column(t, 'nvme-mi.admin.prohibited_opcode')) == [11, 12]
        assert [t[1]['_ws.col.info'], t[2]['_ws.col.info']] == [
            'NVMe-MI NVMe Admin command Request (Identify) Controller',
            'NVMe-MI NVMe Admin command Request (Get Log Page) SMART/Health Information']
        # OWPASS 0h means 16 passes only for an Overwrite; F10 is Block Erase.
        owpass = dissect_pdml(self.FILE).field(frame_in(self.SPAN, 10),
                                               'nvme.cmd.sanitize.dword10.owpass')
        assert owpass['show'] == '0x00000000' and '16 passes' not in owpass['showname']


class TestNvmeMiAdminResponse:
    """Admin responses decoded by the shared CQE Dword 0 and status decoders."""

    FILE = 'nvme-mi-admin-identify.pcapng'
    SECTION = 3

    def test_decode(self, assert_frames_match):
        assert_frames_match(self.FILE, at(self.SPAN, [
            (1, ('nvme.cmd.get_features.dword11.tt.tmpsel == 0'
                 ' && nvme.cmd.set_features.dword11.tt.thpsel == 0')),
            (2, ('nvme-mi.response_to == 1 && nvme.cqe.dword0.get_features.tt == 0x0000014b'
                 ' && nvme.cqe.dword0.get_features.tt.tmpth == 0x14b'
                 # The Phase Tag pins the status word's offset.
                 ' && nvme.cqe.status.sct == 0 && nvme.cqe.status.sc == 0 && nvme.cqe.status.p == 1')),
            (4, ('nvme-mi.response_to == 3 && nvme.cqe.dword0.set_features.nq.nsqa == 3'
                 ' && nvme.cqe.dword0.set_features.ncqa == 7'
                 ' && nvme.cqe.status.sct == 0 && nvme.cqe.status.sc == 0 && nvme.cqe.status.p == 0')),
            # A failed completion's Dword 0 stays raw (SC 0Eh is a Dword 3
            # value, not a Dword 0 encoding).
            (6, ('nvme-mi.response_to == 5 && nvme.cqe.dword0 == 0x0000000e'
                 ' && !nvme.cqe.dword0.set_features.nq.nsqa && !nvme.cqe.dword0.set_features.ncqa'
                 ' && nvme.cqe.status.sct == 1 && nvme.cqe.status.sc == 0x0e'
                 ' && nvme.cqe.status.dnr == 1')),
            (8, ('nvme-mi.response_to == 7 && nvme.cqe.status.m == 1 && nvme.cqe.status.dnr == 1'
                 ' && nvme.cqe.dword0 == 0xcafebabe && nvme-mi.admin.cqe_dw0 == 0xcafebabe')),
            # SC 23h is what a locked-down drive returns (Figure 102).
            (10, ('nvme-mi.response_to == 9 && nvme.cqe.status.sct == 0'
                  ' && nvme.cqe.status.sc == 0x23 && nvme.cqe.status.dnr == 1')),
        ]))

    def test_censuses(self, fields_table):
        t = section(fields_table(self.FILE, ('nvme-mi.admin.opcode', 'nvme.cqe.status.error',
                                             '_ws.malformed.expert')), self.SPAN)
        assert list(column(t, 'nvme-mi.admin.opcode')) == list(range(1, 11))
        # Only SC/SCT make a failure; P, CRD, M and DNR do not.
        assert list(column(t, 'nvme.cqe.status.error')) == [6, 10]
        assert column(t, '_ws.malformed.expert') == {}


class TestNvmeMiTypeMismatch:
    """A response whose NMIMT differs from its slot's request is not its answer (Figure 28)."""

    FILE = 'nvme-mi-types.pcapng'
    SECTION = 4

    def test_decode(self, assert_frames_match):
        assert_frames_match(self.FILE, at(self.SPAN, [
            (2, ('nvme-mi.mi.orphan_response && !nvme-mi.mi.opcode'
                 ' && !nvme-mi.response_to && !nvme-mi.response_time')),
            (4, ('nvme-mi.admin.orphan_response && !nvme-mi.admin.opcode'
                 ' && !nvme-mi.response_to && !nvme-mi.response_time')),
            (5, ('nvme-mi.response_to == 1 && !nvme-mi.admin.orphan_response'
                 ' && nvme-mi.admin.opcode == 0x06')),
            (6, 'nvme-mi.response_to == 3 && !nvme-mi.mi.orphan_response'),
        ]))

    def test_links(self, fields_table):
        """The commit decision is stored per frame, so both passes agree."""
        t = section(fields_table(self.FILE, ('nvme-mi', 'nvme-mi.response_to', 'nvme-mi.response_in',
                                     'nvme-mi.status_absent'), two_pass=True), self.SPAN)
        assert list(column(t, 'nvme-mi')) == list(range(1, 7))
        assert column(t, 'nvme-mi.response_to') == {5: '1', 6: '3'}
        assert column(t, 'nvme-mi.response_in') == {1: '5', 3: '6'}
        # Every response carries its STATUS; only the type is wrong.
        assert column(t, 'nvme-mi.status_absent') == {}


class TestNvmeMiAdminLogpageWindowed:
    """Get Log Page responses windowed by LPO and DOFST together (MI 2.2 Figures 142/143)."""

    FILE = 'nvme-mi-admin-logpage.pcapng'
    SECTION = 2

    def test_windowed_fields(self, assert_frames_match):
        assert_frames_match(self.FILE, at(self.SPAN, [
            # SMART Data Units at DOFST 32 alone, then at LPO 16 + DOFST 16.
            (4, ('nvme.cmd.get_logpage.smart.dur == 10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f'
                 ' && nvme.cmd.get_logpage.smart.duw == 20:21:22:23:24:25:26:27:28:29:2a:2b:2c:2d:2e:2f')),
            (6, ('nvme.cmd.get_logpage.smart.dur == 40:41:42:43:44:45:46:47:48:49:4a:4b:4c:4d:4e:4f'
                 ' && nvme.cmd.get_logpage.smart.duw == 50:51:52:53:54:55:56:57:58:59:5a:5b:5c:5d:5e:5f')),
            (8, 'nvme.cmd.get_logpage.errinf.csi == 0x5756555453525150'),
            (10, 'nvme.cmd.get_logpage.fw_slot.frs.s1.ascii == "WIRESHK1"'),
            (14, 'nvme.cmd.get_logpage.changed_nslist == 0x00000042'),
            (16, 'nvme.cmd.get_logpage.egroup.dur == 60:61:62:63:64:65:66:67:68:69:6a:6b:6c:6d:6e:6f'),
            (18, 'nvme.cmd.get_logpage.egroup.rsvd2[0:4] == 00:01:02:03'),
            (20, 'nvme.cmd.get_logpage.pred_lat.dtwin_rt == 8608196880778817904'),
            (22, 'nvme.cmd.get_logpage.reserv_notif.lpt == 7'),
            # An ordinary Sanitize Status page: the trailing field renders, and
            # bytes 47:32 and SSTAT 10:9 are fields, not Reserved (Figure 302).
            (24, ('nvme.cmd.get_logpage.sanitize.rsvd == 90:91:92:93:94:95:96:97:98:99:9a:9b:9c:9d:9e:9f'
                  ' && nvme.cmd.get_logpage.sanitize.sstat.mvcncld == 1 && nvme.cmd.get_logpage.sanitize.sstat.nde == 1'
                  ' && nvme.cmd.get_logpage.sanitize.sstat.gde == 0 && nvme.cmd.get_logpage.sanitize.sstat.sos == 2'
                  ' && nvme.cmd.get_logpage.sanitize.etpvds == 90 && nvme.cmd.get_logpage.sanitize.ssi.sans == 5'
                  ' && nvme.cmd.get_logpage.sanitize.ssi.fails == 2 && nvme.cmd.get_logpage.sanitize.mnsoip == 4'
                  ' && nvme.cmd.get_logpage.sanitize.stnsid == 0x2a')),
            # IOCS0 sits at byte 1024 (Figure 213), not 1028.
            (34, 'nvme.cmd.get_logpage.cmd_and_eff.cseds == 0x5a5a0002'),
            (36, 'nvme.cmd.get_logpage.smart.ts.s1 == 300'),
            (46, 'nvme.cmd.get_logpage.selftest.res.poh == 3735928559'),
            (48, 'nvme.cmd.get_logpage.fw_slot.rsvd1[0:8] == 46:57:52:53:56:44:30:31'),
            (62, 'nvme.cmd.get_logpage.pred_lat_aggreg.nset == 0xbeef'),
            (68, 'nvme.cmd.get_logpage.fw_slot.afi == 0x02'),
            (70, 'nvme.cmd.get_logpage.ana.grp.id == 0x2a'),
            (72, ('nvme.cmd.get_logpage.cmd_and_eff.cseds == 0x1111ff01 && nvme.cmd.get_logpage.cmd_and_eff.cseds == 0x22220001'
                  ' && nvme.cmd.get_logpage.cmd_and_eff.cseds == 0x33330002'
                  ' && nvme.cmd.get_logpage.cmd_and_eff.cseds == 0x44440003')),
            (74, ('nvme.cmd.get_logpage.lba_status.nel.ne.neid == 0x2a && nvme.cmd.get_logpage.lba_status.nel.ne.nlrd == 2'
                  ' && nvme.cmd.get_logpage.lba_status.nel.ne.ratype == 0x10'
                  ' && nvme.cmd.get_logpage.lba_status.nel.ne.rd.rslba == 0x1111222233334444'
                  ' && nvme.cmd.get_logpage.lba_status.nel.ne.rd.rnlb == 0x55556666'
                  ' && nvme.cmd.get_logpage.lba_status.nel.ne.rd.rslba == 0x0123456789abcdef'
                  ' && nvme.cmd.get_logpage.lba_status.nel.ne.rd.rnlb == 0xbeef')),
            # NLSLNE ends the walk on F92, LSLPLEN on F94 (NVM CS 1.2 Figure 109).
            (92, 'nvme.cmd.get_logpage.lba_status.lslplen == 80 && nvme.cmd.get_logpage.lba_status.nlslne == 1'),
            (94, 'nvme.cmd.get_logpage.lba_status.lslplen == 48 && nvme.cmd.get_logpage.lba_status.nlslne == 2'),
            # LPO 10 decodes as if bits 1:0 were cleared (Figure 203).
            (128, 'nvme.cmd.get_logpage.fw_slot.frs.s1.ascii == "MASKED08"'),
        ]))

    def test_field_values_and_censuses(self, fields_table):
        ana = ('nvme.cmd.get_logpage.ana.grp.id', 'nvme.cmd.get_logpage.ana.grp.nsid', 'nvme.cmd.get_logpage.ana.grp.anas')
        cseds = ('nvme.cmd.get_logpage.cmd_and_eff.cseds.csupp',
                 'nvme.cmd.get_logpage.cmd_and_eff.cseds.rsvd0',
                 'nvme.cmd.get_logpage.cmd_and_eff.cseds.cser',
                 'nvme.cmd.get_logpage.cmd_and_eff.cseds.cse',
                 'nvme.cmd.get_logpage.cmd_and_eff.cseds.uss',
                 'nvme.cmd.get_logpage.cmd_and_eff.cseds.csp')
        fsp = ('nvme.cmd.get_logpage.feat_sup_and_eff.fids.fsp.nscpe',
               'nvme.cmd.get_logpage.feat_sup_and_eff.fids.fsp.cscpe',
               'nvme.cmd.get_logpage.feat_sup_and_eff.fids.fsp.nsetscpe',
               'nvme.cmd.get_logpage.feat_sup_and_eff.fids.fsp.egscpe',
               'nvme.cmd.get_logpage.feat_sup_and_eff.fids.fsp.dscpe',
               'nvme.cmd.get_logpage.feat_sup_and_eff.fids.fsp.nsscpe',
               'nvme.cmd.get_logpage.feat_sup_and_eff.fids.fsp.cdqscp',
               'nvme.cmd.get_logpage.feat_sup_and_eff.fids.fsp.ruhs',
               'nvme.cmd.get_logpage.feat_sup_and_eff.fids.fsp.rsvd')
        mi_csp = ('nvme.cmd.get_logpage.mi_cmd_sup_and_eff.cseds.csp.nscpe',
                  'nvme.cmd.get_logpage.mi_cmd_sup_and_eff.cseds.csp.cscpe',
                  'nvme.cmd.get_logpage.mi_cmd_sup_and_eff.cseds.csp.nsetscpe',
                  'nvme.cmd.get_logpage.mi_cmd_sup_and_eff.cseds.csp.egscpe',
                  'nvme.cmd.get_logpage.mi_cmd_sup_and_eff.cseds.csp.dscpe',
                  'nvme.cmd.get_logpage.mi_cmd_sup_and_eff.cseds.csp.nsscpe',
                  'nvme.cmd.get_logpage.mi_cmd_sup_and_eff.cseds.csp.rsvd')
        csp = ('nvme.cmd.get_logpage.cmd_and_eff.cseds.csp.nscpe',
               'nvme.cmd.get_logpage.cmd_and_eff.cseds.csp.cscpe',
               'nvme.cmd.get_logpage.cmd_and_eff.cseds.csp.nsetscpe',
               'nvme.cmd.get_logpage.cmd_and_eff.cseds.csp.egscpe',
               'nvme.cmd.get_logpage.cmd_and_eff.cseds.csp.dscpe',
               'nvme.cmd.get_logpage.cmd_and_eff.cseds.csp.nsscpe',
               'nvme.cmd.get_logpage.cmd_and_eff.cseds.csp.rsvd')
        lba = ('nvme.cmd.get_logpage.lba_status.nel.ne.neid',
               'nvme.cmd.get_logpage.lba_status.nel.ne.nlrd',
               'nvme.cmd.get_logpage.lba_status.nel.ne.ratype',
               'nvme.cmd.get_logpage.lba_status.nel.ne.rd.rslba',
               'nvme.cmd.get_logpage.lba_status.nel.ne.rd.rnlb')
        telemetry = ('nvme.cmd.get_logpage.telemetry.li', 'nvme.cmd.get_logpage.telemetry.ieee',
                     'nvme.cmd.get_logpage.telemetry.da1b',
                     'nvme.cmd.get_logpage.telemetry.da4b',
                     'nvme.cmd.get_logpage.telemetry.scope',
                     'nvme.cmd.get_logpage.telemetry.dgn', 'nvme.cmd.get_logpage.telemetry.ri')
        lockdown = ('nvme.cmd.get_logpage.cmd_feat_lockdown.cfila',
                    'nvme.cmd.get_logpage.cmd_feat_lockdown.cfila.ss',
                    'nvme.cmd.get_logpage.cmd_feat_lockdown.lngth',
                    'nvme.cmd.get_logpage.cmd_feat_lockdown.cfil',
                    'nvme.cmd.get_logpage.cmd_feat_lockdown.rsvd1')
        fields = (('nvme-mi', '_ws.malformed', '_ws.malformed.expert', '_ws.expert',
                   '_ws.expert.message', 'nvme.window_decode_skipped',
                   'nvme.cmd.get_logpage.window_misaligned',
                   'nvme.cmd.get_logpage.lpo_misaligned', 'nvme.cmd.get_logpage.lpo', 'nvme.cmd.get_logpage.dword14.ot',
                   'nvme.cmd.get_logpage.sanitize.rsvd', 'nvme.cmd.get_logpage.egroup.rsvd2', 'nvme.cmd.get_logpage.pred_lat.rsvd3',
                   'nvme.cmd.get_logpage.telemetry.db', 'nvme.cmd.get_logpage.supported.lids', 'nvme.cmd.get_logpage.changed_nslist',
                   'nvme.cmd.get_logpage.lba_status.lslplen', 'nvme.cmd.get_logpage.pred_lat_aggreg.ne',
                   'nvme.cmd.get_logpage.pred_lat_aggreg.nset',
                   'nvme.cmd.get_logpage.pred_lat_aggreg.fill', 'nvme.cmd.get_logpage.egroup_agreg.eg',
                   'nvme.cmd.get_logpage.egroup_agreg.fill')
                  + ana + cseds + fsp + mi_csp + csp + lba + telemetry + lockdown)
        t = section(fields_table(self.FILE, fields), self.SPAN)

        def row(frame, names):
            return [t[frame][n] for n in names]

        assert list(column(t, 'nvme-mi')) == list(range(1, 129))
        assert column(t, '_ws.malformed.expert') == {}
        # Short transfers that used to underflow `len` decode cleanly.
        assert not any(t[n]['_ws.malformed'] for n in (12, 18, 34, 38, 40, 42, 44))
        # Trailing fields stop at the 512-byte page end, never past it.
        for frame, name, size in ((50, 'nvme.cmd.get_logpage.sanitize.rsvd', 464), (52, 'nvme.cmd.get_logpage.egroup.rsvd2', 312),
                                  (54, 'nvme.cmd.get_logpage.pred_lat.rsvd3', 312)):
            value = t[frame][name]
            assert len(value) == 2 * size and value.endswith('cafebabe'), (frame, len(value))
        assert t[60]['nvme.cmd.get_logpage.telemetry.db'] == '5a' * 512
        # Windows that start mid-record place nothing and say so.
        assert list(column(t, 'nvme.cmd.get_logpage.window_misaligned')) == [64, 66, 98, 102, 104]
        assert (t[64]['nvme.cmd.get_logpage.supported.lids'], t[66]['nvme.cmd.get_logpage.changed_nslist']) == ('', '')
        assert [row(n, ('nvme.cmd.get_logpage.pred_lat_aggreg.nset', 'nvme.cmd.get_logpage.egroup_agreg.eg')) for n in
                (102, 104, 106, 108)] == [
            ['', ''], ['', ''], ['0xdead,0xbeef,0xf00d', ''], ['', '0xdead,0xbeef,0xf00d']]
        # An ANA window past the header has no NAGD: the count is inferred.
        assert note_frames(t, SKIP_ANA_COUNT) == [70, 76, 78]
        assert expert_frames(t, SKIP_ANA_COUNT) == []
        assert row(76, ana) == row(78, ana) == [
            '0x00000011,0x00000022', '0x00000101,0x00000202', '0x31,0x31']
        # A saturated offset cannot be placed in the LBA Status page (an
        # undecoded note, not a malformed one); DOFST 16 can.
        assert row(80, (lba[0], 'nvme.cmd.get_logpage.lba_status.lslplen', 'nvme.cmd.get_logpage.window_misaligned')) == [
            '', '', '']
        assert t[80]['nvme.window_decode_skipped'] == SKIP_RAW
        assert t[80]['_ws.expert.message'] == ''
        assert row(82, lba) == ['0x0000005b', '1', '0x10', '0x00000000deadbeef', '4660']
        # LPO 2**32 must not narrow to a first window.
        assert row(84, telemetry) == [''] * len(telemetry)
        # Event Aggregate pages: a 0000h inside NUMENT is an entry (F118);
        # without NUMENT the first 0000h ends the walk and the rest is fill.
        assert row(118, ('nvme.cmd.get_logpage.pred_lat_aggreg.ne', 'nvme.cmd.get_logpage.pred_lat_aggreg.nset')) == [
            '2', '0x0005,0x0000']
        assert [row(n, ('nvme.cmd.get_logpage.pred_lat_aggreg.ne', 'nvme.cmd.get_logpage.pred_lat_aggreg.nset',
                        'nvme.cmd.get_logpage.egroup_agreg.eg', '_ws.expert')) for n in (114, 116, 120)] == [
            ['1', '0x0005', '', ''], ['', '0x0005', '', ''], ['', '', '0x0007', '']]
        assert (t[116]['nvme.cmd.get_logpage.pred_lat_aggreg.fill'], t[120]['nvme.cmd.get_logpage.egroup_agreg.fill']) == (
            '000000000000', '000000000000')
        assert row(62, ('nvme.cmd.get_logpage.pred_lat_aggreg.nset', '_ws.expert',
                        'nvme.cmd.get_logpage.pred_lat_aggreg.fill')) == ['0xbeef', '', '000000adde']
        # Scope bits: Base 2.4 Figure 271 (FSP) has CDQSCP at bit 6 and RUHS
        # at bit 7, Figures 214/269 (CSP) reserve 11:6.
        assert row(110, fsp) == ['False,True,False'] * 6 + [
            'True,False,False', 'False,False,True', '0x00000000,0x00000000,0x0000000f']
        assert row(112, mi_csp) == ['False,True,False'] * 6 + [
            '0x00000001,0x00000000,0x0000003f']
        assert row(96, csp) == ['True,False'] * 6 + ['0x00000000,0x0000003f']
        # Figure 214: CSER 15:14 and CSP 31:20 are fields, Reserved is 13:05.
        assert row(96, cseds) == ['True,True', '0x00000000,0x00000155',
                                  '0x00000001,0x00000002', '0x00000002,0x00000000',
                                  'True,False', '0x0000003f,0x00000fc0']
        # Command and Feature Lockdown (Figure 271): a window past LNGTH is
        # not walked and says so (F126); the Reserved run stops at byte 511.
        # The ANA (F70-F78) and LBA Status (F80) notes above share the field.
        assert list(column(t, 'nvme.window_decode_skipped')) == [
            26, 56, 58, 70, 76, 78, 80, 126]
        assert list(column(t, 'nvme.cmd.get_logpage.cmd_feat_lockdown.cfil')) == [122, 124]
        assert row(122, lockdown[1:4]) == ['0x00', '8', '0x00,0x01,0x02,0x04,0x05,0x06,0x08,0x09']
        assert not t[124]['nvme.cmd.get_logpage.cmd_feat_lockdown.rsvd1'].endswith('deadbeefdeadbeef')
        assert row(126, (lockdown[0], lockdown[2], lockdown[3], lockdown[4],
                         'nvme.window_decode_skipped', 'nvme.cmd.get_logpage.window_misaligned',
                         '_ws.expert.message')) == [
            '', '', '', '', SKIP_RAW, '', '']
        # A misaligned LPO is flagged on the request (Figure 203).
        assert list(column(t, 'nvme.cmd.get_logpage.lpo_misaligned')) == [127]
        assert row(127, ('nvme.cmd.get_logpage.lpo', 'nvme.cmd.get_logpage.dword14.ot', '_ws.expert.message')) == [
            '10', 'False',
            ('Log Page Offset 10 is not dword aligned (bits 1:0 shall be cleared to 00b):'
            ' the controller may abort with Invalid Field in Command or operate as if the'
            ' offset were 8, which is how a response is decoded here')]

    def test_labels_extents_and_nesting(self, dissect_pdml):
        """Labels and item extents, visible only in PDML."""
        p = pdml_section(dissect_pdml(self.FILE), self.SPAN)

        def depths(frame, name):
            return field_depths(p[frame], name)

        entries = p.fields(100, 'nvme.cmd.get_logpage.errinf.entry')
        assert [f.get('showname') for f in entries] == [
            f'Error Information Log Entry {n}' for n in (2, 3, 4)]
        assert [f.get('size') for f in entries] == ['64', '64', '8']
        assert len(set(depths(100, 'nvme.cmd.get_logpage.errinf.entry'))) == 1
        assert p.shows(100, 'nvme.cmd.get_logpage.errinf.errcnt') == ['47874', '47875', '47876']
        assert p.shows(100, 'nvme.cmd.get_logpage.errinf.opc') == ['0x31', '0x32']
        assert p.field(24, 'nvme.cmd.get_logpage.sanitize.sstat.sos')['showname'].endswith(
            'Sanitize Operation Status (SOS): Sanitizing (0x2)')
        for frame, name, label in (
                (28, 'nvme.cmd.get_logpage.feat_sup_and_eff.fidx', 'FID 01h Supported and Effects'),
                (30, 'nvme.cmd.get_logpage.mi_cmd_sup_and_eff.cs', 'MI Command Opcode 01h Supported and Effects'),
                (32, 'nvme.cmd.get_logpage.supported.lids', 'Log Page Identifier 0x02 Supported (LIDS2)')):
            first = p.field(frame, name)
            assert (first['showname'], first['show']) == (label, '01:00:00:00'), frame
        assert p.shownames(72, 'nvme.cmd.get_logpage.cmd_and_eff.cs') == [
            'Admin Command Supported 255 (ACS255)', 'I/O Command Supported 0 (IOCS0)',
            'I/O Command Supported 1 (IOCS1)', 'I/O Command Supported 2 (IOCS2)']
        assert len(set(depths(72, 'nvme.cmd.get_logpage.cmd_and_eff.cs')[1:])) == 1
        assert p.shownames(88, 'nvme.cmd.get_logpage.cmd_and_eff.cs') == [
            'I/O Command Supported 254 (IOCS254)', 'I/O Command Supported 255 (IOCS255)']
        assert p.shownames(90, 'nvme.cmd.get_logpage.cmd_and_eff.cs') == p.shownames(98, 'nvme.cmd.get_logpage.cmd_and_eff.cs') == []
        assert len(p.fields(74, 'nvme.cmd.get_logpage.lba_status.nel.ne.rd')) == 2
        assert len(set(depths(74, 'nvme.cmd.get_logpage.lba_status.nel.ne.rd'))) == 1
        assert p.field(74, 'nvme.cmd.get_logpage.lba_status.nel.ne')['size'] == '48'
        assert len(p.fields(74, 'nvme.cmd.get_logpage.lba_status.nel')) == 1
        assert len(p.fields(92, 'nvme.cmd.get_logpage.lba_status.nel.ne')) == 1
        assert p.shows(92, 'nvme.cmd.get_logpage.lba_status.nel.ne.neid') == ['0x0000005b']
        assert len(p.fields(94, 'nvme.cmd.get_logpage.lba_status.nel.ne')) == 1
        assert p.field(94, 'nvme.cmd.get_logpage.lba_status.nel')['size'] == '32'
        assert p.field(46, 'nvme.cmd.get_logpage.selftest.res')['size'] == '28'
        assert p.field(46, 'nvme.cmd.get_logpage.selftest.res.status.type')['showname'].endswith(
            'Device Self-test Type: Entry is empty (0x0)')
        for frame in (84, 86):
            assert p.shownames(frame, 'nvme.cmd.get_logpage.telemetry.db') == [
                'Telemetry Data Block: Telemetry Host-Initiated data block 8388608',
                'Telemetry Data Block: Telemetry Host-Initiated data block 8388609'], frame
        assert p.field(96, 'nvme.cmd.get_logpage.cmd_and_eff.cseds.cser')['showname'].endswith(
            'Command Submission and Execution Relaxations (CSER): '
            'One concurrent Admin command per system (0x1)')
        assert 'UUID Selection Supported (USS)' in p.field(
            34, 'nvme.cmd.get_logpage.cmd_and_eff.cseds.uss')['showname']
        for frame in (122, 124):
            rsvd = p.field(frame, 'nvme.cmd.get_logpage.cmd_feat_lockdown.rsvd1')
            assert (rsvd['pos'], rsvd['size']) == ('52', '500'), frame

    def test_index_offsets_are_not_misaligned(self, tshark_fields):
        """Under Offset Type the LPO is an index, so no alignment applies."""
        assert tshark_fields(self.FILE, 'nvme.cmd.get_logpage.lpo & 3 && '
                                        'nvme.cmd.get_logpage.dword14.ot == 1').split() == [
            '27', '241', '243', '245', '247', '249', '251', '455', '457', '459']
        assert tshark_fields(self.FILE, 'nvme.cmd.get_logpage.lpo_misaligned').split() == [
            str(frame_in(self.SPAN, 127))]


class TestNvmeMiFeaturesWindowed:
    """Set/Get Features transfer decoders under a Data Offset."""

    FILE = 'nvme-mi-admin-features.pcapng'
    SECTION = 2

    def test_decode(self, assert_frames_match):
        assert_frames_match(self.FILE, at(self.SPAN, [
            (2, 'nvme.set_features.lbart.apst == 0x9796959493929190'),
            (4, 'nvme.get_features.tst == 0xa7a6a5a4a3a2a1a0'),
            (6, 'nvme.set_features.plmc.dtwinrt == 0xd7d6d5d4d3d2d1d0'),
            (10, 'nvme.set_features.plmc.rsvd1 == 11:22:33:44:55:66:77:88'),
            (12, 'nvme.set_features.hbs.rsvd == aa:bb:cc'),
            (18, ('nvme.set_features.hbs.acre == 0x01'
                  ' && nvme.set_features.hbs.etdas == 0x01'
                  ' && nvme.set_features.hbs.lbafee == 0x01'
                  ' && nvme.set_features.hbs.hdisns == 0x00'
                  ' && nvme.set_features.hbs.cdfe.cdf2e == 1'
                  ' && nvme.set_features.hbs.cdfe.cdf3e == 1'
                  ' && nvme.set_features.hbs.cdfe.cdf4e == 0')),
            (20, ('nvme.set_features.lbart.type == 0x02'
                  ' && nvme.set_features.lbart.slba == 0x1000'
                  ' && nvme.set_features.lbart.nlb == 0xff'
                  ' && nvme.set_features.lbart.type == 0x03'
                  ' && nvme.set_features.lbart.slba == 0x2000'
                  ' && nvme.set_features.lbart.nlb == 0x1ff')),
        ]))

    def test_field_values(self, fields_table):
        t = section(fields_table(self.FILE, (
            'nvme-mi', '_ws.malformed', '_ws.expert.message', 'nvme.set_features.plmc.rsvd1',
            'nvme.set_features.hbs.rsvd', 'nvme.set_features.hmd.nmed', 'nvme.data')), self.SPAN)
        assert list(column(t, 'nvme-mi')) == list(range(1, 23))
        # The short PLMC/HBS transfers and the rest decode without throwing.
        assert column(t, '_ws.malformed') == {}
        # The trailing run stops at the structure's 512-byte end (sentinel).
        for frame, name in ((14, 'nvme.set_features.plmc.rsvd1'), (16, 'nvme.set_features.hbs.rsvd')):
            assert len(t[frame][name]) == 32 * 2 and t[frame][name].endswith('cafebabe'), frame
        # NMED and the descriptor list start at byte 0, so a later window
        # cannot be realigned: raw bytes, no NMED.
        assert [t[22][n] for n in ('nvme.set_features.hmd.nmed', 'nvme.data')] == [
            '', '7562756e74752d32342e303400000000']
        assert t[22]['_ws.expert.message'] == ''

    def test_lbart_entries_span_their_own_bytes(self, dissect_pdml):
        """Each container is its own 64-byte entry, not a copy of entry 0's
        extent (an upstream defect only the item's pos shows)."""
        p = dissect_pdml(self.FILE)
        f20 = frame_in(self.SPAN, 20)
        entries = p.fields(f20, 'nvme.set_features.lbart')
        assert [e.get('size') for e in entries] == ['64', '64']
        assert int(entries[1].get('pos')) - int(entries[0].get('pos')) == 64
        assert len(set(field_depths(p[f20], 'nvme.set_features.lbart'))) == 1
        assert entries[0].get('value') != entries[1].get('value')
        assert entries[1].get('value').startswith('0301')


class TestNvmeMiNmimtError:
    """Error responses that echo a Reserved NMIMT (MI 2.2 Figures 28-32)."""

    FILE = 'nvme-mi-types.pcapng'
    SECTION = 6
    PAIRS = ((1, 9), (15, 17))
    # frame: (status, PEL byte, PEL bit)
    COMMON = ((5, (4, 1, 3)), (6, (4, 1, 3)), (8, (4, 1, 3)), (11, (4, 2, 1)),
              (13, (4, 1, 3)), (16, (4, 1, 3)), (19, (2, None, None)), (20, (2, None, None)))
    OPAQUE = frozenset({2, 3, 4, 7, 10, 12, 14, 18})
    EXPERTS = (('nvme-mi.reserved_type', OPAQUE), ('nvme-mi.mic_bad', {6, 12}))

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_common_errors_and_bounded_links(self, dissect_pdml, two_pass):
        p = pdml_section(dissect_pdml(self.FILE, two_pass=two_pass), self.SPAN)
        assert len(p.packets) == 20
        pairs, common = dict(self.PAIRS), dict(self.COMMON)
        replies = {response: request for request, response in self.PAIRS}
        for number, packet in p.packets.items():
            fields = {field.get('name'): field for field in packet.iter('field')}

            def value(name, fields=fields):
                if name not in fields:
                    return None
                show = fields[name].get('show')
                return str(int(show) - self.SPAN[0] + 1) if name in FRAME_LINKS else show

            expected_to = replies.get(number)
            expected_in = pairs.get(number) if two_pass else None
            assert value('nvme-mi.response_to') == (
                str(expected_to) if expected_to is not None else None), number
            assert value('nvme-mi.response_in') == (
                str(expected_in) if expected_in is not None else None), number
            assert value('nvme-mi.response_time') == (
                f'{number - expected_to}.000000000' if expected_to else None), number
            assert 'nvme-mi.req_superseded' not in fields, number
            assert 'nvme-mi.response_is_mpr' not in fields, number
            for name, frames in self.EXPERTS:
                assert (name in fields) == (number in frames), (number, name)
            assert ('nvme-mi.mic_unverified' in fields) == (number in {7, 19}), number
            assert len(packet.findall(".//field[@name='_ws.expert']")) == sum(
                number in frames for _, frames in self.EXPERTS), number
            assert ('nvme-mi.mic_unverified' in fields) == (number in {7, 19}), number
            if number not in (1, 9, 15, 17):
                for proto in ('nvme-mi.admin', 'nvme-mi.mi', 'nvme-mi.control'):
                    assert packet.find(f".//proto[@name='{proto}']") is None, number
            if number in common:
                status, byte, bit = common[number]
                assert int(value('nvme-mi.status'), 0) == status, number
                assert (fields['nvme-mi.status'].get('pos'),
                        fields['nvme-mi.status'].get('size')) == ('24', '1'), number
                assert value('nvme-mi.pel.byte') == (str(byte) if byte is not None else None)
                assert value('nvme-mi.pel.bit') == (str(bit) if bit is not None else None)
                assert 'nvme-mi.reserved_type' not in fields, number
                assert 'data.data' not in fields, number
                assert ('nvme-mi.resp_reserved' in fields) == (status == 2), number
                if status == 4:
                    assert (fields['nvme-mi.pel.bit'].get('pos'),
                            fields['nvme-mi.pel.bit'].get('size')) == ('25', '1'), number
                    assert (fields['nvme-mi.pel.byte'].get('pos'),
                            fields['nvme-mi.pel.byte'].get('size')) == ('26', '2'), number
            else:
                for name in ('nvme-mi.status', 'nvme-mi.pel.byte', 'nvme-mi.pel.bit'):
                    assert name not in fields, (number, name)
            if number in self.OPAQUE:
                assert 'nvme-mi.reserved_type' in fields and 'data.data' in fields, number
            if number in (8, 11, 20):
                assert '_ws.expert' not in fields, number
        assert p.field(9, 'nvme-mi.admin.opcode')['show'] == '0x06'

    def test_expert_frames(self, dissect_pdml):
        p = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        assert set(p.frames_with('_ws.expert')) == self.OPAQUE | {6}

    def test_without_mic_checking(self, fields_table):
        """With MIC checking off, F6's error decodes all the same."""
        t = section(fields_table(self.FILE, ('nvme-mi.type', 'nvme-mi.response_to',
                                     'nvme-mi.response_in', 'nvme-mi.status',
                                     'nvme-mi.reserved_type'),
                         prefs={'nvme-mi.check_mic': 'FALSE'}, two_pass=True), self.SPAN)
        assert [n for n, r in t.items() if int(r['nvme-mi.type'], 0) == 3
                and (r['nvme-mi.response_to'] or r['nvme-mi.response_in'])] == []
        assert column(t, 'nvme-mi.status') == {
            n: f'0x{status:02x}' for n, (status, _, _) in self.COMMON}
        assert list(column(t, 'nvme-mi.reserved_type')) == sorted(self.OPAQUE)


class TestNvmeMiReservedType:
    """Message types that own no Command Slot (Figure 20)."""

    FILE = 'nvme-mi-types.pcapng'
    SECTION = 3

    def test_decode(self, assert_frames_match):
        assert_frames_match(self.FILE, at(self.SPAN, [
            (2, ('nvme-mi.reserved_type && data.data && !nvme-mi.admin && !nvme-mi.mi'
                ' && !nvme-mi.control')),
            (3, 'nvme-mi.type == 0x5 && !nvme-mi.reserved_type'),
            (4, 'nvme-mi.admin.opcode == 0x06 && nvme-mi.admin.cqe_dw0 == 0x5EED0005'),
        ]))

    def test_slotless_types_leave_the_slot_alone(self, fields_table):
        t = section(fields_table(self.FILE, ('nvme-mi.reserved_type', '_ws.col.info',
                                     'nvme-mi.req_superseded', 'nvme-mi.response_in',
                                     'nvme-mi.response_to'), two_pass=True), self.SPAN)
        assert list(column(t, 'nvme-mi.reserved_type')) == [2]
        assert 'Asynchronous Event' in t[3]['_ws.col.info']
        assert 'Reserved' not in t[3]['_ws.col.info']
        assert column(t, 'nvme-mi.req_superseded') == {}
        assert {n: (r['nvme-mi.response_in'], r['nvme-mi.response_to']) for n, r in t.items()} == {
            1: ('4', ''), 2: ('', ''), 3: ('', ''), 4: ('', '1')}


class TestNvmeMiMctpBridge:
    """Conversation keys over MCTP-over-SMBus carry the physical pair, EIDs and tag."""

    FILE = 'nvme-mi-transactions.pcapng'
    SECTION = 3

    def test_decode(self, assert_frames_match):
        assert_frames_match(self.FILE, at(self.SPAN, [
            # Each response recovers its own endpoint's opcode.
            (3, 'nvme-mi.admin.opcode == 0x06 && nvme-mi.admin.cqe_dw0 == 0xAAAA000A'),
            (4, 'nvme-mi.admin.opcode == 0x02 && nvme-mi.admin.cqe_dw0 == 0xBBBB000B'),
            (8, 'nvme-mi.mi.opcode == 0x01 && !nvme-mi.mi.orphan_response'),
            (10, 'nvme-mi.mi.opcode == 0x04'),
            (11, '!nvme-mi.req_superseded && nvme-mi.mi.opcode == 0x01'),
            (12, 'nvme-mi.response_to == 11 && nvme-mi.mi.opcode == 0x01'),
        ]))

    def test_links(self, fields_table):
        """The null-destination retry drops the device EID only, never the physical pair."""
        t = section(fields_table(self.FILE, (
            'frame.protocols', 'nvme-mi.response_to', 'nvme-mi.response_in',
            'nvme-mi.req_superseded', 'nvme-mi.mi.orphan_response',
            'nvme-mi.admin.orphan_response'), two_pass=True), self.SPAN)
        assert 'mctp.smbus' in t[1]['frame.protocols']
        pairs = {1: 3, 2: 4, 5: 6, 7: 8, 9: 10, 11: 12}
        assert {n: int(v) for n, v in column(t, 'nvme-mi.response_to').items()} == {
            rsp: req for req, rsp in pairs.items()}
        assert {n: int(v) for n, v in column(t, 'nvme-mi.response_in').items()} == pairs
        for field in ('nvme-mi.req_superseded', 'nvme-mi.mi.orphan_response',
                      'nvme-mi.admin.orphan_response'):
            assert column(t, field) == {}, field


class TestNvmeMiPhysicalAddressPredicate:
    """SMBus physical-address fields as rendered."""

    #: build_mctp_bridge_pcapng's section of nvme-mi-transactions.pcapng.
    BRIDGE, BRIDGE_SPAN = 'nvme-mi-transactions.pcapng', (247, 258)
    #: The first SMBus frame of each capture with SMBus ingress.
    SMBUS_FRAMES = ((BRIDGE, BRIDGE_SPAN[0]), ('mctp-smbus-ingress.pcapng', 1),
                    ('mctp-ingress-scope.pcapng', 1))

    @pytest.mark.parametrize(('capture', 'frame'), SMBUS_FRAMES)
    def test_the_smbus_address_wire_fields_are_one_byte_wide(self, dissect_pdml, capture,
                                                             frame):
        p = dissect_pdml(capture)
        for field in ('mctp.smbus.src_addr', 'mctp.smbus.dst_addr'):
            assert p.field(frame, field)['size'] == '1', (capture, field)

    def test_bridge_addresses(self, fields_table):
        """Each request and response mirror the two addresses (the shifted 7-bit values)."""
        t = section(fields_table(self.BRIDGE, ('mctp.smbus.src_addr', 'mctp.smbus.dst_addr')),
                    self.BRIDGE_SPAN)
        assert [(r['mctp.smbus.src_addr'], r['mctp.smbus.dst_addr']) for r in t.values()] == [
            ('0x10', '0x3a'), ('0x10', '0x3a'), ('0x3a', '0x10'), ('0x3a', '0x10'),
            ('0x10', '0x3a'), ('0x3a', '0x10'), ('0x10', '0x3a'), ('0x3a', '0x10'),
            ('0x10', '0x3b'), ('0x3b', '0x10'), ('0x10', '0x3a'), ('0x3a', '0x10')]


class TestNvmeMiNullDestination:
    """Pairing of responses to Null Destination EID requests (DSP0236 Table 2)."""

    FILE = 'nvme-mi-transactions.pcapng'
    #: span: ({request: response}, {orphan response}, {response: its opcode})
    SPANS: ClassVar = {
        # F8/F9 are on another SLL2 interface index; without the index in the
        # key (SLL2 is not given to MCTP) they pair with each other.
        'sll2': ((288, 296), {1: 2, 3: 4, 5: 6, 8: 9}, {7},
                 {2: '0x01', 4: '0x04', 6: '0x01', 9: '0x01'}),
        'smbus': ((297, 304), {1: 2, 3: 4, 5: 6, 7: 8}, set(),
                  {2: '0x01', 4: '0x04', 6: '0x01', 8: '0x01'}),
        # NVMe-MI 2.2 section 4.2: a newer Command Message into an occupied
        # Command Slot implicitly aborts the older one, so the response
        # answers F4, not F3, and F3 is left unanswered.
        'smbus_unanswered': ((305, 311), {1: 2, 4: 5, 6: 7}, set(),
                             {2: '0x01', 5: '0x01', 7: '0x01'}),
        # The other way round: a stale null-destination request does not take
        # the response from a newer EID-addressed one.
        'smbus_stale_null': ((312, 314), {2: 3}, set(), {3: '0x04'}),
        'sll2_stale_null': ((315, 317), {2: 3}, set(), {3: '0x04'}),
        'sll2_version': ((318, 321), {1: 2, 3: 4}, set(),
                         {2: '0x00', 4: '0x01'}),
    }

    @pytest.mark.parametrize('name', SPANS)
    def test_links(self, fields_table, name):
        span, pairs, orphans, opcodes = self.SPANS[name]
        t = section(fields_table(self.FILE, (
            'nvme-mi.ror', 'nvme-mi.response_to', 'nvme-mi.response_in',
            'nvme-mi.req_superseded', 'nvme-mi.mi.orphan_response', 'nvme-mi.mi.opcode',
            '_ws.expert.message'), two_pass=True), span)
        assert {n: int(v) for n, v in column(t, 'nvme-mi.response_to').items()} == {
            rsp: req for req, rsp in pairs.items()}
        assert {n: int(v) for n, v in column(t, 'nvme-mi.response_in').items()} == pairs
        assert set(column(t, 'nvme-mi.mi.orphan_response')) == orphans
        assert column(t, 'nvme-mi.req_superseded') == {}
        responses = {n for n, row in t.items() if row['nvme-mi.ror'] == 'True'}
        assert {n: v for n, v in column(t, 'nvme-mi.mi.opcode').items()
                if n in responses} == opcodes
        # Nothing but the orphan responses' own expert.
        assert set(column(t, '_ws.expert.message')) == orphans


class TestNvmeMiReplayAlias:
    """A Replay to the Null Destination EID does not pair with the assigned EID's response."""

    FILE = 'nvme-mi-transactions.pcapng'
    #: span: (response_to, two-pass response_in, {replay: (replay_of,
    #: replay_request)}, orphans, {response: its opcode}, frames with experts)
    SPANS: ClassVar = {
        # F7 answers F6 and frees its slot for F8.
        'stale': ((322, 330), {2: 1, 4: 3, 7: 6, 9: 8}, {1: 2, 3: 4, 6: 7, 8: 9},
                  {5: (2, 3)}, set(), {2: '0x00', 5: '0x00', 7: '0x04', 9: '0x01'},
                  {5}),
        # F8 answers nothing.
        'abort': ((331, 338), {2: 1, 4: 3, 7: 6}, {1: 2, 3: 4, 6: 7},
                  {5: (2, 3)}, {8}, {2: '0x00', 5: '0x00'}, {5, 8}),
        # F7 is not F2's replay and answers nothing.
        'between': ((346, 352), {2: 1, 4: 3, 6: 5}, {1: 2, 3: 4, 5: 6},
                    {}, {7}, {2: '0x00', 4: '0x04'}, {7}),
    }

    @pytest.mark.parametrize('name', SPANS)
    def test_links(self, fields_table, name):
        span, response_to, response_in, replays, orphans, opcodes, experts = self.SPANS[name]
        t = section(fields_table(self.FILE, (
            'frame.protocols', 'nvme-mi.ror', 'nvme-mi.response_to', 'nvme-mi.response_in',
            'nvme-mi.replay_of', 'nvme-mi.replay_request', 'nvme-mi.req_superseded',
            'nvme-mi.mi.orphan_response', 'nvme-mi.mi.opcode', '_ws.expert.message'),
            two_pass=True), span)
        assert 'mctp.smbus' in t[1]['frame.protocols']
        assert {n: int(v) for n, v in column(t, 'nvme-mi.response_to').items()} == response_to
        assert {n: int(v) for n, v in column(t, 'nvme-mi.response_in').items()} == response_in
        assert {n: (int(t[n]['nvme-mi.replay_of']), int(v))
                for n, v in column(t, 'nvme-mi.replay_request').items()} == replays
        assert set(column(t, 'nvme-mi.replay_of')) == set(replays)
        assert column(t, 'nvme-mi.req_superseded') == {}
        assert set(column(t, 'nvme-mi.mi.orphan_response')) == orphans
        responses = {n for n, row in t.items() if row['nvme-mi.ror'] == 'True'}
        assert {n: v for n, v in column(t, 'nvme-mi.mi.opcode').items()
                if n in responses} == opcodes
        # The refused replay's bad MIC and the orphan's note, nothing else.
        assert set(column(t, '_ws.expert.message')) == experts


class TestNvmeMiReplayLostOriginal:
    """A Replay whose original response never reached NVMe-MI."""

    FILE = 'nvme-mi-transactions.pcapng'
    #: span: (response_to, two-pass response_in, {replay: (replay_of or None,
    #: replay_request)}, orphans, {response: its opcode}, frames with experts)
    SPANS: ClassVar = {
        # F8 answers F1 and frees its slot for F13; F12 replays F8.
        'transmit': ((353, 366), {4: 3, 6: 5, 8: 1, 10: 9, 12: 1, 14: 13},
                     {1: 8, 3: 4, 5: 6, 9: 10, 13: 14},
                     {8: (None, 5), 12: (8, 9)}, set(),
                     {8: '0x00', 12: '0x00', 14: '0x01'}, {8, 12}),
        # The suffix is kept raw, so no opcode, but it still answers F1.
        'partial': ((367, 375), {4: 3, 6: 5, 7: 1, 9: 8}, {1: 7, 3: 4, 5: 6, 8: 9},
                    {7: (None, 5)}, set(), {9: '0x01'}, {7}),
        # A Replay to the Null Destination EID is not answered from 1Eh.
        'between': ((386, 392), {4: 3, 6: 5}, {3: 4, 5: 6},
                    {}, {7}, {4: '0x04'}, {7}),
        # Neither another NMIMT nor another slot is the replay.
        'mismatch': ((393, 402), {4: 3, 8: 1, 10: 9}, {1: 8, 3: 4, 9: 10},
                     {8: (None, 3)}, {6},                      {8: '0x00', 10: '0x01'}, {5, 6, 8}),
        # F7 and F9 clear an expectation that holds no response.  No replay
        # was seen, so F1 keeps its slot and F9 supersedes it.
        'unanswered': ((403, 412), {4: 3, 6: 5, 8: 7, 10: 9}, {3: 4, 5: 6, 7: 8, 9: 10},
                       {}, set(), {10: '0x01'}, {9}),
    }

    @pytest.mark.parametrize('name', SPANS)
    def test_links(self, fields_table, name):
        span, response_to, response_in, replays, orphans, opcodes, experts = self.SPANS[name]
        t = section(fields_table(self.FILE, (
            'frame.protocols', 'nvme-mi.ror', 'nvme-mi.response_to', 'nvme-mi.response_in',
            'nvme-mi.replay_of', 'nvme-mi.replay_request', 'nvme-mi.req_superseded',
            'nvme-mi.mi.orphan_response', 'nvme-mi.mi.opcode', 'nvme-mi.mi.ctrllist.numids',
            'nvme-mi.partial_replay', '_ws.expert.message'), two_pass=True), span)
        assert 'mctp.smbus' in t[1]['frame.protocols']
        assert {n: int(v) for n, v in column(t, 'nvme-mi.response_to').items()} == response_to
        assert {n: int(v) for n, v in column(t, 'nvme-mi.response_in').items()} == response_in
        assert {n: (int(t[n]['nvme-mi.replay_of']) if t[n]['nvme-mi.replay_of'] else None,
                    int(v))
                for n, v in column(t, 'nvme-mi.replay_request').items()} == replays
        assert set(column(t, 'nvme-mi.req_superseded')) == (
            {9} if name == 'unanswered' else set())
        assert set(column(t, 'nvme-mi.mi.orphan_response')) == orphans
        responses = {n for n, row in t.items() if row['nvme-mi.ror'] == 'True'}
        assert {n: v for n, v in column(t, 'nvme-mi.mi.opcode').items()
                if n in responses} == opcodes
        # Every whole replay decodes as F1's Controller List.
        assert column(t, 'nvme-mi.mi.ctrllist.numids') == {
            n: '40' for n in replays if n in opcodes}
        assert set(column(t, 'nvme-mi.partial_replay')) == (
            {7} if name == 'partial' else set())
        # The partial replay's note, the orphans' notes, the superseded
        # note, nothing else.
        assert set(column(t, '_ws.expert.message')) == experts


class TestNvmeMiAdminIdentify:
    """Admin Identify responses decoded from their request's CNS and DOFST."""

    FILE = 'nvme-mi-admin-identify.pcapng'

    def test_decode(self, assert_frames_match):
        assert_frames_match(self.FILE, [(n, 'nvme-mi.admin.opcode == 0x06') for n in range(1, 29)])
        assert_frames_match(self.FILE, [
            # Figure 324: CDW11 15:00 is CNSSID, and CSI is 31:24.
            (1, ('nvme.cmd.identify.dword11.cnssid == 0'
                 ' && nvme.cmd.identify.dword11.csi == 0')),
            (2, ('nvme-mi.response_to == 1'
                 ' && nvme.cmd.identify.ctrl.vid == 0x144d'
                 ' && nvme.cmd.identify.ctrl.cntlid == 0x0007'
                 ' && nvme.cmd.identify.ctrl.sn contains "SERIAL01234567890123"'
                 ' && nvme.cmd.identify.ctrl.mn contains "WIRESHARK MODEL NUMBER"'
                 # Figure 329: PSD bytes 29:23 are fields, not Reserved.
                 ' && nvme.cmd.identify.ctrl.psds.psd.epfrt == 0'
                 ' && nvme.cmd.identify.ctrl.psds.psd.fqvt == 0'
                 ' && nvme.cmd.identify.ctrl.psds.psd.epfvt == 0'
                 ' && nvme.cmd.identify.ctrl.psds.psd.epfrts == 0'
                 ' && nvme.cmd.identify.ctrl.psds.psd.fqvts == 0'
                 ' && nvme.cmd.identify.ctrl.psds.psd.epfvts == 0'
                 ' && nvme.cmd.identify.ctrl.psds.psd.mbw == 0'
                 ' && nvme.cmd.identify.ctrl.psds.psd.mbws == 0'
                 # Figure 328 fields that sat inside oversized Reserved runs.
                 ' && nvme.cmd.identify.ctrl.bpcap == 0x06'
                 ' && nvme.cmd.identify.ctrl.bpcap.rpmbbpwps == 0x02'
                 ' && nvme.cmd.identify.ctrl.bpcap.sfbpwps == 1'
                 ' && nvme.cmd.identify.ctrl.nssl == 0x112233'
                 ' && nvme.cmd.identify.ctrl.plsi == 0x03'
                 ' && nvme.cmd.identify.ctrl.plsi.plsepf == 1'
                 ' && nvme.cmd.identify.ctrl.plsi.plsfq == 1'
                 ' && nvme.cmd.identify.ctrl.crcap == 0x03'
                 ' && nvme.cmd.identify.ctrl.crcap.rrsup == 1'
                 ' && nvme.cmd.identify.ctrl.crcap.rgidc == 1'
                 ' && nvme.cmd.identify.ctrl.ciu == 0x5a'
                 ' && nvme.cmd.identify.ctrl.cirn == 0x0123456789abcdef'
                 ' && nvme.cmd.identify.ctrl.did == 0xbeef'
                 ' && nvme.cmd.identify.ctrl.kpioc == 0x03'
                 ' && nvme.cmd.identify.ctrl.kpioc.kpios == 1'
                 ' && nvme.cmd.identify.ctrl.kpioc.kpiosc == 1'
                 ' && nvme.cmd.identify.ctrl.mptfawr == 0x37'
                 ' && nvme.cmd.identify.ctrl.megcap == '
                 '00:00:00:00:01:00:00:00:00:00:00:00:00:00:00:00'
                 ' && nvme.cmd.identify.ctrl.tmpthha.tmpthmh == 5'
                 ' && nvme.cmd.identify.ctrl.mupa.mups == 0x02'
                 ' && nvme.cmd.identify.ctrl.cqt == 625'
                 ' && nvme.cmd.identify.ctrl.cdpa.hs3 == 1'
                 ' && nvme.cmd.identify.ctrl.mup == 1234'
                 ' && nvme.cmd.identify.ctrl.ipmsr.srv == 100'
                 ' && nvme.cmd.identify.ctrl.ipmsr.srs == 0x0004'
                 ' && nvme.cmd.identify.ctrl.msmt == 5678'
                 ' && nvme.cmd.identify.ctrl.maxdna == '
                 '3f:5b:01:00:00:00:00:00:00:00:00:00:00:00:00:00'
                 ' && nvme.cmd.identify.ctrl.maxcna == 1025'
                 ' && nvme.cmd.identify.ctrl.oaqd == 3200'
                 ' && nvme.cmd.identify.ctrl.rhiri == 90'
                 ' && nvme.cmd.identify.ctrl.hirt == 30'
                 ' && nvme.cmd.identify.ctrl.cmmrtd == 257'
                 ' && nvme.cmd.identify.ctrl.nmmrtd == 514'
                 ' && nvme.cmd.identify.ctrl.minmrtg == 12'
                 ' && nvme.cmd.identify.ctrl.maxmrtg == 42'
                 ' && nvme.cmd.identify.ctrl.trattr == 0x07'
                 ' && nvme.cmd.identify.ctrl.trattr.thmcs == 1'
                 ' && nvme.cmd.identify.ctrl.trattr.tudcs == 1'
                 ' && nvme.cmd.identify.ctrl.trattr.mrtll == 1'
                 ' && nvme.cmd.identify.ctrl.mcudmq == 771'
                 ' && nvme.cmd.identify.ctrl.mnsudmq == 1028'
                 ' && nvme.cmd.identify.ctrl.mcmr == 1285'
                 ' && nvme.cmd.identify.ctrl.nmcmr == 1542'
                 ' && nvme.cmd.identify.ctrl.mcdqpc == 1799'
                 ' && nvme.cmd.identify.ctrl.nvmeof.dctype == 0x02'
                 ' && nvme.cmd.identify.ctrl.nvmeof.ccrl == 9')),
            # NVM CS 1.2 Figure 114 bytes 103:31, which were not decoded.
            (4, ('nvme-mi.response_to == 3'
                 ' && nvme.cmd.identify.ns.nsze == 0x100000'
                 ' && nvme.cmd.identify.ns.ncap == 0x80000'
                 ' && nvme.cmd.identify.ns.rescap == 0x1f'
                 ' && nvme.cmd.identify.ns.fpi == 0x87'
                 ' && nvme.cmd.identify.ns.dlfeat == 0x19'
                 ' && nvme.cmd.identify.ns.dlfeat.drb == 0x1'
                 ' && nvme.cmd.identify.ns.dlfeat.wzds == 1'
                 ' && nvme.cmd.identify.ns.dlfeat.gds == 1'
                 ' && nvme.cmd.identify.ns.nawun == 257'
                 ' && nvme.cmd.identify.ns.nawupf == 514'
                 ' && nvme.cmd.identify.ns.nacwu == 771'
                 ' && nvme.cmd.identify.ns.nabsn == 1028'
                 ' && nvme.cmd.identify.ns.nabo == 1285'
                 ' && nvme.cmd.identify.ns.nabspf == 1542'
                 ' && nvme.cmd.identify.ns.noiob == 1799'
                 ' && nvme.cmd.identify.ns.nvmcap == '
                 '00:00:00:00:80:00:00:00:00:00:00:00:00:00:00:00'
                 ' && nvme.cmd.identify.ns.npwg == 2056'
                 ' && nvme.cmd.identify.ns.npwa == 2313'
                 ' && nvme.cmd.identify.ns.npdg == 2570'
                 ' && nvme.cmd.identify.ns.npda == 2827'
                 ' && nvme.cmd.identify.ns.nows == 3084'
                 ' && nvme.cmd.identify.ns.mssrl == 3341'
                 ' && nvme.cmd.identify.ns.mcl == 0x00112233'
                 ' && nvme.cmd.identify.ns.msrc == 43'
                 ' && nvme.cmd.identify.ns.kpios == 0x03'
                 ' && nvme.cmd.identify.ns.kpios.kpioens == 1'
                 ' && nvme.cmd.identify.ns.kpios.kpiosns == 1'
                 ' && nvme.cmd.identify.ns.nulbaf == 47'
                 ' && nvme.cmd.identify.ns.kpiodaag == 0x00445566'
                 ' && nvme.cmd.identify.ns.anagrpid == 0x0000abcd'
                 ' && nvme.cmd.identify.ns.nsattr == 0x01'
                 ' && nvme.cmd.identify.ns.nvmsetid == 0x1357'
                 ' && nvme.cmd.identify.ns.endgid == 0x2468')),
            (6, ('nvme-mi.response_to == 5'
                 ' && nvme.cmd.identify.nslist.nsid == 1'
                 ' && nvme.cmd.identify.nslist.nsid == 2'
                 ' && nvme.cmd.identify.nslist.nsid == 7')),
            (8, ('nvme-mi.response_to == 7'
                 ' && nvme.cmd.identify.nsdesc.nidt == 0x1'
                 ' && nvme.cmd.identify.nsdesc.nidl == 8'
                 ' && nvme.cmd.identify.nsdesc.nidt == 0x2'
                 ' && nvme.cmd.identify.nsdesc.nidl == 16')),
            (10, ('nvme-mi.response_to == 9'
                  ' && nvme.cmd.identify.ctrl_list.num == 3'
                  ' && nvme.cmd.identify.ctrl_list.id == 1'
                  ' && nvme.cmd.identify.ctrl_list.id == 5')),
            # DOFST 24 places the Model Number; VID (offset 0) is not here.
            (12, ('nvme-mi.response_to == 11'
                  ' && nvme.cmd.identify.ctrl.mn contains "WIRESHARK MODEL NUMBER"'
                  ' && !nvme.cmd.identify.ctrl.vid')),
            # A 64-byte window ends with NVMCAP; NPWG (65:64) is past it.
            (14, ('nvme-mi.response_to == 13'
                  ' && nvme.cmd.identify.ns.nsze == 0x100000'
                  ' && nvme.cmd.identify.ns.ncap == 0x80000'
                  ' && nvme.cmd.identify.ns.nvmcap && !nvme.cmd.identify.ns.npwg')),
            # Base 2.3 Figure 335: every field, so a wrong offset or mask fails.
            (22, ('nvme.cmd.identify.cs_ind_ns.nsfeat.vwcnp == 1'
                  ' && nvme.cmd.identify.cs_ind_ns.nsfeat.rmedia == 1'
                  ' && nvme.cmd.identify.cs_ind_ns.nsfeat.uidreuse == 1'
                  ' && nvme.cmd.identify.cs_ind_ns.nmic.disns == 1'
                  ' && nvme.cmd.identify.cs_ind_ns.nmic.shrns == 1'
                  ' && nvme.cmd.identify.cs_ind_ns.rescap.ieks == 1'
                  ' && nvme.cmd.identify.cs_ind_ns.rescap.eaars == 0'
                  ' && nvme.cmd.identify.cs_ind_ns.rescap.wears == 1'
                  ' && nvme.cmd.identify.cs_ind_ns.rescap.eas == 1'
                  ' && nvme.cmd.identify.cs_ind_ns.rescap.ptpls == 1'
                  ' && nvme.cmd.identify.cs_ind_ns.fpi.fpis == 1'
                  ' && nvme.cmd.identify.cs_ind_ns.fpi.rfnvm == 25'
                  ' && nvme.cmd.identify.cs_ind_ns.anagrpid == 0x12345678'
                  ' && nvme.cmd.identify.cs_ind_ns.nsattr.cwp == 1'
                  ' && nvme.cmd.identify.cs_ind_ns.nvmsetid == 0xabcd'
                  ' && nvme.cmd.identify.cs_ind_ns.endgid == 0x1234'
                  ' && nvme.cmd.identify.cs_ind_ns.nstat.ioi == 3'
                  ' && nvme.cmd.identify.cs_ind_ns.nstat.nrdy == 1'
                  ' && nvme.cmd.identify.cs_ind_ns.kpios.kpiosns == 1'
                  ' && nvme.cmd.identify.cs_ind_ns.kpios.kpioens == 1'
                  ' && nvme.cmd.identify.cs_ind_ns.maxkt == 0x42'
                  ' && nvme.cmd.identify.cs_ind_ns.rgrpid == 0xcafebabe')),
        ])

    def test_field_values(self, fields_table):
        t = fields_table(self.FILE, (
            'nvme-mi.admin.opcode', '_ws.malformed.expert', '_ws.col.protocol',
            '_ws.expert.message',
            'nvme.identify.ns.lbaf.count_invalid', 'nvme.cmd.identify.ns.lbaf',
            'nvme.cmd.identify.ns.rsvd0', 'nvme.cmd.identify.ns.rsvd1',
            'nvme.cmd.identify.ns.rsvd2',
            'nvme.cmd.identify.ctrl.chsi', 'nvme.cmd.identify.ctrl.rsvd6',
            'nvme.cmd.identify.ctrl.rsvd1', 'nvme.cmd.identify.ctrl.rsvd2',
            'nvme.cmd.identify.ctrl.rsvd7', 'nvme.cmd.identify.ctrl.rsvd8',
            'nvme.cmd.identify.ctrl.rsvd4', 'nvme.cmd.identify.ctrl.rsvd9',
            'nvme.cmd.identify.ctrl.nvmeof.rsvd',
            'nvme.cmd.identify.dword11.csi', 'nvme.cmd.identify.dword11.rsvd',
            'nvme.cmd.identify.ctrl.nvmeof.fcatt', 'nvme.cmd.identify.ctrl.nvmeof.fcatt.dcm',
            'nvme.cmd.identify.ctrl.nvmeof.fcatt.nznsetids',
            'nvme.cmd.identify.ctrl.nvmeof.fcatt.rsvd',
            'nvme.cmd.identify.ctrl.mi.vwci', 'nvme.cmd.identify.ctrl.mi.vwci.vwcrv',
            'nvme.cmd.identify.ctrl.mi.vwci.vwcr'))

        def row(frame, *names):
            return [t[frame][n] for n in names]

        def nbytes(frame, *names):
            return [len(v) // 2 for v in row(frame, *names)]   # FT_BYTES is bare hex

        t = section(t, (1, 28))   # F29-F51 are the decode and response classes'
        assert list(column(t, 'nvme-mi.admin.opcode')) == list(range(1, 29))
        # F20's count expert is PI_MALFORMED; no frame throws.
        assert column(t, '_ws.malformed.expert') == {}
        assert t[2]['_ws.col.protocol'] == 'NVMe-MI'
        # Section 5.5 caps LBA Formats at 64: F20's 74 is flagged and the 64
        # that fit still decode.  F4 (2 + 47, 0's based NLBAF) has 50; MS is
        # the format index, so a wrong offset is a wrong number.
        assert list(column(t, 'nvme.identify.ns.lbaf.count_invalid')) == [20]
        assert len(t[20]['nvme.cmd.identify.ns.lbaf'].split(',')) == 64
        lbaf = t[4]['nvme.cmd.identify.ns.lbaf'].split(',')
        assert len(lbaf) == 50
        assert (lbaf[0], lbaf[15], lbaf[16], lbaf[49]) == (
            '0x00090000', '0x030c000f', '0x00090010', '0x010a0031')
        # Zero-filled Reserved runs: only their lengths show an off-by-N.
        assert nbytes(4, 'nvme.cmd.identify.ns.rsvd0', 'nvme.cmd.identify.ns.rsvd1',
                      'nvme.cmd.identify.ns.rsvd2') == [1, 4, 3]
        # Base 2.4 names byte 103 (CHSI), RMDCA (362) and 423:396.
        assert t[2]['nvme.cmd.identify.ctrl.chsi'] == '0x00'
        assert nbytes(2, 'nvme.cmd.identify.ctrl.rsvd6',
                      'nvme.cmd.identify.ctrl.rsvd1', 'nvme.cmd.identify.ctrl.rsvd2',
                      'nvme.cmd.identify.ctrl.rsvd7', 'nvme.cmd.identify.ctrl.rsvd8',
                      'nvme.cmd.identify.ctrl.rsvd4', 'nvme.cmd.identify.ctrl.rsvd9',
                      'nvme.cmd.identify.ctrl.nvmeof.rsvd') == [2, 96, 1, 5, 88, 1, 180, 240]
        assert row(17, 'nvme.cmd.identify.dword11.csi', 'nvme.cmd.identify.dword11.rsvd') == [
            '0x00000002', '0x00000000']
        # FCATT bit 1 is NZNSETIDS, not Reserved.
        assert row(2, 'nvme.cmd.identify.ctrl.nvmeof.fcatt',
                   'nvme.cmd.identify.ctrl.nvmeof.fcatt.dcm',
                   'nvme.cmd.identify.ctrl.nvmeof.fcatt.nznsetids',
                   'nvme.cmd.identify.ctrl.nvmeof.fcatt.rsvd') == ['0x03', 'True', 'True', '0x00']
        # VWCR is shown as sent, whether or not VWCRV is set (Figure 328 byte 254).
        assert [(n, r['nvme.cmd.identify.ctrl.mi.vwci.vwcrv'],
                 r['nvme.cmd.identify.ctrl.mi.vwci.vwcr'], r['_ws.expert.message'])
                for n, r in t.items() if r['nvme.cmd.identify.ctrl.mi.vwci']] == [
            (2, 'False', '0x00', ''), (16, 'False', '0x00', ''),
            (26, 'False', '0x45', ''), (28, 'True', '0x45', '')]

    def test_labels_and_extents(self, dissect_pdml):
        p = dissect_pdml(self.FILE)

        def label(frame, name):
            return p.field(frame, name)['showname']

        # CNSSID is CNS-specific, not "NVM Set Identifier" (CNS 01h, 06h).
        for frame in (1, 17):
            assert label(frame, 'nvme.cmd.identify.dword11.cnssid') == (
                '.... .... .... .... 0000 0000 0000 0000 = '
                'CNS Specific Identifier (CNSSID): 0x0000')
        assert label(17, 'nvme.cmd.identify.dword11.csi').endswith(
            'Command Set Identifier (CSI): Zoned Namespace Command Set (0x02)')
        # DSTO bit 0 set means only one self-test at a time.
        sdso = label(2, 'nvme.cmd.identify.ctrl.dsto.sdso')
        assert 'Single Device Self-test Operation (SDSO)' in sdso
        assert 'Concurrent Self-Tests' not in sdso
        # LBA Formats are 383:128 with Vendor Specific right after.
        lbafs = p.field(4, 'nvme.cmd.identify.ns.lbafs')
        assert lbafs['size'] == '256'
        assert int(p.field(4, 'nvme.cmd.identify.ns.vs')['pos']) == int(lbafs['pos']) + 256
        # The plural branch used to print a literal "%s"; AWUN/AWUPF are 0's
        # based.
        assert [label(16, n) for n in (
            'nvme.cmd.identify.ctrl.rtd3r', 'nvme.cmd.identify.ctrl.rtd3e',
            'nvme.cmd.identify.ctrl.awun', 'nvme.cmd.identify.ctrl.awupf')] == [
            'RTD3 Resume Latency (RTD3R): 1500000 (1500000 microseconds)',
            'RTD3 Entry Latency (RTD3E): 2500000 (2500000 microseconds)',
            'Atomic Write Unit Normal (AWUN): 2 logical blocks',
            'Atomic Write Unit Power Fail (AWUPF): 4 logical blocks']
        # NVM CS 1.2 Figure 116: MS 15:00, LBADS 23:16.
        assert [f.get('showname') for f in p.fields(24, 'nvme.cmd.identify.ns.lbaf')] == [
            'LBA Format: 0x00090000 (LBAF0: LBADS 9, MS 0, RP Best performance)',
            'LBA Format: 0x000c1000 (LBAF1: LBADS 12, MS 4096, RP Best performance)',
            'LBA Format: 0x03100008 (LBAF2: LBADS 16, MS 8, RP Degraded performance)']


class TestNvmeMiAdminLogPage:
    """Get Log Page (02h) responses decoded by the shared NVMe decoders."""

    FILE = 'nvme-mi-admin-logpage.pcapng'
    SECTION = 1

    def test_decode(self, assert_frames_match):
        assert_frames_match(self.FILE, at(self.SPAN, [
            (2, ('nvme-mi.response_to == 1 && nvme.cmd.get_logpage.smart.ct == 320'
                 ' && nvme.cmd.get_logpage.smart.lae == 5'
                 ' && nvme.cmd.get_logpage.smart.asc == 100')),
            (4, ('nvme-mi.response_to == 3 && nvme.cmd.get_logpage.fw_slot.afi.afs == 0x1'
                 ' && nvme.cmd.get_logpage.fw_slot.frs.s1.ascii == "FWREV100"')),
            # Figure 209: CSI (byte 30) is .cmdset, .csi is bytes 39:32.
            (6, ('nvme-mi.response_to == 5 && nvme.cmd.get_logpage.errinf.errcnt == 42'
                 ' && nvme.cmd.get_logpage.errinf.sqid == 3'
                 ' && nvme.cmd.get_logpage.errinf.cid == 0x00ab'
                 ' && nvme.cmd.get_logpage.errinf.cmdset == 0x02'
                 ' && nvme.cmd.get_logpage.errinf.opc == 0x09'
                 ' && nvme.cmd.get_logpage.errinf.trype == 0x03'
                 ' && nvme.cmd.get_logpage.errinf.csi == 0x1122334455667788'
                 ' && nvme.cmd.get_logpage.errinf.lpver == 0x01')),
            (8, ('nvme-mi.response_to == 7'
                 ' && nvme.cmd.get_logpage.supported.lidseds.lsupp == 1'
                 ' && nvme.cmd.get_logpage.supported.lidseds.ios == 1'
                 ' && nvme.cmd.get_logpage.supported.lidseds.lidsp == 0x1234')),
            # Figure 222: EGFEAT bit 0 and the Domain Identifier are fields.
            (10, ('nvme-mi.response_to == 9 && nvme.cmd.get_logpage.egroup.cw.ro == 1'
                  ' && nvme.cmd.get_logpage.egroup.cw.rd == 1'
                  ' && nvme.cmd.get_logpage.egroup.cw.asc == 0'
                  ' && nvme.cmd.get_logpage.egroup.as == 100'
                  ' && nvme.cmd.get_logpage.egroup.ast == 10'
                  ' && nvme.cmd.get_logpage.egroup.pu == 7'
                  ' && nvme.cmd.get_logpage.egroup.egfeat == 0x01'
                  ' && nvme.cmd.get_logpage.egroup.egfeat.egrmedia == 1'
                  ' && nvme.cmd.get_logpage.egroup.rsvd0 == 0x00'
                  ' && nvme.cmd.get_logpage.egroup.did == 0x1234')),
            (12, 'nvme-mi.response_to == 11'),
            (14, 'nvme-mi.response_to == 13'),
            (16, 'nvme-mi.response_to == 15'),
            (20, 'nvme-mi.response_to == 19'),
            (22, ('nvme-mi.response_to == 21'
                  ' && nvme.cmd.get_logpage.pred_lat.status.plmw == 1'
                  ' && nvme.cmd.get_logpage.pred_lat.etype.atde == 1'
                  ' && nvme.cmd.get_logpage.pred_lat.etype.atve == 1')),
            (24, 'nvme-mi.response_to == 23'),
            (26, 'nvme-mi.response_to == 25'),
            # DUR/DUW are billions of bytes (Figure 222), not SMART units.
            (42, ('nvme.cmd.get_logpage.egroup.dur == '
                  '03:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00'
                  ' && nvme.cmd.get_logpage.egroup.duw == '
                  '07:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00')),
        ]))

    def test_field_values(self, fields_table):
        t = section(fields_table(self.FILE, (
            'nvme-mi.admin.opcode', '_ws.malformed', '_ws.col.protocol', '_ws.expert.message',
            'nvme.window_decode_skipped',
            'nvme.cmd.get_logpage.dword10.id', 'nvme.cmd.get_logpage.dword10.lsp',
            'nvme.cmd.get_logpage.dword10.rae', 'nvme.cmd.get_logpage.dword10.lsp.act',
            'nvme.cmd.get_logpage.dword10.lsp.mqual',
            'nvme.cmd.get_logpage.smart.cw', 'nvme.cmd.get_logpage.smart.cw.sc',
            'nvme.cmd.get_logpage.smart.cw.mrro', 'nvme.cmd.get_logpage.smart.cw.ips',
            'nvme.cmd.get_logpage.smart.cw.rsvd', 'nvme.cmd.get_logpage.smart.ct',
            'nvme.cmd.get_logpage.errinf.pel', 'nvme.cmd.get_logpage.errinf.pel.bytee',
            'nvme.cmd.get_logpage.errinf.pel.bite', 'nvme.cmd.get_logpage.errinf.pel.rsvd',
            'nvme.cmd.get_logpage.ana.grp.id', 'nvme.cmd.get_logpage.ana.grp.anas',
            'nvme.cmd.get_logpage.ana.grp.anas.state', 'nvme.cmd.get_logpage.ana.grp.anas.rsvd',
            'nvme.cmd.get_logpage.egroup.rsvd1', 'nvme.cmd.get_logpage.egroup.rsvd2',
            'nvme.cmd.get_logpage.egroup.tegcap', 'nvme.cmd.get_logpage.egroup.uegcap',
            'nvme.cmd.get_logpage.dword14.uuid_index',
            'nvme.cmd.get_logpage.dword14.rsvd', 'nvme.cmd.get_logpage.dword14.ot',
            'nvme.cmd.get_logpage.dword14.csi',
            'nvme.cmd.get_logpage.lpo', 'nvme.cmd.dword13',
            'nvme.cmd.get_logpage.changed_nslist')), self.SPAN)

        def row(frame, *names):
            return [t[frame][n] for n in names]

        assert list(column(t, 'nvme-mi.admin.opcode')) == list(range(1, 43))
        assert column(t, '_ws.malformed') == {}
        assert t[2]['_ws.col.protocol'] == 'NVMe-MI'
        # LSP is CDW10 14:08 (Figure 201); RAE stays outside it.
        assert row(11, 'nvme.cmd.get_logpage.dword10.id', 'nvme.cmd.get_logpage.dword10.lsp',
                   'nvme.cmd.get_logpage.dword10.rae') == ['2', '0x0000007f', 'True']
        # ACT/MQUAL are LID 19h's; no request here is for 19h.
        lids = set(column(t, 'nvme.cmd.get_logpage.dword10.id').values())
        assert lids and '25' not in lids
        assert column(t, 'nvme.cmd.get_logpage.dword10.lsp.act') == column(
            t, 'nvme.cmd.get_logpage.dword10.lsp.mqual') == {}
        # SMART Critical Warning bit 6 is IPS (Figure 210).
        assert row(12, 'nvme.cmd.get_logpage.smart.cw', 'nvme.cmd.get_logpage.smart.cw.sc',
                   'nvme.cmd.get_logpage.smart.cw.mrro', 'nvme.cmd.get_logpage.smart.cw.ips',
                   'nvme.cmd.get_logpage.smart.cw.rsvd') == ['0xe1', 'True', 'True', 'True', '0x01']
        # PEL is 15:11 Reserved, 10:08 bit, 07:00 byte (Figure 209); two entries.
        assert row(14, 'nvme.cmd.get_logpage.errinf.pel', 'nvme.cmd.get_logpage.errinf.pel.bytee',
                   'nvme.cmd.get_logpage.errinf.pel.bite', 'nvme.cmd.get_logpage.errinf.pel.rsvd'
                   ) == ['0x852a,0xeeee', '42,238', '5,6', '16,29']
        # The ANASA container carries the whole byte (Figure 228).
        assert row(16, 'nvme.cmd.get_logpage.ana.grp.id', 'nvme.cmd.get_logpage.ana.grp.anas',
                   'nvme.cmd.get_logpage.ana.grp.anas.state', 'nvme.cmd.get_logpage.ana.grp.anas.rsvd'
                   ) == ['0x00000003', '0x31', '0x01', '0x03']
        # Figure 222: Reserved 31:08 and 511:192; TEGCAP/UEGCAP at 175:160/191:176.
        assert t[10]['nvme.cmd.get_logpage.egroup.rsvd1'] == ''.join(
            f'{b:02x}' for b in range(0xc0, 0xd8))
        assert t[10]['nvme.cmd.get_logpage.egroup.rsvd2'] == '00' * 320
        assert row(10, 'nvme.cmd.get_logpage.egroup.tegcap',
                   'nvme.cmd.get_logpage.egroup.uegcap') == [
            '8877665544332211' + '00' * 8, '11ffeeddccbbaa99' + '00' * 8]
        # CDW14 (Figure 205): UIDX 06:00, Reserved 22:07, OT 23, CSI 31:24.
        assert row(17, 'nvme.cmd.get_logpage.dword14.uuid_index',
                   'nvme.cmd.get_logpage.dword14.rsvd', 'nvme.cmd.get_logpage.dword14.ot',
                   'nvme.cmd.get_logpage.dword14.csi') == [
            '0x00000045', '0x00000000', 'True', '0x00000002']
        # With Offset Type the LPO is an index, so the response is not
        # decoded at a byte offset (F28 is F2's payload).
        assert [n for n, r in t.items() if r['nvme.cmd.get_logpage.dword14.ot'] == 'True'] == [17, 27]
        assert note_frames(t, SKIP_RAW) == [28]
        assert expert_frames(t, SKIP_RAW) == []
        assert (t[2]['nvme.cmd.get_logpage.smart.ct'], t[28]['nvme.cmd.get_logpage.smart.ct']) == (
            '320', '')
        # LPO is one 8-byte item over CDW12/13, with no CDW13 item on top.
        assert list(column(t, 'nvme.cmd.get_logpage.lpo')) == list(range(1, 42, 2))
        assert column(t, 'nvme.cmd.dword13') == {}
        # The FFFFFFFFh overflow sentinel is still the wire value.
        assert t[34]['nvme.cmd.get_logpage.changed_nslist'] == '0xffffffff'

    def test_labels_and_walks(self, dissect_pdml):
        p = pdml_section(dissect_pdml(self.FILE), self.SPAN)

        # Data units: a ceiling when reported, "not reported" when 0h.
        dur = p.field(42, 'nvme.cmd.get_logpage.egroup.dur')['showname']
        assert dur.endswith('(<= 3 GB)') and 'iB' not in dur
        assert '<= 7 GB' in p.field(42, 'nvme.cmd.get_logpage.egroup.duw')['showname']
        assert '<= 5 GB' in p.field(42, 'nvme.cmd.get_logpage.egroup.muw')['showname']
        for frame, name in ((10, 'nvme.cmd.get_logpage.egroup.dur'),
                            (10, 'nvme.cmd.get_logpage.egroup.duw'),
                            (10, 'nvme.cmd.get_logpage.egroup.muw'),
                            (2, 'nvme.cmd.get_logpage.smart.dur'),
                            (2, 'nvme.cmd.get_logpage.smart.duw')):
            label = p.field(frame, name)['showname']
            assert '(not reported)' in label and '<=' not in label, label
        # Labels that had been copied from the wrong field.
        for frame, name, label, sep in (
                (6, 'nvme.cmd.get_logpage.errinf.nsid', 'Namespace ID', ':'),
                (6, 'nvme.cmd.get_logpage.errinf.cmdset', 'Command Set Identifier (CSI)', ':'),
                (6, 'nvme.cmd.get_logpage.errinf.vsi', 'Vendor Specific Information Available', ':'),
                (6, 'nvme.cmd.get_logpage.errinf.trype', 'Transport Type', ':'),
                (6, 'nvme.cmd.get_logpage.errinf.tsi', 'Transport Type Specific Information', ':'),
                (6, 'nvme.cmd.get_logpage.errinf.rsvd1', 'Reserved', ':'),
                (10, 'nvme.cmd.get_logpage.egroup.mdie', 'Media and Data Integrity Errors', ' ('),
                (10, 'nvme.cmd.get_logpage.egroup.ele', 'Number of Error Information Log Entries',
                 ' (')):
            assert p.field(frame, name)['showname'].split(sep)[0] == label, name
        assert p.field(2, 'nvme.cmd.get_logpage.smart.lae')['showname'].startswith(
            'Percentage Used (PUSED):')
        assert p.field(2, 'nvme.cmd.get_logpage.smart.us')['showname'].startswith(
            'Unexpected Power Losses (UPL)')
        assert p.field(17, 'nvme.cmd.get_logpage.dword14.csi')['showname'].endswith(
            'Command Set Identifier (CSI): Zoned Namespace Command Set (0x02)')
        assert p.field(1, 'nvme.cmd.get_logpage.lpo')['size'] == '8'
        # Error Information is a list of 64-byte siblings; the Reserved run is
        # bytes 62:42 of each, and a partial entry stops at the transfer.
        entries = p.fields(6, 'nvme.cmd.get_logpage.errinf.entry')
        runs = p.fields(6, 'nvme.cmd.get_logpage.errinf.rsvd1')
        assert [e.get('size') for e in entries] == ['64', '64']
        assert int(entries[1].get('pos')) - int(entries[0].get('pos')) == 64
        assert [(r.get('size'), int(r.get('pos')) - int(e.get('pos'))) for e, r in
                zip(entries, runs)] == [('21', 42), ('21', 42)]
        assert [r.get('value') for r in runs] == [
            ''.join(f'{b:02x}' for b in range(0xa0, 0xb5)), 'ee' * 21]
        assert len(set(field_depths(p[6], 'nvme.cmd.get_logpage.errinf.entry'))) == 1
        assert set(field_depths(p[6], 'nvme.cmd.get_logpage.errinf.rsvd1')) == {
            field_depths(p[6], 'nvme.cmd.get_logpage.errinf.entry')[0] + 1}
        entries = p.fields(40, 'nvme.cmd.get_logpage.errinf.entry')
        assert [e.get('showname') for e in entries] == [
            f'Error Information Log Entry {n}' for n in range(4)]
        assert [e.get('size') for e in entries] == ['64', '64', '64', '40']
        assert len(set(field_depths(p[40], 'nvme.cmd.get_logpage.errinf.entry'))) == 1
        assert p.shows(40, 'nvme.cmd.get_logpage.errinf.errcnt') == [
            '43521', '43522', '43523', '43524']
        assert p.shows(40, 'nvme.cmd.get_logpage.errinf.cid') == [
            '0x0011', '0x0022', '0x0033', '0x0044']
        assert p.shows(40, 'nvme.cmd.get_logpage.errinf.opc') == ['0x21', '0x22', '0x23', '0x24']
        assert [len(p.fields(40, n)) for n in (
            'nvme.cmd.get_logpage.errinf.csi', 'nvme.cmd.get_logpage.errinf.tsi',
            'nvme.cmd.get_logpage.errinf.rsvd1', 'nvme.cmd.get_logpage.errinf.lpver')] == [4, 3, 3, 3]
        # Device Self-test has exactly 20 results, RDS1-RDS20 (Figure 215).
        assert p.shownames(30, 'nvme.cmd.get_logpage.selftest.res') == [
            f'Self-test Result Data Structure {i} (RDS{i})' for i in range(1, 21)]
        assert len(set(field_depths(p[30], 'nvme.cmd.get_logpage.selftest.res'))) == 1
        assert [int(s) for s in p.shows(30, 'nvme.cmd.get_logpage.selftest.res.poh')] == list(
            range(0xA000, 0xA014))
        # A Namespace List ends at its zero fill (Figure 139); FFFFFFFFh says
        # the list overflowed (5.2.12.1.5).
        assert p.shows(32, 'nvme.cmd.get_logpage.changed_nslist') == [
            '0x00000001', '0x0000002a', '0x00002000']
        assert p.field(34, 'nvme.cmd.get_logpage.changed_nslist')['showname'] == (
            'Changed Namespace: 0xffffffff (more than 1,024 namespaces changed)')
        # Event Aggregate walks stop at NUMENT (Figures 225/257).
        assert p.shows(36, 'nvme.cmd.get_logpage.pred_lat_aggreg.nset') == [
            '0x0005', '0x0000', '0x0009']
        assert p.shows(38, 'nvme.cmd.get_logpage.egroup_agreg.eg') == ['0x0007', '0x0003']

    def test_names_from_context(self, cmd_tshark, capture_file, test_env):
        """Lockdown values are named by Scope and Endurance Group / NVM Set pages by LSI."""
        out = subprocess.check_output([cmd_tshark, '-r', capture_file(self.FILE), '-V',
                                       '-Y', 'frame.number <= 42'],
                                      encoding='utf-8', env=test_env)
        for name in ('0x02 (Get Log Page)', '0x04 (Delete CQ)', '0x06 (Identify)',
                     '0x02 (Power Management)', '0x04 (Temperature Threshold)',
                     '0x06 (Volatile Write Cache)'):
            assert 'Command/Feature Identifier: ' + name in out, name
        for text in ('Endurance Group Information), Endurance Group 0',
                     'Endurance Group Information), Endurance Group 7',
                     'Predictable Latency Per NVM Set), NVM Set 3'):
            assert text in out, text


class TestNvmeMiAdminFeatures:
    """Admin Get/Set Features through the shared packet-nvme.c decoders."""

    FILE = 'nvme-mi-admin-features.pcapng'

    def test_decode(self, assert_frames_match):
        # Host Metadata: ET named via Figures 463/464, UTF-8 values.  DOFST
        # does not window Request Data (Figure 139), so F27 decodes as F5.
        set_hmd = ('nvme.set_features.hmd.nmed == 2'
                   ' && nvme.set_features.hmd.med.et == 0x01'
                   ' && nvme.set_features.hmd.med.et == 0x10'
                   ' && nvme.set_features.hmd.med.eval == "nvme9"'
                   ' && nvme.set_features.hmd.med.eval == "overtemp"')
        assert_frames_match(self.FILE, [
            (2, ('nvme-mi.response_to == 1 && nvme.set_features.hmd.nmed == 2'
                 ' && nvme.set_features.hmd.med.et == 0x01'
                 ' && nvme.set_features.hmd.med.et == 0x0a'
                 ' && nvme.set_features.hmd.med.elen == 5'
                 ' && nvme.set_features.hmd.med.elen == 11'
                 ' && nvme.set_features.hmd.med.eval == "nvme0"'
                 ' && nvme.set_features.hmd.med.eval == "Linux 6.1.0"')),
            (4, ('nvme-mi.response_to == 3 && nvme.set_features.hmd.nmed == 2'
                 ' && nvme.set_features.hmd.med.et == 0x01'
                 ' && nvme.set_features.hmd.med.et == 0x02'
                 ' && nvme.set_features.hmd.med.eval == "nvme0n1"'
                 ' && nvme.set_features.hmd.med.eval == "EFI NS1"')),
            (5, set_hmd + (' && nvme.cmd.set_features.dword11.hmd.ea == 0x2'
                           ' && nvme.cmd.set_features.dword10.rsvd == 0'
                           ' && nvme.cmd.set_features.dword14.rsvd == 0')),
            (6, 'nvme-mi.response_to == 5'),
            (7, ('nvme.cmd.get_features.dword11.tt.tmpsel == 0'
                 ' && nvme.cmd.set_features.dword11.tt.thpsel == 0')),
            (8, ('nvme-mi.response_to == 7'
                 ' && nvme.cqe.dword0.get_features.tt == 0x0000014b'
                 ' && nvme.cqe.dword0.get_features.tt.tmpth == 0x14b')),
            (10, 'nvme-mi.response_to == 9'),
            (12, 'nvme-mi.response_to == 11'),
            (27, set_hmd),
            # Figure 409: eleven bits that a 30:15 Reserved run swallowed; F32
            # has bits 14:08 in the opposite phase.
            (29, ('nvme.cmd.set_features.dword11.aec.nnsshdn == 1'
                  ' && nvme.cmd.set_features.dword11.aec.tthry == 1'
                  ' && nvme.cmd.set_features.dword11.aec.rassn == 1'
                  ' && nvme.cmd.set_features.dword11.aec.rgrp0 == 1'
                  ' && nvme.cmd.set_features.dword11.aec.ansan == 1'
                  ' && nvme.cmd.set_features.dword11.aec.ccrcn == 1'
                  ' && nvme.cmd.set_features.dword11.aec.lhcn == 1'
                  ' && nvme.cmd.set_features.dword11.aec.zdcn == 1'
                  ' && nvme.cmd.set_features.dword11.aec.pmdrlpcn == 1'
                  ' && nvme.cmd.set_features.dword11.aec.adlpcn == 1'
                  ' && nvme.cmd.set_features.dword11.aec.hdlpcn == 1'
                  ' && nvme.cmd.set_features.dword11.aec.smart == 0x5a'
                  ' && nvme.cmd.set_features.dword11.aec.ns == 1'
                  ' && nvme.cmd.set_features.dword11.aec.fwa == 0'
                  ' && nvme.cmd.set_features.dword11.aec.tel == 1'
                  ' && nvme.cmd.set_features.dword11.aec.ana == 0'
                  ' && nvme.cmd.set_features.dword11.aec.plat == 1'
                  ' && nvme.cmd.set_features.dword11.aec.lba == 0'
                  ' && nvme.cmd.set_features.dword11.aec.eg == 1'
                  ' && nvme.cmd.set_features.dword11.aec.disc == 1')),
            (32, ('nvme.cqe.dword0.get_features.aec.nnsshdn == 1'
                  ' && nvme.cqe.dword0.get_features.aec.tthry == 1'
                  ' && nvme.cqe.dword0.get_features.aec.rassn == 1'
                  ' && nvme.cqe.dword0.get_features.aec.rgrp0 == 1'
                  ' && nvme.cqe.dword0.get_features.aec.ansan == 1'
                  ' && nvme.cqe.dword0.get_features.aec.ccrcn == 1'
                  ' && nvme.cqe.dword0.get_features.aec.lhcn == 1'
                  ' && nvme.cqe.dword0.get_features.aec.zdcn == 1'
                  ' && nvme.cqe.dword0.get_features.aec.pmdrlpcn == 1'
                  ' && nvme.cqe.dword0.get_features.aec.adlpcn == 1'
                  ' && nvme.cqe.dword0.get_features.aec.hdlpcn == 1'
                  ' && nvme.cqe.dword0.get_features.aec.smart == 0xa5'
                  ' && nvme.cqe.dword0.get_features.aec.ns == 0'
                  ' && nvme.cqe.dword0.get_features.aec.fwa == 1'
                  ' && nvme.cqe.dword0.get_features.aec.tel == 0'
                  ' && nvme.cqe.dword0.get_features.aec.ana == 1'
                  ' && nvme.cqe.dword0.get_features.aec.plat == 0'
                  ' && nvme.cqe.dword0.get_features.aec.lba == 1'
                  ' && nvme.cqe.dword0.get_features.aec.eg == 0'
                  ' && nvme.cqe.dword0.get_features.aec.disc == 1')),
            # Figure 425 in the completion: Reserved is 31:03.
            (38, 'nvme.cqe.dword0.get_features.plmw.rsvd == 0x14b6d8fa'),
            # Select 011b returns supported capabilities (Figure 199), whatever
            # the FID; Select 000b keeps the Arbitration layout.
            (39, 'nvme.cmd.get_features.dword10.sel == 3'),
            (40, ('nvme.cqe.dword0.get_features.caps.svbl == 1'
                  ' && nvme.cqe.dword0.get_features.caps.nsspec == 1'
                  ' && nvme.cqe.dword0.get_features.caps.chang == 1'
                  ' && nvme.cqe.dword0.get_features.caps.rsvd == 0x0b492704')),
            (41, 'nvme.cmd.get_features.dword10.sel == 0'),
            (42, ('nvme.cqe.dword0.get_features.arb.ab == 7'
                  ' && nvme.cqe.dword0.get_features.arb.hpw == 0x5a'
                  ' && not nvme.cqe.dword0.get_features.caps.svbl')),
        ])

    def test_field_values(self, fields_table):
        t = fields_table(self.FILE, (
            'nvme-mi.admin.opcode', '_ws.malformed', '_ws.col.protocol', '_ws.expert.message',
            'nvme.cmd.set_features.dword11.hctm', 'nvme.cmd.set_features.dword11.hctm.tmt1',
            'nvme.cmd.set_features.dword11.hctm.tmt2', 'nvme.cqe.dword0.get_features.hctm',
            'nvme.cqe.dword0.get_features.hctm.tmt1', 'nvme.cqe.dword0.get_features.hctm.tmt2',
            'nvme.cmd.set_features.dword11.irqv.iv', 'nvme.cmd.set_features.dword11.irqv.cd',
            'nvme.cqe.dword0.get_features.irqv.iv', 'nvme.cqe.dword0.get_features.irqv.cd',
            'nvme-mi.admin.invalid_dlen', 'nvme-mi.admin.short_response',
            'nvme-mi.admin.invalid_dofst', 'nvme.set_features.tst', 'nvme.get_features.tst',
            'nvme.cqe.dword0.get_features.arb.ab'))
        t = section(t, (1, 44))   # F45-F66 are TestNvmeMiFeaturesWindowed's

        def row(frame, *names):
            return [t[frame][n] for n in names]

        assert list(column(t, 'nvme-mi.admin.opcode')) == list(range(1, 45))
        assert column(t, '_ws.malformed') == {}
        assert t[2]['_ws.col.protocol'] == 'NVMe-MI'
        # Figure 417: TMT1 31:16, TMT2 15:00.
        assert row(9, 'nvme.cmd.set_features.dword11.hctm',
                   'nvme.cmd.set_features.dword11.hctm.tmt1',
                   'nvme.cmd.set_features.dword11.hctm.tmt2') == row(
            12, 'nvme.cqe.dword0.get_features.hctm', 'nvme.cqe.dword0.get_features.hctm.tmt1',
            'nvme.cqe.dword0.get_features.hctm.tmt2') == [
            '0x0154015e', '0x00000154', '0x0000015e']
        # Figure 475: IV 15:00, CD bit 16.
        assert row(23, 'nvme.cmd.set_features.dword11.irqv.iv',
                   'nvme.cmd.set_features.dword11.irqv.cd') == row(
            26, 'nvme.cqe.dword0.get_features.irqv.iv',
            'nvme.cqe.dword0.get_features.irqv.cd') == ['0x00001234', 'False']
        # Features DLEN/DOFST are checked against the FID's transfer and size
        # (MI 2.2 Figure 139, Base 2.4 Figure 466).
        assert list(column(t, 'nvme-mi.admin.invalid_dlen')) == [
            5, 7, 9, 11, 13, 17, 19, 21, 23, 25, 27, 29, 31, 33, 37, 39, 41]
        assert t[27]['_ws.expert.message'].endswith(
            'Data Length 128 does not equal the 4096 bytes of NVMe Request Data'
            ' the Set Features FID requires')
        assert t[33]['_ws.expert.message'] == (
            'Data Offset 0 plus Data Length 4096 exceeds the 8-byte Get Features'
            ' FID and SEL completion data')
        assert list(column(t, 'nvme-mi.admin.invalid_dofst')) == [27]
        # F15's LBA Range Type window is 4096 bytes; F16 returns none.
        assert list(column(t, 'nvme-mi.admin.short_response')) == [16]
        # Timestamp layouts are per direction (Figures 414/415).
        assert list(column(t, 'nvme.set_features.tst')) == [35]
        assert list(column(t, 'nvme.get_features.tst')) == [34]
        assert list(column(t, 'nvme.cqe.dword0.get_features.arb.ab')) == [42]

    def test_labels(self, dissect_pdml):
        p = dissect_pdml(self.FILE)

        def label(frame, name):
            return p.field(frame, name)['showname']

        # Temperature Threshold: a completion returns only the selected
        # threshold (5.2.26.1.3); 31:16 is named, not called Reserved, and
        # Figure 407's request fields are not rendered over it.
        tt = [(f.get('name'), f.get('show')) for f in p[44].iter('field')
              if f.get('name', '').startswith('nvme.cqe.dword0.get_features.tt')]
        assert tt == [('nvme.cqe.dword0.get_features.tt', '0x0012014b'),
                      ('nvme.cqe.dword0.get_features.tt.tmpth', '0x0000014b'),
                      ('nvme.cqe.dword0.get_features.tt.undefined', '0x00000012')]
        assert label(44, 'nvme.cqe.dword0.get_features.tt.undefined').endswith(
            'Not defined for a Get Features completion: 0x0012')
        assert [p.field(43, n)['show'] for n in (
            'nvme.cmd.get_features.dword11.tt.tmpsel',
            'nvme.cmd.set_features.dword11.tt.thpsel')] == ['0x00000002', '0x00000001']
        # Group members carry their own names, not the container's.
        for frame, name, tail in (
                (13, 'nvme.cmd.set_features.dword11.lbart.lbarn',
                 'Number of LBA Ranges (NUM): 0x5 (6)'),
                (16, 'nvme.cqe.dword0.get_features.lbart.lbarn',
                 'Number of LBA Ranges (NUM): 0x7 (8)'),
                (17, 'nvme.cmd.set_features.dword11.nswp.wps',
                 'Write Protection State (WPS): Write Protect Until Power Cycle (0x2)'),
                (20, 'nvme.cqe.dword0.get_features.nswp.wps',
                 'Write Protection State (WPS): Permanent Write Protect (0x3)'),
                (21, 'nvme.cmd.set_features.dword12.plmw.ws',
                 'Window Select (WSEL): Deterministic Window (0x1)'),
                (29, 'nvme.cmd.set_features.dword11.aec.hdlpcn',
                 'Host Discovery Log Page Change Notification (HDLPCN): True')):
            assert label(frame, name).endswith(tail), (frame, name, label(frame, name))
        # Full shownames pin each mask through the bit-position prefix.
        assert {(f, n): label(f, n) for f, n in (
            (29, 'nvme.cmd.set_features.dword11.aec.rsvd'),
            (32, 'nvme.cqe.dword0.get_features.aec.rsvd'),
            (29, 'nvme.cmd.set_features.dword11.aec.rlccn'),
            (32, 'nvme.cqe.dword0.get_features.aec.rlccn'),
            (29, 'nvme.cmd.set_features.dword11.aec.nnsshdn'),
            (29, 'nvme.cmd.set_features.dword11.aec.tthry'),
            (29, 'nvme.cmd.set_features.dword11.aec.rassn'),
            (29, 'nvme.cmd.set_features.dword11.aec.rgrp0'),
            (29, 'nvme.cmd.set_features.dword11.aec.hdlpcn'),
            (34, 'nvme.get_features.tst.tstmpo'),
            (34, 'nvme.get_features.tst.sync'),
            (34, 'nvme.get_features.tst.tstmps_rsvd'),
            (34, 'nvme.get_features.tst.rsvd'),
            (35, 'nvme.set_features.tst.rsvd'),
            (38, 'nvme.cqe.dword0.get_features.plmw.ws'),
            (38, 'nvme.cqe.dword0.get_features.plmw.rsvd'))} == {
            # Base 2.4 gives bit 22 to RLCCN; 26:23 stay Reserved.
            (29, 'nvme.cmd.set_features.dword11.aec.rsvd'):
                '.... .101 0... .... .... .... .... .... = Reserved: 0xa',
            (32, 'nvme.cqe.dword0.get_features.aec.rsvd'):
                '.... .010 1... .... .... .... .... .... = Reserved: 0x5',
            (29, 'nvme.cmd.set_features.dword11.aec.rlccn'):
                ('.... .... .1.. .... .... .... .... .... = '
                 'Rate Limiting Configuration Change Notices (RLCCN): True'),
            (32, 'nvme.cqe.dword0.get_features.aec.rlccn'):
                ('.... .... .0.. .... .... .... .... .... = '
                 'Rate Limiting Configuration Change Notices (RLCCN): False'),
            # Bits 18:15 are named for the event, so they say what is sent.
            (29, 'nvme.cmd.set_features.dword11.aec.nnsshdn'):
                ('.... .... .... .... 1... .... .... .... = '
                 'Normal NVM Subsystem Shutdown (NNSSHDN): Event sent to the host'),
            (29, 'nvme.cmd.set_features.dword11.aec.tthry'):
                ('.... .... .... ...1 .... .... .... .... = Temperature Threshold'
                 ' Hysteresis Recovery (TTHRY): Event sent to the host'),
            (29, 'nvme.cmd.set_features.dword11.aec.rassn'):
                ('.... .... .... ..1. .... .... .... .... = '
                 'Reachability Association (RASSN): Event sent to the host'),
            (29, 'nvme.cmd.set_features.dword11.aec.rgrp0'):
                ('.... .... .... .1.. .... .... .... .... = '
                 'Reachability Group (RGRP0): Event sent to the host'),
            (29, 'nvme.cmd.set_features.dword11.aec.hdlpcn'):
                ('.1.. .... .... .... .... .... .... .... = Host Discovery Log'
                 ' Page Change Notification (HDLPCN): True'),
            # Get Timestamp byte 06 is TSTMPS (Figure 415); Set reserves 07:06.
            (34, 'nvme.get_features.tst.tstmpo'):
                ('.... .... .... 001. .... .... .... .... .... .... .... .... '
                 '.... .... .... .... = Timestamp Origin (TSTMPO): Initialized '
                 'with a Timestamp value using a Set Features command (0x1)'),
            (34, 'nvme.get_features.tst.sync'):
                ('.... .... .... ...1 .... .... .... .... .... .... .... .... '
                 '.... .... .... .... = Synch (SYNC): May have stopped counting '
                 'during vendor specific intervals'),
            (34, 'nvme.get_features.tst.tstmps_rsvd'):
                ('.... .... 0101 .... .... .... .... .... .... .... .... .... '
                 '.... .... .... .... = Reserved: 0x5'),
            (34, 'nvme.get_features.tst.rsvd'):
                ('1010 0101 .... .... .... .... .... .... .... .... .... .... '
                 '.... .... .... .... = Reserved: 0xa5'),
            (35, 'nvme.set_features.tst.rsvd'):
                ('1010 0101 0101 0011 .... .... .... .... .... .... .... .... '
                 '.... .... .... .... = Reserved: 0xa553'),
            # Figure 425 (Command Dword 12), not Figure 424, in the completion.
            (38, 'nvme.cqe.dword0.get_features.plmw.ws'):
                ('.... .... .... .... .... .... .... .010 = '
                 'Window Select (WSEL): Non-Deterministic Window (0x2)'),
            (38, 'nvme.cqe.dword0.get_features.plmw.rsvd'):
                '1010 0101 1011 0110 1100 0111 1101 0... = Reserved: 0x14b6d8fa'}
        for frame, name in ((29, 'nvme.cmd.set_features.dword11.aec.ns'),
                            (32, 'nvme.cqe.dword0.get_features.aec.ns')):
            assert 'Attached Namespace Attribute Notices (NAN)' in label(frame, name)
        assert label(35, 'nvme.set_features.tst.ms').endswith(
            'Timestamp (milliseconds since 01-Jan-1970): 0x123456789abc')


class TestNvmeMiFeaturesSelect:
    """MI-6: Get Features Select (Base 2.3 Figures 197, 199) and feature units
    (Figures 404, 450-454, 467, 679, 681; NVM CS 1.2 Figures 93-95, 99)."""

    FILE = 'nvme-mi-features-sel.pcapng'
    CQE = 'nvme.cqe.dword0.get_features.'
    CDP = 'nvme.features.cdp.'

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_decode(self, assert_frames_match, two_pass):
        c, d = self.CQE, self.CDP
        assert_frames_match(self.FILE, [
            (2, f'{c}arb.ab == 3 && {c}arb.lpw == 0x38 && {c}arb.hpw == 0xff'),
            (4, f'{c}arb.ab == 7'),
            (6, f'{c}caps.svbl == 1 && !{c}arb'),
            (7, 'nvme.cmd.get_features.sel_reserved'),
            (8, f'nvme.cqe.dword0 == 0xff003803 && !{c}arb'),
            # Select 011b returns no Response Data (Base 2.4 Figure 201).
            (9, 'nvme-mi.admin.invalid_dlen'),
            (10, ('nvme-mi.admin.unexpected_response_data && nvme-mi.admin.data'
                 ' && !nvme.data && !nvme.cmd.get_features.sel_caps_data'
                 ' && !nvme.cmd.get_features.sel_no_data'
                 f' && !nvme.set_features.lbart.apst && {c}caps.svbl == 1')),
            # Reserved Select: flagged on the command only.
            (12, ('!nvme.cmd.get_features.sel_caps_data && !nvme.cmd.get_features.sel_no_data'
                 ' && nvme.cqe.dword0 == 0 && !nvme.get_features.tst')),
            (14, ('nvme.cqe.dword0 == 0xdeadbeef'
                 ' && nvme.features.hostid == 30:31:32:33:34:35:36:37')),
            (16, (f'{c}lbart.lbarn == 0 && nvme.set_features.lbart.nlb == 0'
                 ' && nvme.set_features.lbart.nlb == 0xffffffffffffffff')),
            (18, 'nvme.features.power.plv == 0x1234 && nvme.features.power.pls == 1'),
            (20, 'nvme.features.power.pts == 2 && nvme.features.power.pmts == 0xc'),
            (21, 'nvme.features.measurement.act == 1 && nvme.features.measurement.pmts == 0'),
            (24, (f'{d}security_status == 0x00010006 && {d}security_status.tcgpst == 1'
                 f' && {d}security_status.ahatsdps == 1 && {d}security_status.vsp == 1'
                 f' && {d}security_supported.tcgpsup == 1'
                 f' && {d}security_supported.ahatsdps == 0'
                 f' && {d}security_supported.vsp == 0x8000')),
            (25, (f'{d}security_attributes.asp == 1 && {d}security_attributes.tcgp == 1'
                 f' && {d}security_attributes.ahatsdp == 0 && {d}security_attributes.vsp == 2')),
            (27, 'nvme.features.power.plv == 0x100 && nvme.features.power.pls == 2'),
            (30, f'{c}lbasi.lsiri == 0x14 && {c}lbasi.lsipi == 0x32'),
        ], two_pass=two_pass)

    def test_labels(self, dissect_pdml):
        p = dissect_pdml(self.FILE)

        def label(frame, name):
            return p.field(frame, name)['showname']

        c = self.CQE
        assert {(f, n): label(f, n).split(' = ')[-1] for f, n in (
            (2, c + 'arb.ab'), (2, c + 'arb.lpw'), (2, c + 'arb.mpw'), (2, c + 'arb.hpw'),
            (4, c + 'arb.ab'), (16, c + 'lbart.lbarn'),
            (18, 'nvme.features.power.pls'), (20, 'nvme.features.power.pts'),
            (20, 'nvme.features.power.pmts'), (21, 'nvme.features.measurement.pmts'),
            (27, 'nvme.features.power.pls'), (7, 'nvme.cmd.get_features.dword10.sel'),
        )} == {
            (2, c + 'arb.ab'): 'Arbitration Burst: 3 (8 commands)',
            (2, c + 'arb.lpw'): 'Low Priority Weight: 0x38 (57)',
            (2, c + 'arb.mpw'): 'Medium Priority Weight: 0x0 (1)',
            (2, c + 'arb.hpw'): 'High Priority Weight: 0xff (256)',
            (4, c + 'arb.ab'): 'Arbitration Burst: 7 (No limit)',
            (16, c + 'lbart.lbarn'): 'Number of LBA Ranges (NUM): 0x0 (1)',
            (18, 'nvme.features.power.pls'): 'Power Limit Scale (PLS): 0.0001 W (0x1)',
            (20, 'nvme.features.power.pts'): 'Power Threshold Scale (PTS): 0.01 W (0x2)',
            (20, 'nvme.features.power.pmts'):
                'Power Measurement Type Select (PMTS): Vendor Specific (0xc)',
            (21, 'nvme.features.measurement.pmts'):
                'Power Measurement Type Select (PMTS): NVM subsystem total power (0x0)',
            (27, 'nvme.features.power.pls'): 'Power Limit Scale (PLS): 0.01 W (0x2)',
            (7, 'nvme.cmd.get_features.dword10.sel'): 'Select: Reserved (0x4)',
        }
        assert p.shownames(16, 'nvme.set_features.lbart.nlb') == ['Number of Logical Blocks: 0x0 (1)',
                       'Number of Logical Blocks: 0xffffffffffffffff (2^64)']
        # The SEL 011b data stays one visible raw MI item, not a structure.
        assert p.sizes(10, 'nvme-mi.admin.data') == [16]
        assert p.fields(10, 'nvme-mi.admin.data')[0].get('hide') is None
        assert p.fields(10, 'nvme.data') == []
        # Host Identifier is returned only in the data buffer (Base 2.3
        # 5.2.26.1.32), so DW0 carries no decoded sub-fields.
        assert not [f for f in p[14].iter('field')
                    if f.get('name', '').startswith(self.CQE)]

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_get_set_field_names(self, dissect_pdml, field_registry, two_pass):
        # Base 2.4 Figures 468/469 (WH), 470 (TMPSEL), 484 (NVMSETID).
        p = dissect_pdml(self.FILE, two_pass=two_pass)
        wh = {31: 'nvme.cmd.set_features.dword11.pm.wh', 34: self.CQE + 'pm.wh'}
        ps = {31: 'nvme.cmd.set_features.dword11.pm.ps', 34: self.CQE + 'pm.ps'}
        assert {n: (p.field(n, f)['showname'].split(' = ')[-1], p.values(n, ps[n]))
                for n, f in wh.items()} == {
            31: ('Workload Hint (WH): 0x3', [5]), 34: ('Workload Hint (WH): 0x2', [5])}
        tmpsel = 'nvme.cmd.{}_features.dword11.tt.tmpsel'
        assert {n: (p.values(n, tmpsel.format('set')), p.values(n, tmpsel.format('get')))
                for n in (35, 37)} == {35: ([2], []), 37: ([], [2])}
        assert p.label(35, tmpsel.format('set')) == p.label(37, tmpsel.format('get')) == \
            'Temperature Sensor 2 (0x2)'
        assert p.values(39, 'nvme.cmd.get_features.dword11.rrl.nvmsetid') == [3]
        assert 'nvme.cmd_get_features.dword11.rrl.nvmsetid' not in field_registry
        # Neighbouring control: Arbitration keeps its own fields.
        assert p.label(2, self.CQE + 'arb.ab') == '3 (8 commands)'


class TestNvmeMiIdentifyWindows:
    """MI-7: windowed Identify lists (Base 2.3 Figures 331-352, NVM CS 1.2
    Figures 116-124) and the NVM Command Set specific fields."""

    FILE = 'nvme-mi-identify-win.pcapng'
    ID = 'nvme.cmd.identify.'

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_decode(self, assert_frames_match, two_pass):
        i = self.ID
        assert_frames_match(self.FILE, [
            (2, f'{i}ns.lbaf == 0x010c0020 && {i}ns.lbaf == 0x010c002f && !{i}ns.nlbaf'),
            (4, f'{i}nslist.nsid == 5 && {i}nslist.nsid == 7'),
            (6, ('nvme.identify.nsdesc.nidl_mismatch'
                f' && {i}nsdesc.csi == 2 && {i}nsdesc.rsvd == 00:00')),
            (8, f'{i}nvmset.num == 2 && {i}nvmset.id == 2 && {i}nvmset.ows == 9'),
            (10, (f'!{i}nvmset.num && {i}nvmset.id == 2'
                 f' && {i}nvmset.unvmsc == 51:51:51:51:51:51:51:51:51:51:51:51:51:51:51:51')),
            (12, f'{i}pcc.vqfrt == 0x11 && {i}pcc.vigran == 0xcc && !{i}pcc.cntlid'),
            (14, f'!{i}scl.num && {i}scl.scid == 0x22 && {i}scl.nvi == 5'),
            (16, f'{i}ngl.nd == 0 && {i}ngl.nsg == 0x1000 && !({i}ngl.nsg == 0x3000)'),
            (18, f'{i}uuid.idassoc == 2 && !({i}uuid.idassoc == 3)'),
            (20, f'{i}uuid.idassoc == 3'),
            (22, (f'{i}nvm_ns.pic.qpifs && {i}nvm_ns.pifa.stmla == 1'
                 f' && {i}nvm_ns.npdgl == 0x100 && {i}nvm_ns.nprg == 7'
                 f' && {i}nvm_ns.lbapss == 0x300 && {i}nvm_ns.tlbaag == 0x400')),
            (24, (f'{i}nvm_ctrl.kpiocap.kpiosc && {i}nvm_ctrl.aocs.ralbas'
                 f' && {i}nvm_ctrl.ver.mjr == 1 && {i}nvm_ctrl.ver.mnr == 2'
                 f' && {i}nvm_ctrl.lbamqf == 0xc1 && {i}nvm_ctrl.wzdsl == 5')),
            (26, f'!{i}domain.num && {i}domain.id == 0x4321'),
            (28, f'!{i}eg.num && {i}eg.id == 9'),
            (30, f'{i}iocsc.znscs && {i}iocsc.cpncs'),
            (32, (f'{i}underlying.traddr == "192.168.0.1" && {i}underlying.trtype == 3'
                 f' && {i}underlying.adrfam == 1 && {i}underlying.treq.tasc == 1'
                 f' && {i}underlying.pidup == 0x0102')),
            (34, 'nvme.identify.cns_reserved'),
            (36, f'{i}ctrl.psds.psd.apw == 1'),
        ], two_pass=two_pass)

    def test_labels(self, dissect_pdml):
        p = dissect_pdml(self.FILE)
        i = self.ID
        # IDENTIFY-6: slot indices follow the structure offset.
        lbafs = p.shownames(2, i + 'ns.lbaf')
        assert len(lbafs) == 16
        assert '(LBAF32: LBADS 12, MS 32, RP Better performance)' in lbafs[0]
        assert '(LBAF47:' in lbafs[-1]
        # Unaligned window: two partial fields and entries labeled by index.
        assert p.shownames(4, i + 'nslist.nsid') == ['nsid[1]: 5', 'nsid[2]: 6', 'nsid[3]: 7']
        assert p.sizes(4, 'nvme.window.partial') == [2, 2]
        # IDENTIFY-4: the EUI64 NID keeps its 16 bytes; the CSI is decoded.
        assert p.sizes(6, i + 'nsdesc.nid') == [16]
        assert p.experts(6) == [
            "NIDL 16 does not match the 8 bytes NIDT 1 requires (NVMe Base 'Identify - Namespace Identification Descriptor')"]
        assert p.label(6, i + 'nsdesc.csi') == 'Zoned Namespace Command Set (0x02)'
        # IDENTIFY-7: entry 1 cut inside TNVMSC decodes through OWS, then partial.
        assert p.values(8, i + 'nvmset.id') == [1, 2]
        assert p.values(8, i + 'nvmset.r4krt') == [100, 101]
        assert p.sizes(8, i + 'nvmset.tnvmsc') == [16]
        assert p.fields(8, 'nvme.window.partial')[-1].get('value') == '41414141'
        # Without NUMENT/NEGIDS the list is labeled by its structure index
        # and all-zero slots are skipped.
        assert p.values(10, i + 'nvmset.id') == [2]
        assert p.values(28, i + 'eg.id') == [7, 9, 0x10]
        # The ND count bounds the descriptors even when more are nonzero.
        assert p.values(16, i + 'ngl.ncg') == [0x2000]
        # IDENTIFY-15: a zero UUID ends the list; a mid-entry window decodes
        # its whole fields.
        assert p.values(18, i + 'uuid.idassoc') == [1, 2]
        assert [f.get('value') for f in p.fields(20, i + 'uuid.uuid')] == [
            bytes(range(0x20, 0x30)).hex(), bytes(range(0x30, 0x40)).hex()]
        assert not p.fields(20, 'nvme.window.partial')
        # IDENTIFY-1/2/9/10: NVM CS 1.2 Figures 118-119.
        assert p.label(22, i + 'nvm_ns.pifa.stmla') == 'Byte Granularity Masking (0x1)'
        elbaf = p.shownames(22, i + 'nvm_ns.elbaf')
        assert len(elbaf) == 64
        assert elbaf[0].endswith('0x00000390 (ELBAF0)') and elbaf[63].endswith('(ELBAF63)')
        assert p.shownames(22, i + 'nvm_ns.pif')[:2] == [
            '.... .... .... .... .... ...1 1... .... = Protection Information Format (PIF): Qualified Type (0x3)',
            ('.... .... .... .... .... ...1 0... .... = Protection Information Format (PIF):'
            ' 64b Guard Protection Information (0x2)')]
        assert p.label(22, i + 'nvm_ns.qpif') == '32b Guard Protection Information (0x1)'
        assert p.label(22, i + 'nvm_ns.nprg') == '0x7 (8)'
        assert p.label(22, i + 'nvm_ns.npra') == '0x3 (4)'
        assert p.label(22, i + 'nvm_ns.nors') == '0xf (16)'
        # IDENTIFY-3: NVM CS 1.2 Figure 120.
        assert p.label(24, i + 'nvm_ctrl.lbamqf') == 'Vendor Specific (0xc1)'
        assert p.values(24, i + 'nvm_ctrl.ver.ter') == [0]
        # IDENTIFY-5: one bitmask per vector, labeled by combination index.
        assert [s.split(': ', 1)[1] for s in p.shownames(30, i + 'iocsc')] == [
            '0x0000000000000005 (Combination 0)', '0x000000000000001f (Combination 1)']
        # IDENTIFY-8: Base 2.3 Figure 352.
        assert p.label(32, i + 'underlying.trtype') == 'TCP Transport (0x03)'
        assert p.label(32, i + 'underlying.adrfam') == 'AF_INET (0x01)'
        assert p.sizes(32, i + 'underlying.tsas') == [256]
        # IDENTIFY-14: a reserved CNS is raw with a warning.
        assert p.sizes(34, 'nvme.data') == [16]
        # IDENTIFY-12: Base 2.3 Figure 674.
        assert p.label(36, i + 'ctrl.psds.psd.apw') == 'Workload #1 (0x1)'
        # 128-bit byte counts (Base 2.4 Figures 345/351) keep their 16 raw
        # bytes and show the magnitude, below and above 2^64.
        assert [(f.get('size'), f.get('showname').rsplit(' (', 1)[1])
                for n, name in ((76, 'nvmset.tnvmsc'), (76, 'nvmset.unvmsc'),
                                (78, 'domain.tdc'), (78, 'domain.udc'),
                                (78, 'domain.megdc'))
                for f in p.fields(n, i + name)] == [
            ('16', '1099511627776 bytes)'), ('16', '18014398509481988 KiB)'),
            ('16', '4096 bytes)'), ('16', '0 bytes)'), ('16', '90071992547409920 KiB)')]

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_mid_entry_windows(self, dissect_pdml, two_pass):
        p = dissect_pdml(self.FILE, two_pass=two_pass)
        i = self.ID

        def val(fr, name):
            return [f.get('value') for f in p.fields(fr, name)]

        def entries(fr):
            return [f for f in p[fr].iter('field')
                    if (f.get('show') or '').startswith('Domain Attributes Entry')]

        def typed(fr):
            return [f for f in p[fr].iter('field')
                    if (f.get('name') or '').startswith(i + 'domain.')]

        # IDENTIFY-1: a window inside entry 0 decodes TDC whole.
        assert val(38, i + 'domain.tdc') == ['01' * 16]
        assert not p.fields(38, 'nvme.window.partial')
        assert not p.fields(38, i + 'domain.id')
        # A window splitting TDC leaves it partial.
        assert not p.fields(40, i + 'domain.tdc')
        assert val(40, 'nvme.window.partial') == ['01' * 12]
        # Reserved bytes only: raw data under the entry node.
        e = entries(42)
        assert [n.get('show') for n in e] == ['Domain Attributes Entry 0']
        assert [f.get('value') for f in e[0].findall(".//field[@name='nvme.data']")] == ['ee' * 12]
        assert not typed(42)
        assert not p.fields(42, 'nvme.window.partial')
        # Starting inside entry 0 and crossing into entry 1.
        assert val(44, i + 'domain.tdc') == ['01' * 16]
        assert val(44, i + 'domain.udc') == ['02' * 16]
        assert val(44, i + 'domain.megdc') == ['03' * 16]
        assert p.values(44, i + 'domain.id') == [2]
        assert not p.fields(44, 'nvme.window.partial')
        assert [n.get('show') for n in entries(44)] == [
            'Domain Attributes Entry 0', 'Domain Attributes Entry 1']
        # An all-zero entry is still skipped when NUMENT is unknown.
        assert not entries(46)
        assert not typed(46)
        assert not p.fields(46, 'nvme.window.partial')

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_underlying_namespace_list(self, dissect_pdml, two_pass):
        p = dissect_pdml(self.FILE, two_pass=two_pass)
        u = self.ID + 'underlying.'
        excess = ('NUMENT exceeds the maximum of 12 Underlying Namespace entries'
                  ' (Base 5.2.14.2.20)')
        # IDENTIFY-2: Base 2.4 Figure 357 IDX, requested through CNSSID.
        assert p.values(47, self.ID + 'dword11.cnssid') == [0x1234]
        assert p.values(48, u + 'idx') == [0x1234]
        genctr, = p.extents(48, u + 'genctr')
        assert p.extents(48, u + 'idx') == [(genctr[0] + 16 + 318, 2)]
        # IDENTIFY-3: at most 12 entries; NUMENT keeps its wire value.
        assert p.values(50, u + 'nument') == [12]
        assert len(p.fields(50, u + 'unsnqn')) == 12
        assert p.values(50, u + 'idx') == list(range(12))
        assert excess not in p.experts(50)
        assert p.values(52, u + 'nument') == [13]
        assert excess in p.experts(52)
        assert len(p.fields(52, u + 'unsnqn')) == 12
        assert p.values(52, u + 'idx') == list(range(12))
        assert 240 not in p.sizes(52, 'nvme.data')

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_ns_granularity_csi(self, dissect_pdml, two_pass):
        # Base 2.4 section 5.2.14.2.13: the CNS 16h layout is the I/O Command
        # Set's (NVM CS 1.3 Figures 132-133); others stay opaque.
        p = dissect_pdml(self.FILE, two_pass=two_pass)
        i = self.ID
        ngl = b'\x01' + bytes(31) + b''.join(
            v.to_bytes(8, 'little') for v in (0x1000, 0x2000, 0x3000, 0x4000))
        assert p.values(53, i + 'dword11.csi') == [0x01]
        assert p.values(55, i + 'dword11.csi') == [0x30]
        assert [f.get('value') for f in p.fields(54, 'nvme.data')] == [ngl.hex()]
        assert [f.get('value') for f in p.fields(56, 'nvme.data')] == [ngl[32:].hex()]
        assert p.extents(54, 'nvme.data')[0][0] == p.extents(56, 'nvme.data')[0][0]
        for n in (54, 56, 60):
            assert not [f for f in p[n].iter('field')
                        if (f.get('name') or '').startswith(i + 'ngl.')]
        assert p.experts(54) == p.experts(56) == []
        # CSI 00h at DOFST 32: NVM descriptors, ND outside the window.
        assert p.values(58, i + 'ngl.nsg') == [0x1000, 0x3000]
        assert p.values(58, i + 'ngl.ncg') == [0x2000, 0x4000]
        assert not p.fields(58, i + 'ngl.nd') and not p.fields(58, 'nvme.data')
        # An Invalid I/O Command Set completion stays an ordinary error.
        assert p.label(60, 'nvme.cqe.status.sc') == '0x2c (Invalid I/O Command Set)'
        assert p.experts(60) == ['Command completed with an error status']
        assert not p.fields(60, 'nvme.data')

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_reserved_enum_values(self, dissect_pdml, two_pass):
        # Base 2.4 Figures 338/342; NVM CS 1.3 Figures 123/128.
        p = dissect_pdml(self.FILE, two_pass=two_pass)
        i = self.ID

        def text(n, f):
            return [s.split(': ', 1)[-1] for s in p.shownames(n, i + f)]

        assert text(62, 'ctrl.sanicap.nodmmas') == ['Reserved (0x3)']
        assert text(64, 'ctrl.sanicap.nodmmas') == [
            'additional modification after sanitize completion (0x2)']
        assert {n: (text(n, 'ns.dps.pit'), text(n, 'ns.dlfeat.drb')) for n in (66, 68, 70)} == {
            66: (['Reserved (0x4)'], ['Reserved (0x3)']),
            68: (['Reserved (0x7)'], ['Reserved (0x7)']),
            70: (['Type 3 protection information is enabled (0x3)'],
                 ['deallocated logical block returns all bytes set to FFh (0x2)'])}
        assert p.values(66, i + 'ns.dps.pit') == [4] and p.values(68, i + 'ns.dlfeat.drb') == [7]
        assert text(72, 'nsdesc.nidt') == [
            'Reserved (0x00)', 'Reserved (0x05)', 'Reserved (0xff)',
            'Command Set Identifier (CSI) (0x04)']
        assert p.values(72, i + 'nsdesc.nidt') == [0, 5, 0xff, 4]
        assert text(74, 'nvm_ns.pif') == ['Qualified Type (0x3)'] * 3
        assert text(74, 'nvm_ns.qpif') == [
            'Reserved (0x3)', 'Reserved (0xf)', '64b Guard Protection Information (0x2)']
        assert p.values(74, i + 'nvm_ns.qpif') == [3, 0xf, 2]
        assert all(p.experts(n) == [] for n in range(61, 75))


class TestNvmeMiP2_5:
    FILE = 'nvme-mi-p2-5.pcapng'

    def test_identify_names_units_and_partial_fields(self, dissect_pdml):
        p = dissect_pdml(self.FILE)
        i = 'nvme.cmd.identify.'
        assert any('Function Type (FT)' in name for name in
                   p.shownames(2, i + 'ctrl.cmic.sriov'))
        assert any('343 K' in name for name in
                   p.shownames(2, i + 'ctrl.wctemp'))
        assert any('300 K' in name for name in
                   p.shownames(2, i + 'ctrl.cctemp'))
        assert any('1234' in name and 'microsecond' in name
                   for name in p.shownames(2, i + 'ctrl.psds.psd.enlat'))
        assert any('5678' in name and 'microsecond' in name
                   for name in p.shownames(2, i + 'ctrl.psds.psd.exlat'))
        assert any('Reserved' in name for name in
                   p.shownames(2, i + 'ctrl.psds.psd.epfrt'))
        assert p.label(2, i + 'ctrl.nvmeof.dctype') == 'Reserved (0x03)'
        assert p.label(8, i + 'nvm_ns.pifa.stmla') == 'Reserved (0x3)'

        for frame in (4, 6):
            partial = p.field(frame, 'nvme.window.partial')
            assert int(partial['size']) == 8
            assert p.experts(frame) == []

    def test_log_labels_and_units(self, dissect_pdml):
        p = dissect_pdml(self.FILE)
        assert any('Command Set Identifier (CSI)' in name for name in
                   p.shownames(10, 'nvme.cmd.get_logpage.errinf.cmdset'))
        assert any('No time reported' in name for name in
                   p.shownames(12, 'nvme.cmd.get_logpage.sanitize.eto'))
        assert any('Completed in background' in name for name in
                   p.shownames(14, 'nvme.cmd.get_logpage.sanitize.eto'))
        # LOG-2: ETPVDS 0h is a time, not a sentinel (Base 2.4 Figure 312).
        etpvds = 'nvme.cmd.get_logpage.sanitize.etpvds'
        assert p.label(64, etpvds) == '0 seconds'
        assert p.label(66, etpvds) == 'No time reported'

    def test_log_lsp_labels(self, dissect_pdml):
        # LOG-3: Base 2.4 Figures 220 and 274.
        p = dissect_pdml(self.FILE)
        lsp = 'nvme.cmd.get_logpage.lsp.'
        for frame, text in (
                (67, 'Controller determines the data areas (0)'),
                (69, 'Data Area 1 (1)'),
                (71, 'Data Area 1 through Data Area 2 (2)'),
                (73, 'Data Area 1 through Data Area 3 (3)'),
                (75, 'Reserved (5)'),
                (77, 'Reserved (7)')):
            assert p.label(frame, lsp + 'mcda') == text
        assert p.label(79, lsp + 'scope') == 'Reserved (0x1)'
        assert p.label(81, lsp + 'contents') == 'Reserved (0x3)'

    def test_admin_reserved_values(self, dissect_pdml):
        # CORE-1: Base 2.4 Figures 177, 187, 195, 365 and 451.
        p = dissect_pdml(self.FILE)
        cmd = 'nvme.cmd.'
        for frame, name, text in (
                (83, 'format_nvm.dword10.ses', 'Reserved (0x7)'),
                (85, 'fw_commit.dword10.ca', 'Reserved (0x4)'),
                (87, 'fw_commit.dword10.ca', 'Replace Boot Partition specified by BPID (0x6)'),
                (89, 'self_test.dword10.stc', 'Reserved (0x4)'),
                (91, 'self_test.dword10.stc', 'Vendor specific (0xe)'),
                (93, 'lockdown.dword10.scp', 'Reserved (0x5)'),
                (95, 'lockdown.dword10.scp', 'Reserved (0x1)'),
                (97, 'lockdown.dword10.ifc', 'Reserved (0x3)'),
                (99, 'lockdown.dword10.csel', 'Reserved (0x3)'),
                (101, 'lockdown.dword10.csel', 'Vendor Specific (0xf)'),
                (103, 'sanitize.dword10.sanact', 'Reserved (0x0)'),
                (105, 'sanitize.dword10.sanact', 'Reserved (0x6)'),
                (107, 'sanitize.dword10.sanact', 'Block Erase (0x2)')):
            assert p.label(frame, cmd + name) == text

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_sanitize_ns_reserved_bits(self, assert_frames_match, dissect_pdml, two_pass):
        # CORE-2: Base 2.4 Figure 454.
        n = 'nvme.cmd.sanitize_ns.'
        assert_frames_match(self.FILE, [
            (109, f'{n}rsvd0 == 1 && {n}rsvd1 == 0 && {n}act == 4'),
            (111, f'{n}rsvd0 == 0 && {n}rsvd1 == 0x100000 && {n}act == 4'),
            (113, (f'{n}rsvd0 == 0 && {n}rsvd1 == 0 && {n}preq == 1'
                  f' && {n}ause == 1 && {n}emvs == 1 && !_ws.expert')),
        ], two_pass=two_pass)
        assert dissect_pdml(self.FILE).label(109, n + 'act') == (
            'Start a Crypto Erase namespace sanitize operation (0x4)')

    def test_feature_value_names(self, dissect_pdml):
        p = dissect_pdml(self.FILE)
        fid = 'nvme.cmd.get_features.dword10.fid'
        assert p.label(19, fid) == 'Reserved (0x00)'
        assert p.label(21, fid) == 'Reserved (0x90)'
        assert p.label(23, fid) == 'LBA Status Information Attributes (0x15)'
        assert p.label(25, 'nvme.features.perf.attri') == 'Reserved (0x01)'
        # A Reserved attribute leaves the transfer unknown: DLEN 0h is not flagged.
        assert p.experts(25) == []
        assert p.label(27, 'nvme.features.perf.attri') == \
            'Performance Attribute Identifier List (0xc0)'
        assert any('Greater than or equal to 1 second' in name for name in
                   p.shownames(16, 'nvme.features.perf.r4karl'))
        assert p.label(18, 'nvme.features.perf.r4karl') == 'Reserved (0x18)'
        assert p.label(28, 'nvme.features.perf.attrtyp') == 'Default attribute (0x1)'
        assert p.label(29, 'nvme.cmd.get_features.dword10.sel') == \
            'Supported Capabilities (0x3)'

        act = 'nvme.features.measurement.act'
        assert p.label(31, act) == 'Stop (0x0)'
        assert p.label(33, act) == 'Start (0x1)'
        assert p.label(35, act) == 'Reserved (0x2)'
        assert p.label(37, act) == 'Reserved (0xb)'
        assert p.label(39, act) == 'Vendor Specific (0xc)'
        assert p.label(41, act) == 'Vendor Specific (0xf)'

    def test_format_sanitize_and_count_labels(self, dissect_pdml):
        p = dissect_pdml(self.FILE)
        f = 'nvme.cmd.format_nvm.dword10.'
        # MSET/PI/PIL are I/O Command Set specific (Base 2.4 Figure 195).
        assert p.label(43, f + 'pi') == '0x1'
        assert p.label(43, f + 'mset') == '0x0'
        assert p.label(43, f + 'pil') == '0x1'
        assert p.label(43, f + 'ses') == 'No secure erase operation requested (0x0)'

        sanact = 'nvme.cmd.sanitize_ns.act'
        assert p.label(45, sanact) == 'Reserved (0x0)'
        assert p.label(47, sanact) == 'Exit Failure Mode (0x1)'
        assert p.label(49, sanact) == \
            'Start a Crypto Erase namespace sanitize operation (0x4)'
        assert p.label(51, sanact) == 'Exit Media Verification State (0x5)'
        assert p.label(53, sanact) == 'Reserved (0x7)'
        # Two NVMe Base 2.4 figures disagree (Figure 455 lists 12h, Figure
        # 104 assigns 3Ch): a note on the status, not an expert info.
        assert p.shows(56, 'nvme.cqe.status.sc.note') == [
            "NVMe Base 'Sanitize Namespace - Command Specific Status Values' lists"
            ' Request Exceeds Maximum Namespace Sanitize Operations In Progress;'
            " 'Status Code - Command Specific Status Values' assigns this status to 3Ch"]
        assert not any('Request Exceeds Maximum Namespace' in expert
                       for expert in p.experts(56))
        assert 'nvme.cqe.status.sc.sanitize_ns_conflict' not in p.names
        assert any('Sanitize Namespace - Command Specific Status Values: Request Exceeds Maximum Namespace' in name
                   for name in p.shownames(56, 'nvme.cqe.status.sc'))
        assert not any('Undefined for Sanitize Namespace' in expert
                       for expert in p.experts(56))
        assert not p.fields(58, 'nvme.cqe.status.sc.undefined_for_cmd')
        assert p.label(58, 'nvme.cqe.status.sc') == \
            '0x3c (Request Exceeds Maximum Namespace Sanitize Operations In Progress)'
        assert '  is Enabled' not in p.label(60, 'nvme.cqe.status.sc')
        assert p.shownames(61, 'nvme.cmd.get_lba_status.mndw') == [
            'Maximum Number of Dwords (MNDW): 0x0 (1)']

    @pytest.mark.parametrize('capture', (
        'nvme-mi-admin-identify.pcapng', 'nvme-mi-mi-commands.pcapng', 'nvme-mi-mi4.pcapng',
        'nvme-mi-p2-5.pcapng', 'nvme-mi-pel-events.pcapng', 'nvme-mi-spec-revisions.pcapng'))
    def test_format_nvm_no_command_set_meanings(self, dissect_pdml, capture):
        # The Format NVM SQE and PEL Format NVM Start event carry no CSI.
        nvm = ('protection information is enabled', 'Extended LBA', 'Separate buffer',
               'First bytes', 'Last bytes')
        trees = []
        for two_pass in (False, True):
            p = dissect_pdml(capture, two_pass=two_pass)
            frames = p.frames_with('nvme.cmd.format_nvm.dword10')
            assert frames
            tree = {n: [ET.tostring(e, encoding='unicode')
                        for e in p.fields(n, 'nvme.cmd.format_nvm.dword10')] for n in frames}
            assert not [s for n in frames for s in nvm if s in ''.join(tree[n])]
            trees.append(tree)
        assert trees[0] == trees[1]


class TestNvmeMiLogPageFixed:
    """MI-8a: fixed-layout MI-reachable log pages (Base 2.3 Figures 272-300):
    Boot Partition, Rotational Media, Management Address List, Device
    Personalities, Power Measurement and Sanitize Namespace Status List."""

    FILE = 'nvme-mi-logpage-fixed.pcapng'
    LP = 'nvme.cmd.get_logpage.'

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_decode(self, assert_frames_match, two_pass):
        g = self.LP
        assert_frames_match(self.FILE, [
            (2, f'{g}bp.lid == 0x15 && {g}bp.bpinfo.abpid && {g}bp.bpinfo.bpsz == 2'),
            (4, (f'{g}rmi.endgid == 1 && {g}rmi.numa == 2 && {g}rmi.nrs == 7200'
                f' && {g}rmi.fldc == 2 && {g}rmi.rsvd1')),
            (6, f'{g}rmi.nrs == 1 && !{g}rmi.rsvd1'),
            (8, (f'{g}mal.mat == 1 && {g}mal.madrs == "https://10.0.0.1/mgmt"'
                f' && {g}mal.mat == 0xff')),
            (10, f'{g}mal.mat == 2 && !({g}mal.mat == 1)'),
            (12, (f'{g}dp.nump == 1 && {g}dp.dplphl == 6 && {g}dp.mrstt == 3'
                 f' && {g}dp.aus.pkas && {g}dp.attr.pscude')),
            (14, (f'nvme.cmd.get_logpage.layout_invalid && {g}dp.perid == 0'
                 f' && !({g}dp.perid == 1)')),
            (16, f'!{g}dp.nump && {g}dp.perid == 1 && !({g}dp.perid == 0)'),
            (18, (f'{g}pm.nphd == 2 && {g}pm.pma.mipwrts && {g}pm.smts.tstmp == 0x123456'
                 f' && {g}pm.aipwr.value == 1234 && {g}pm.phblt.value == 25'
                 f' && {g}pm.vs == de:ad:be:ef')),
            (20, (f'nvme.cmd.get_logpage.layout_invalid && {g}pm.ipwrpe == 0xff'
                 f' && !{g}pm.phbc')),
            (22, (f'{g}snsl.genctr == 7 && {g}snsl.numnsid == 3 && {g}snsl.nsid == 5'
                 f' && !({g}snsl.nsid == 9)')),
            (24, f'!{g}snsl.numnsid && {g}snsl.nsid == 2 && {g}snsl.nsid == 5'),
            (26, f'!{g}bp.lid && {g}bp.bpinfo.abpid && !{g}bp.bpd'),
            # DPLPHL 12 puts the Personalities at byte 12; the list's end
            # must not wrap for a header longer than the minimum.
            (28, f'{g}dp.dplphl == 12 && {g}dp.perid == 0 && {g}dp.perid == 1'),
        ], two_pass=two_pass)

    def test_labels(self, dissect_pdml):
        p = dissect_pdml(self.FILE)
        g = self.LP
        assert p.label(2, g + 'bp.bpinfo.bpsz') == '2 (256 KiB)'
        assert p.sizes(2, g + 'bp.bpd') == [32]
        assert p.label(4, g + 'rmi.nrs') == '7200 RPM'
        assert p.label(6, g + 'rmi.nrs') == 'Prohibited (1)'
        # The list ends at the first MAT FFh.
        assert p.values(8, g + 'mal.mat') == [1, 2, 0xff]
        assert p.shows(8, g + 'mal.madrs')[:2] == [
            'https://10.0.0.1/mgmt', 'snmp://192.0.2.7:161']
        assert p.values(10, g + 'mal.mat') == [2]
        assert p.label(12, g + 'dp.nump') == '0x1 (2)'
        assert [s.split(': ', 1)[1] for s in p.shownames(12, g + 'dp.mrstt')] == [
            'No Reset (0x00)', 'NVM Subsystem Reset (0x03)']
        assert p.experts(14) == [
            "Personality 1 has PPS 4; NVMe Base 'Personality Properties Data Structure' defines 5"]
        # Without the header a cut personality stays raw.
        assert p.sizes(16, 'nvme.data')[-1] == 3
        assert p.values(16, g + 'dp.pps') == [5]
        assert p.label(18, g + 'pm.smtr') == '30 minutes'
        assert p.label(18, g + 'pm.phbs') == '250mW'
        assert p.label(18, g + 'pm.aipwr.scale') == '0.01 W (0x2)'
        assert p.label(18, g + 'pm.ipwrpe') == 'Maximum percent error (5)'
        assert p.values(18, g + 'pm.phbc') == [60, 40]
        assert p.experts(20) == [
            'PHDS 4 is smaller than the 8-byte Power Histogram Descriptor']
        assert p.label(20, g + 'pm.ipwrpe') == 'Not reported (255)'
        # NUMNSID bounds the list; without the header entries use their index.
        assert p.values(22, g + 'snsl.nsid') == [1, 2, 5]
        assert p.values(24, g + 'snsl.nsid') == [2, 5]


class TestNvmeMiLogPageDesc:
    """MI-8b: descriptor-list log pages (Base 2.3 Figures 259-265, 275 and
    279-283): Media Unit Status, Supported Capacity Configuration List,
    Dispersed Namespace Participating NVM Subsystems, and Reachability
    Groups/Associations read with OT=0."""

    FILE = 'nvme-mi-logpage-desc.pcapng'
    LP = 'nvme.cmd.get_logpage.'

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_decode(self, assert_frames_match, two_pass):
        g = self.LP
        assert_frames_match(self.FILE, [
            (2, (f'{g}mus.nmu == 2 && {g}mus.cio == 32 && {g}mus.chid == 3'
                f' && {g}mus.caf == 0xffff')),
            (4, f'nvme.cmd.get_logpage.layout_invalid && {g}mus.cio == 8 && !{g}mus.chid'),
            (6, f'nvme.window_decode_skipped && !{g}mus.muid'),
            (8, f'{g}mus.nvmsetid == 2 && !({g}mus.caf == 0xffff)'),
            (10, (f'{g}scc.sccn == 1 && {g}scc.egcn == 1 && {g}scc.egsets == 2'
                 f' && {g}scc.chid == 0xffff && {g}scc.muid == 2 && {g}scc.mudl == 4'
                 f' && {g}scc.mudi == aa:bb:cc:dd')),
            (12, f'{g}scc.ee && !{g}scc.egsets'),
            (14, f'nvme.window_decode_skipped && !{g}scc.ccid'),
            (16, (f'{g}dnps.numpsub == 2 && {g}dnps.nqn == "nqn.2024-01.com.example:subsys2"'
                 f' && !({g}dnps.nqn == "nqn.stale")')),
            (18, f'!{g}dnps.numpsub && {g}dnps.nqn == "nqn.2024-01.com.example:subsys2"'),
            (20, (f'{g}reach.count == 2 && {g}reach.id == 2 && {g}reach.member == 2'
                 f' && !{g}reach.rac')),
            (22, f'nvme.window_decode_skipped && !{g}reach.id'),
            (24, f'{g}reach.rac == 2 && {g}reach.member == 2 && {g}reach.id == 7'),
            # The window ends where Media Unit 2 would start: Media Unit 1 is
            # decoded, nothing is read past the window.
            (26, f'!_ws.malformed && {g}scc.muid == 1 && !({g}scc.muid == 2)'),
        ], two_pass=two_pass)

    def test_labels(self, dissect_pdml):
        p = dissect_pdml(self.FILE)
        g = self.LP
        assert p.values(2, g + 'mus.muid') == [0, 1]
        assert p.values(2, g + 'mus.chid') == [0, 1, 3]
        assert p.sizes(2, g + 'mus.rsvd1') == [2, 18]
        assert p.label(2, g + 'mus.avsp') == '90%'
        assert [s.split(': ', 1)[1] for s in p.shownames(2, g + 'mus.caf')] == [
            '3', '65535 or more (0xffff)']
        assert p.experts(4) == ["CIO 8 is not a non-zero multiple of 16 (NVMe Base 'Media Unit Status Descriptor')"]
        # NMU bounds the walk; the window cut stops inside descriptor 1.
        assert p.values(8, g + 'mus.muid') == [0, 1]
        assert p.values(10, g + 'scc.nvmsetid') == [1, 2]
        assert p.values(10, g + 'scc.muid') == [0, 1, 2]
        assert [s.split(': ', 1)[1] for s in p.shownames(10, g + 'scc.chid')] == [
            '0', 'Not specified (0xffff)']
        assert p.shownames(10, g + 'scc.tegcap') == [
            'Total Endurance Group Capacity (TEGCAP) (17592186044416 bytes)']
        assert p.shownames(10, g + 'scc.ee') == ['Endurance Estimate (EE) (<= 1000 GB)']
        assert p.shows(16, g + 'dnps.nqn') == [
            'nqn.2014-08.org.nvmexpress:uuid:1111', 'nqn.2024-01.com.example:subsys2']
        assert p.values(20, g + 'reach.member') == [1, 2]
        assert p.label(24, g + 'reach.rac') == 'Fast copy operations are supported (0x02)'


class TestNvmeMiAdminEom:
    """Receiver Eye Opening Measurement log page (LID 19h, PCIe Transport 1.4 Figures 71-76)."""

    FILE = 'nvme-mi-admin-logpage.pcapng'
    SECTION = 8

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_field_values(self, fields_table, two_pass):
        t = section(fields_table(self.FILE, (
            'nvme-mi', '_ws.malformed.expert', '_ws.col.info', '_ws.expert.message',
            'nvme-mi.admin.short_response', 'nvme-mi.admin.invalid_dlen',
            'nvme-mi.admin.invalid_dofst',
            'nvme.cmd.get_logpage.eom.lid', 'nvme.cmd.get_logpage.eom.eomip',
            'nvme.cmd.get_logpage.eom.hsize', 'nvme.cmd.get_logpage.eom.rsz',
            'nvme.cmd.get_logpage.eom.edgn', 'nvme.cmd.get_logpage.eom.lrev',
            'nvme.cmd.get_logpage.eom.lns', 'nvme.cmd.get_logpage.eom.epl',
            'nvme.cmd.get_logpage.eom.lsic', 'nvme.cmd.get_logpage.eom.ds',
            'nvme.cmd.get_logpage.eom.nd', 'nvme.cmd.get_logpage.eom.maxtb',
            'nvme.cmd.get_logpage.eom.maxlr', 'nvme.cmd.get_logpage.eom.etgood',
            'nvme.cmd.get_logpage.eom.etbetter', 'nvme.cmd.get_logpage.eom.etbest',
            'nvme.cmd.get_logpage.eom.odp.pefp', 'nvme.cmd.get_logpage.eom.odp.edfp',
            'nvme.cmd.get_logpage.eom.lspfc.lspfv', 'nvme.cmd.get_logpage.eom.linfo.mls',
            'nvme.cmd.get_logpage.eom.desc.ln', 'nvme.cmd.get_logpage.eom.desc.eye',
            'nvme.cmd.get_logpage.eom.desc.mstat.mscs', 'nvme.cmd.get_logpage.eom.desc.top',
            'nvme.cmd.get_logpage.eom.desc.btm', 'nvme.cmd.get_logpage.eom.desc.lft',
            'nvme.cmd.get_logpage.eom.desc.rgt', 'nvme.cmd.get_logpage.eom.desc.nrows',
            'nvme.cmd.get_logpage.eom.desc.ncols', 'nvme.cmd.get_logpage.eom.desc.edlen',
            'nvme.cmd.get_logpage.eom.desc.rsvd1', 'nvme.cmd.get_logpage.eom.desc.pe',
            'nvme.cmd.get_logpage.eom.desc.ed', 'nvme.cmd.get_logpage.eom.desc.pad',
            'nvme.cmd.get_logpage.eom.desc.undefined',
            'nvme.cmd.get_logpage.eom.desc_field_overrun', 'nvme.window_decode_skipped',
            'nvme.cmd.get_logpage.dword10.lsp.act', 'nvme.cmd.get_logpage.dword10.lsp.mqual'),
            two_pass=two_pass), self.SPAN)

        def row(frame, *names):
            return [t[frame][n] for n in names]

        desc = ('nvme.cmd.get_logpage.eom.desc.nrows', 'nvme.cmd.get_logpage.eom.desc.ncols',
                'nvme.cmd.get_logpage.eom.desc.edlen', 'nvme.cmd.get_logpage.eom.desc.pe',
                'nvme.cmd.get_logpage.eom.desc.ed')

        assert list(column(t, 'nvme-mi')) == list(range(1, 25))
        assert column(t, '_ws.malformed.expert') == {}
        assert 'Physical Interface Receiver Eye Opening Measurement' in t[1]['_ws.col.info']
        # PCIe Transport 1.4 Figure 75: each header field has a distinct value.
        assert row(2, 'nvme.cmd.get_logpage.eom.lid', 'nvme.cmd.get_logpage.eom.eomip',
                   'nvme.cmd.get_logpage.eom.hsize', 'nvme.cmd.get_logpage.eom.rsz',
                   'nvme.cmd.get_logpage.eom.edgn', 'nvme.cmd.get_logpage.eom.lrev',
                   'nvme.cmd.get_logpage.eom.lns', 'nvme.cmd.get_logpage.eom.epl',
                   'nvme.cmd.get_logpage.eom.lsic', 'nvme.cmd.get_logpage.eom.ds',
                   'nvme.cmd.get_logpage.eom.nd', 'nvme.cmd.get_logpage.eom.maxtb',
                   'nvme.cmd.get_logpage.eom.maxlr', 'nvme.cmd.get_logpage.eom.etgood',
                   'nvme.cmd.get_logpage.eom.etbetter', 'nvme.cmd.get_logpage.eom.etbest',
                   'nvme.cmd.get_logpage.eom.odp.pefp', 'nvme.cmd.get_logpage.eom.odp.edfp',
                   'nvme.cmd.get_logpage.eom.lspfc.lspfv',
                   'nvme.cmd.get_logpage.eom.linfo.mls') == [
            '0x19', '0x02', '64', '208', '7', '3', '4', '1', '0xbeef', '72', '2', '16', '11',
            '11', '22', '33', 'True', 'True', '0x41', '0x05']
        # Both descriptors, DS apart (Figure 76); Reserved 31:20 is 12 bytes.
        assert row(2, 'nvme.cmd.get_logpage.eom.desc.ln', 'nvme.cmd.get_logpage.eom.desc.eye',
                   'nvme.cmd.get_logpage.eom.desc.mstat.mscs',
                   'nvme.cmd.get_logpage.eom.desc.top', 'nvme.cmd.get_logpage.eom.desc.btm',
                   'nvme.cmd.get_logpage.eom.desc.lft', 'nvme.cmd.get_logpage.eom.desc.rgt',
                   *desc) == [
            '0,1', '0,1', 'True,True', '14,14', '16,16', '11,11', '9,9', '4,4', '8,8', '6,6',
            '11111111000000000000000000000000,11111111100000001000000010000000',
            'a0a0a0a0a0a0,a1a1a1a1a1a1']
        assert [len(v) // 2 for v in t[2]['nvme.cmd.get_logpage.eom.desc.rsvd1'].split(',')] == [
            12, 12]
        # EOMIP 0h: header only.  DOFST 64: neither ND nor DS, so no walk,
        # and the skip is reported.
        assert row(4, 'nvme.cmd.get_logpage.eom.lid', 'nvme.cmd.get_logpage.eom.eomip',
                   'nvme.cmd.get_logpage.eom.nd', 'nvme.cmd.get_logpage.eom.desc.ln') == [
            '0x19', '0x00', '0', '']
        assert row(6, 'nvme.cmd.get_logpage.eom.lid', 'nvme.cmd.get_logpage.eom.desc.ln') == [
            '', '']
        assert list(column(t, 'nvme.window_decode_skipped')) == [6]
        # F4 under-delivers a 208-byte request (Base Figure 201, MI Figure 139).
        assert t[4]['_ws.expert.message'] == (
            "NVMe Response Data is 64 bytes, fewer than the 208 bytes the request's"
            " Data Length selected")
        assert list(column(t, 'nvme-mi.admin.short_response')) == [4]
        assert list(column(t, 'nvme-mi.admin.invalid_dlen')) == []
        assert list(column(t, 'nvme-mi.admin.invalid_dofst')) == []
        # PE overruns DS on F8, so neither PE nor ED has an offset; F14 declares
        # neither, which is not an overrun (and DS 32 needs no Padding).
        assert row(8, 'nvme.cmd.get_logpage.eom.desc.ln', *desc) == ['0', '8', '8', '6', '', '']
        assert row(14, *desc, 'nvme.cmd.get_logpage.eom.desc.pad') == [
            '0', '0', '0', '', '', '']
        assert list(column(t, 'nvme.cmd.get_logpage.eom.desc_field_overrun')) == [8]
        # A partial window (F10) and a prefix read of a larger log (F12) both
        # stop at the data's end without a warning (Base 2.3 Figures 202/203).
        assert not [n for n, m in column(t, '_ws.expert.message').items()
                    if 'Number of Descriptors exceeds' in m]
        assert t[10]['_ws.malformed.expert'] == t[12]['_ws.malformed.expert'] == ''
        assert t[10]['nvme.cmd.get_logpage.eom.desc.ln'] == '0'
        assert t[12]['nvme.cmd.get_logpage.eom.desc.ln'] == '0,1'
        # Padding stops at the Dword boundary; what DS leaves past it is shown.
        assert row(18, 'nvme.cmd.get_logpage.eom.desc.pad',
                   'nvme.cmd.get_logpage.eom.desc.undefined') == ['0000', 'de' * 8]
        assert t[20]['nvme.cmd.get_logpage.eom.desc.pad'] == '00a5'
        # The descriptor list starts at HSIZE (PCIe Transport 1.4 Figure 74),
        # which Figure 75 requires to be 64: F22's 72 is followed and reported,
        # F24's 32 would overlap the header, so its list is not walked.
        assert row(22, 'nvme.cmd.get_logpage.eom.hsize', 'nvme.cmd.get_logpage.eom.desc.ln',
                   'nvme.cmd.get_logpage.eom.desc.eye', *desc) == [
            '72', '0', '0', '4', '8', '6', '11111111000000000000000000000000', 'a0a0a0a0a0a0']
        assert t[22]['_ws.expert.message'] == (
            'Header Size is not 64 (NVMe over PCIe Transport 1.4 Figure 75)')
        assert row(24, 'nvme.cmd.get_logpage.eom.hsize', 'nvme.cmd.get_logpage.eom.nd',
                   'nvme.cmd.get_logpage.eom.desc.ln') == ['32', '1', '']
        assert t[24]['_ws.expert.message'] == (
            'Header Size 32 is smaller than the 64-byte EOM Header (NVMe over PCIe'
            ' Transport 1.4 Figure 75); the descriptor list is not decoded')
        # CDW10 LSP is ACT 11:10 / MQUAL 09:08 (Figure 72) on every request;
        # only F15's LSP 06h tells the two slices apart.
        lsp = {n: row(n, 'nvme.cmd.get_logpage.dword10.lsp.act',
                      'nvme.cmd.get_logpage.dword10.lsp.mqual')
               for n in column(t, 'nvme.cmd.get_logpage.dword10.lsp.act')}
        assert list(lsp) == list(range(1, 24, 2))
        assert lsp.pop(15) == ['0x00000001', '0x00000002']
        assert all(v == ['0x00000000', '0x00000000'] for v in lsp.values()), lsp

    def test_labels_and_extents(self, dissect_pdml):
        p = pdml_section(dissect_pdml(self.FILE), self.SPAN)

        def label(frame, name):
            return p.field(frame, name)['showname']

        # Padding is DS minus the 70-byte body, at the end of each descriptor.
        descs = p.fields(2, 'nvme.cmd.get_logpage.eom.desc')
        pads = p.fields(2, 'nvme.cmd.get_logpage.eom.desc.pad')
        assert [(d.get('size'), a.get('size'), int(a.get('pos')) - int(d.get('pos')))
                for d, a in zip(descs, pads)] == [('72', '2', 70)] * 2
        assert len(pads) == 2
        # LSPFV (the header's copy of LSP) and CDW10's LSP name ACT/MQUAL.
        assert p.field(2, 'nvme.cmd.get_logpage.eom.lspfc.lspfv.act')['show'] == '0x00'
        assert p.field(2, 'nvme.cmd.get_logpage.eom.lspfc.lspfv.mqual')['show'] == '0x01'
        for frame, name, tail in (
                (2, 'nvme.cmd.get_logpage.eom.lspfc.lspfv.act',
                 'Action (ACT): Read Log Data (0x0)'),
                (2, 'nvme.cmd.get_logpage.eom.lspfc.lspfv.mqual',
                 'Measurement Quality (MQUAL): Better (0x1)'),
                (1, 'nvme.cmd.get_logpage.dword10.lsp.act', 'Action (ACT): Read Log Data (0x0)'),
                (1, 'nvme.cmd.get_logpage.dword10.lsp.mqual',
                 'Measurement Quality (MQUAL): Good (0x0)'),
                (15, 'nvme.cmd.get_logpage.dword10.lsp.act',
                 'Action (ACT): Start Measurement and Read Log Data (0x1)'),
                (15, 'nvme.cmd.get_logpage.dword10.lsp.mqual',
                 'Measurement Quality (MQUAL): Best (0x2)')):
            assert label(frame, name).endswith(tail), (frame, name, label(frame, name))


class TestNvmeMiDiscoveryIndexTsas:
    """An indexed Discovery entry read whole and as DOFST 0 and 512 windows."""

    FILE = 'nvme-mi-admin-logpage.pcapng'
    SECTION = 9
    RCRD = 'nvme.cmd.get_logpage.identify.rcrd'
    FIELDS = (RCRD + '.trtype', RCRD + '.portid', RCRD + '.tsas', RCRD + '.tsas.tcp_sectype')

    def test_tsas_per_transaction(self, fields_table):
        t = section(fields_table(self.FILE, self.FIELDS), self.SPAN)
        assert {n: (row[self.RCRD + '.trtype'], row[self.RCRD + '.portid'],
                    bool(row[self.RCRD + '.tsas']), row[self.RCRD + '.tsas.tcp_sectype'])
                for n, row in t.items() if n % 2 == 0} == {
            2: ('0x03', '0x4001', True, '0x02'),
            4: ('0x03', '0x4001', False, ''),
            6: ('', '', True, '')}


class TestNvmeMiAdminSecuritySelectors:
    """Security Send/Receive Command Dword 10/11 selectors."""

    FILE = 'nvme-mi-security.pcapng'
    SECTION = 1

    def test_selectors(self, fields_table):
        t = section(fields_table(self.FILE, (
            'nvme.cmd.security.dword10.secp', 'nvme.cmd.security.dword10.spsp1',
            'nvme.cmd.security.dword10.spsp0', 'nvme.cmd.security.dword10.nssf',
            'nvme.cmd.security_send.dword11.tl', 'nvme.cmd.security_recv.dword11.al')), self.SPAN)
        secp = set(column(t, 'nvme.cmd.security.dword10.secp').values())
        assert secp and secp <= {'0x00000000', '0x00000001', '0x00000002'}
        # ComID 1000h: SPSP1 is ComID 15:8, SPSP0 7:0 (TCG SIIS 1.20 Tables 23/24).
        assert [t[5][n] for n in ('nvme.cmd.security.dword10.secp',
                                  'nvme.cmd.security.dword10.spsp1',
                                  'nvme.cmd.security.dword10.spsp0',
                                  'nvme.cmd.security.dword10.nssf')] == [
            '0x00000001', '0x00000010', '0x00000000', '0x00000000']
        # Dword 11 is Transfer Length on Send and Allocation Length on Receive
        # (Figures 399/395); exactly one appears per command.
        lengths = [(r['nvme.cmd.security_send.dword11.tl'], r['nvme.cmd.security_recv.dword11.al'])
                   for r in t.values()
                   if r['nvme.cmd.security_send.dword11.tl'] or r['nvme.cmd.security_recv.dword11.al']]
        assert lengths and all(bool(tl) != bool(al) for tl, al in lengths), lengths


class TestNvmeMiTcgComidMgmt:
    """SECP 02h ComID management response bodies (TCG Core 2.01 3.3.4.7)."""

    FILE = 'nvme-mi-security.pcapng'
    SECTION = 5

    def test_field_values(self, fields_table):
        t = section(fields_table(self.FILE, (
            'nvme-mi', '_ws.expert', '_ws.expert.message', '_ws.col.info',
            'nvme-mi.admin.dlen', 'nvme.cmd.security_recv.dword11.al', 'nvme-mi.admin.data_excess',
            'tcg-storage.comid_mgmt.comid_state', 'tcg-storage.comid_mgmt.time_allocated',
            'tcg-storage.comid_mgmt.time_expiry', 'tcg-storage.comid_mgmt.time_since_reset',
            'tcg-storage.comid_mgmt.date.year', 'tcg-storage.comid_mgmt.date.month',
            'tcg-storage.comid_mgmt.available_data_length',
            'tcg-storage.comid_mgmt.stack_reset_result', 'tcg-storage.comid_mgmt.data',
            'tcg-storage.padding', 'tcg-storage.comid_mgmt.request_code')), self.SPAN)

        def row(frame, *names):
            return [t[frame][n] for n in names]

        result = ('tcg-storage.comid_mgmt.available_data_length',
                  'tcg-storage.comid_mgmt.stack_reset_result', 'tcg-storage.comid_mgmt.data',
                  'tcg-storage.padding')
        assert list(column(t, 'nvme-mi')) == list(range(1, 17))
        # Consecutive 10-byte dates; the last is all zero (no real-time clock).
        assert row(2, 'tcg-storage.comid_mgmt.comid_state',
                   'tcg-storage.comid_mgmt.time_allocated', 'tcg-storage.comid_mgmt.time_expiry',
                   'tcg-storage.comid_mgmt.time_since_reset',
                   'tcg-storage.comid_mgmt.date.year', 'tcg-storage.comid_mgmt.date.month') == [
            '0x00000003', '07e8030f0c220501f400', '07e90102030405000600',
            '00000000000000000000', '2024,2025,0', '3,1,0']
        # Pending has no result word, even with bytes after the header (F14);
        # those are padding, not response data.
        assert row(4, *result) == ['0', '', '', '']
        assert row(6, *result)[:2] == ['4', '0x00000000']
        assert row(14, *result) == ['0', '', '', 'deadbeef']
        # A probe declares 4 and carries none of it (3.3.4.7.2 probe-then-
        # refetch): normal, not truncated.
        assert row(7, 'nvme-mi.admin.dlen', 'nvme.cmd.security_recv.dword11.al') == [
            '0x0000000c', '12']
        assert row(8, *result)[:3] == ['4', '', '']
        # Under-declared (F10) is truncated; over-declared (F16) keeps the
        # mandated prefix and the excess as declared data.
        assert row(10, 'tcg-storage.comid_mgmt.available_data_length', 'tcg-storage.padding') == [
            '2', '0000']
        assert 'TCG Storage structure truncated' in t[10]['_ws.expert.message']
        assert row(16, *result) == ['8', '0x00000000', 'a1a2a3a4', '']
        assert t[12]['tcg-storage.comid_mgmt.request_code'] == '0x00000000'
        assert 'No Response Available' in t[12]['_ws.col.info']
        assert 'Unknown request code' not in t[12]['_ws.col.info']
        # Only the under-declared length carries an expert.
        assert list(column(t, '_ws.expert')) == [10]
        assert column(t, 'nvme-mi.admin.data_excess') == {}

    def test_responses_carry_their_dlen(self, fields_table):
        t = section(fields_table(self.FILE, ('nvme-mi.ror', 'nvme-mi.admin.data'), two_pass=True), self.SPAN)
        assert [(n, len(r['nvme-mi.admin.data'].split())) for n, r in t.items()
                if r['nvme-mi.ror'] == 'True'] == [
            (2, 48), (4, 12), (6, 16), (8, 12), (10, 16), (12, 12), (14, 16), (16, 20)]


class TestNvmeMiSecurityWindowed:
    """Security Send/Receive transfers under a Data Offset."""

    FILE = 'nvme-mi-security.pcapng'
    SECTION = 3

    def test_field_values(self, fields_table):
        t = section(fields_table(self.FILE, (
            'nvme-mi', '_ws.malformed', '_ws.expert.message', 'tcg-storage',
            'nvme-mi.admin.invalid_dlen', 'nvme-mi.admin.invalid_dofst',
            'nvme-mi.admin.data', 'nvme.cmd.security.data', 'nvme.cmd.security_send.dword11.tl')), self.SPAN)
        assert list(column(t, 'nvme-mi')) == list(range(1, 7))
        assert column(t, '_ws.malformed') == {}
        assert list(column(t, 'nvme-mi.admin.invalid_dlen')) == [3]
        # None is eligible for TCG dispatch: mid-structure bytes, or a partial
        # first window that would parse as a ComPacket with a made-up length.
        assert column(t, 'tcg-storage') == {}
        assert t[2]['nvme.cmd.security.data'] == (
            '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f')
        assert t[2]['_ws.expert.message'] == ''
        assert [t[3][n] for n in ('nvme-mi.admin.data', 'nvme.cmd.security_send.dword11.tl')] == [
            '80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f', '64']
        assert 'Data Length 0 is shorter than the 16-byte' in t[3]['_ws.expert.message']
        # F5 stays raw and reports that DOFST is invalid on Security Send.
        assert t[5]['nvme-mi.admin.data'] != ''
        assert 'Data Offset 32 is nonzero' in t[5]['_ws.expert.message']
        assert list(column(t, 'nvme-mi.admin.invalid_dofst')) == [5]

    @pytest.mark.parametrize('span', ((1, 24), (41, 42)))
    def test_conformant_sends_are_silent(self, fields_table, span):
        """Conformant Security Send/Receive sections raise no DLEN diagnostic that
        says the data is shorter (span 1-24 has F1, whose DLEN is not dword-aligned)."""
        t = section(fields_table(self.FILE, ('nvme-mi.admin.invalid_dlen',
                                             '_ws.expert.message')), span)
        assert [n for n, r in t.items() if r['nvme-mi.admin.invalid_dlen']
                and 'shorter than' in r['_ws.expert.message']] == []


class TestNvmeMiTcgConformance:
    """TCG Core/SIIS grammar, transfer windows and state boundaries."""

    FILE = 'nvme-mi-tcg.pcapng'
    SECTION = 2
    COUNT = 235
    MI_COUNT = 218
    SENDS = frozenset({1, 7, 151, 159, 163, 169, 173, 179, 197, 199})
    NO_TCG_RESP = frozenset({2, 8, 10, 12, 14, 16, 18, 22, 24, 152, 160,
                             164, 170, 174, 180, 198, 200, 216, 218})
    # Window-clipped leaves whose declared Length the version forbids.
    BAD_LEAF_LENGTH = frozenset({64, 70, 78})
    CENSUS = (
        ('tcg-storage.length_overrun', {28, 30, 44}),
        # F64 declares an Opal SSC V2 Version 1 Length of 12, not 0x10 (Opal
        # SSC 2.01 Table 7), F70 a Pyrite SSC V2.00 Version 1 Length of 12,
        # not 0x10 (Pyrite SSC 2.01 Table 6), and F78 a Data Removal
        # Mechanism Version 1 Length of 4, not 0x20 (Pyrite SSC 2.01
        # Table 7), whatever the window delivers.
        ('tcg-storage.l0.feat.invalid_length', {34, 38, 64, 70, 78}),
        # F32/F46/F48-F78 are fulfilled MI DLEN<AL selections and F232 a
        # non-final NVMe/TCP PDU; each is a legal Level 0 prefix, not short.
        ('tcg-storage.transfer_short', set()),
        ('tcg-storage.tok.zero_length', set(range(92, 114, 2))),
        ('tcg-storage.tok.status_type', set(range(114, 124, 2))),
        ('tcg-storage.tok.delimiter', {128, 130, 132, 134, 204}),
    )

    def table(self, fields_table):
        return section(fields_table(self.FILE, (
            'nvme-mi', 'tcg-storage', 'frame.protocols', '_ws.expert', '_ws.col.info',
            '_ws.malformed', '_ws.malformed.expert',
            'nvme.data.wrong_direction', 'nvme-mi.admin.invalid_dlen',
            'nvme-mi.admin.invalid_dofst', 'nvme-mi.admin.unexpected_response_data',
            'nvme.security.invalid_length', '_ws.expert.message',
            'nvme-mi.admin.data', 'nvme.cmd.security.data',
            'tcg-storage.tok.uid', 'tcg-storage.tok.status', 'tcg-storage.packet.secure_data',
            *(name for name, _ in self.CENSUS))), self.SPAN)

    def test_layers_and_unique_protocol_nodes(self, fields_table, dissect_pdml):
        t = self.table(fields_table)
        expected = ((set(range(2, self.MI_COUNT + 1, 2)) - self.NO_TCG_RESP)
                    | self.SENDS | {220, 224, 230, 232})
        assert list(column(t, 'nvme-mi')) == list(range(1, self.MI_COUNT + 1))
        assert set(column(t, 'tcg-storage')) == expected
        assert {n for n, r in t.items() if 'tcg-storage' in r['frame.protocols']} == expected
        p = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        assert len(p.packets) == self.COUNT
        for number, packet in p.packets.items():
            assert len(packet.findall(".//proto[@name='tcg-storage']")) == (number in expected)

    def test_direction_and_length_censuses(self, fields_table):
        t = self.table(fields_table)
        for field, expected in (
                # F8's Security Send Response Data is flagged and left raw
                # (Base 2.4 Figure 92); F13's DLEN 20 is not its TL 16.
                # F17/F23 select past the SECP 01h AL (SIIS 1.20 Table 24).
                ('nvme.data.wrong_direction', {5, 234, 235}),
                ('nvme-mi.admin.unexpected_response_data', {8}),
                ('nvme-mi.admin.invalid_dlen', {9, 11, 13, 17, 20, 215}),
                ('nvme-mi.admin.invalid_dofst', {11, 15, 23}),
                ('nvme.security.invalid_length', {18, 24, 222, 228})):
            assert set(column(t, field)) == expected, field
        assert {n for n, r in t.items() if n <= 24 and not r['tcg-storage']
                and (r['nvme-mi.admin.data'] or r['nvme.cmd.security.data'])} == {
            5, 8, 9, 11, 13, 15, 18, 22, 24}
        assert t[218]['nvme.cmd.security.data'] != ''
        assert (t[218]['tcg-storage'], t[218]['_ws.expert']) == ('', '')

    def test_tcg_expert_censuses(self, fields_table, dissect_pdml):
        t = self.table(fields_table)
        census = dict(self.CENSUS)
        for field, expected in census.items():
            assert set(column(t, field)) == expected, field
        malformed = set.union(*census.values())
        assert set(column(t, '_ws.malformed')) == malformed
        assert set(column(section(fields_table(self.FILE, ('_ws.malformed',), two_pass=True), self.SPAN),
                          '_ws.malformed')) == malformed
        assert column(t, '_ws.malformed.expert') == {}
        expected_counts = {frame: 1 for frames in census.values() for frame in frames}
        for frame in (5, 8, 9, 11, 13, 17, 18, 20, 23, 24, 140, 215, 222, 228,
                      234, 235):
            expected_counts[frame] = 1
        expected_counts[5] = 2  # Security Receive Request Data: the Warning and the direction Note.
        expected_counts.update({11: 2, 15: 1})
        p = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        assert {n: len(p.experts(n)) for n in p.packets if p.experts(n)} == expected_counts

    def test_level0_prefix_and_parent_extents(self, assert_frames_match, dissect_pdml):
        assert_frames_match(self.FILE, at(self.SPAN, [
            (26, '!_ws.expert && !tcg-storage.l0.feat'),
            (32, 'tcg-storage.l0.feat.length == 12 && !tcg-storage.truncated'),
            (36, '!_ws.expert && tcg-storage.l0.feat.length == 12'),
            (40, '!_ws.expert && tcg-storage.l0.feat.locking.flags == 3'),
            (42, '!_ws.expert && tcg-storage.padding'),
            (44, 'tcg-storage.length_overrun && !tcg-storage.l0.feat.locking.flags'),
        ]))
        p = pdml_section(dissect_pdml(self.FILE), self.SPAN)

        def parents(packet):
            return {child: parent for parent in packet.iter() for child in parent}

        for frame, anchors in (
                (28, {'tcg-storage.packet.length'}),
                (30, {'tcg-storage.subpacket.length'}),
                (44, {'tcg-storage.l0.feat.length'})):
            up = parents(p[frame])
            assert {up[e].get('name') for e in p.fields(frame, '_ws.expert')
                    if e.find(".//field[@name='tcg-storage.length_overrun']") is not None
                    } == anchors
        # Legal selected/non-final prefixes keep their clipped feature
        # raw (no invented leaf values) and carry no transfer diagnosis.
        for frame in (32, 46, *range(48, 80, 2), 232):
            # Only a declared Length that the version forbids is flagged.
            assert len(p.fields(frame, '_ws.expert')) == (frame in self.BAD_LEAF_LENGTH), frame
            assert p.fields(frame, 'tcg-storage.level0_discovery'), frame
            assert not p.fields(frame, 'tcg-storage.l0.feat.locking.flags'), frame
        for frame in (32, 232):
            assert [n.get('show') for n in p.fields(frame, 'tcg-storage.l0.feat.code')] == \
                ['0x0001', '0x0002'], frame
            assert p.field(frame, 'tcg-storage.l0.feat.tper.flags')['show'] == '0x41'
        # The invalid Level 0 length is anchored on its own byte, also when the
        # frame is redissected alone.
        selected = pdml_section(dissect_pdml(self.FILE, two_pass=True, dfilter=f'frame.number in {{{frame_in(self.SPAN, 34)}, {frame_in(self.SPAN, 38)}}}'),
            self.SPAN)
        for packet in (p[34], p[38], selected[34], selected[38]):
            base = int(packet.find(".//proto[@name='tcg-storage']").get('pos'))
            expert, = packet.findall(".//field[@name='_ws.expert']")
            assert expert.find("./field[@name='tcg-storage.l0.feat.invalid_length']") is not None
            assert int(expert.find("./field[@name='_ws.expert.group']").get('show')) == 0x7000000
            assert int(expert.find("./field[@name='_ws.expert.severity']").get('show')) == 0x600000
            length = parents(packet)[expert]
            assert length.get('name') == 'tcg-storage.l0.feat.length'
            assert (int(length.get('pos')) - base, int(length.get('size'))) == (67, 1)
        for frame, field, size in ((42, 'tcg-storage.level0_discovery', '80'),
                                   (42, 'tcg-storage.padding', '16'),
                                   (196, 'tcg-storage.compacket', '20'),
                                   (196, 'tcg-storage.padding', '12'),
                                   (20, 'tcg-storage.compacket', '20')):
            assert p.field(frame, field)['size'] == size, (frame, field)
        for frame, field, size in (
                (5, 'nvme-mi.admin.data', '20'), (8, 'nvme-mi.admin.data', '20'),
                (9, 'nvme-mi.admin.data', '20'), (11, 'nvme-mi.admin.data', '20'),
                (13, 'nvme-mi.admin.data', '20'), (15, 'nvme-mi.admin.data', '20'),
                (18, 'nvme.cmd.security.data', '24'), (24, 'nvme.cmd.security.data', '20')):
            assert any(n.get('size') == size and n.get('hide') != 'yes'
                       for n in p.fields(frame, field)), (frame, field)
        assert any(n.get('size') == '4' and n.get('hide') != 'yes' and n.get('value') == 'fafafafa'
                   for n in p.fields(20, 'nvme-mi.admin.data_excess'))

    def test_status_domain_direction_and_atom_extents(self, assert_frames_match, dissect_pdml):
        assert_frames_match(self.FILE, at(self.SPAN, [
            (1, 'tcg-storage.tok.host_status == 0 && !tcg-storage.tok.status'),
            (4, 'tcg-storage.tok.status == 0 && !tcg-storage.tok.host_status'),
            (80, 'tcg-storage.tok.status == 0x0d && !_ws.expert'),
            (82, 'tcg-storage.tok.status == 0x13 && !_ws.expert'),
            (84, 'tcg-storage.tok.status == 0x14 && !_ws.expert'),
            (86, 'tcg-storage.tok.status == 0x1234 && !_ws.expert'),
            (88, 'tcg-storage.tok.status == 0x100000001 && !_ws.expert'),
            *[(frame, '!tcg-storage.tok.status') for frame in range(114, 124, 2)],
        ]))
        p = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        for frame, name in ((80, 'OBSOLETE'), (82, 'INCOMPATIBLE_MBR_FORMAT'),
                            (84, 'WP_DATA_REMAIN')):
            status = p.field(frame, 'tcg-storage.tok.status')
            assert name in status['showname']
            assert status['size'] == '9'  # full short-atom header + 8-byte value
        assert p.field(212, 'tcg-storage.tok.status')['size'] == '12'  # long atom, not clamped

    def test_stream_reassembly_and_session_isolation(self, assert_frames_match, fields_table):
        assert_frames_match(self.FILE, at(self.SPAN, [
            *[(frame, ('count(tcg-storage.tok.uid) == 2 && tcg-storage.tok.status == 0'
                       ' && !_ws.expert')) for frame in (136, 138)],
            # This endpoint's Level 0 reports Async Supported = 0 (Core
            # 3.3.6.4.2), so F140's atom cannot complete after its ComPacket
            # (3.3.10.3(a)) and its regular session is aborted in both
            # directions (F148, F151, F154); F204 starts on a fresh stream.
            # Their no-evidence twins are the TCG suite's final-corrective
            # F255-F272.
            (140, ('tcg-storage.tok.spans_compacket && tcg-storage.data == a8:00:00:00:00'
                  ' && !tcg-storage.tok.fragment && !tcg-storage.tok.uid')),
            *[(frame, ('tcg-storage.data && !tcg-storage.subpacket && !_ws.expert'
                      ' && _ws.col.info contains "atom spanning a synchronous ComPacket"'))
              for frame in (148, 151, 154)],
            *[(frame, 'tcg-storage.tok.uint == 1 && !tcg-storage.tok.uid && !_ws.expert')
              for frame in (142, 144, 146, 150)],
            (156, ('tcg-storage.tok.bytes == '
                   '00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13'
                   ' && !_ws.expert')),
            (158, 'tcg-storage.tok.uint == 0x1234 && !_ws.expert'),
            (202, '!tcg-storage.tok.status && !_ws.expert'),
            (204, '!tcg-storage.tok.status && tcg-storage.tok.delimiter'),
            (206, 'tcg-storage.tok.uint == 1 && tcg-storage.tok.uint == 2 && !_ws.expert'),
            *[(frame, ('count(tcg-storage.tok.uid) == 2'
                       ' && tcg-storage.tok.bytes == 00:00:02:05:00:00:00:01'
                       ' && !(tcg-storage.tok.uid == 0x0000020500000001)')) for frame in (1, 126)],
        ]))
        t = self.table(fields_table)
        for frame in (124, 210, 214):
            assert (t[frame]['tcg-storage.tok.uid'], t[frame]['tcg-storage.tok.status']) == (
                '', ''), frame

    def test_secure_payload_requires_observed_keys(self, fields_table, assert_frames_match):
        assert list(column(self.table(fields_table), 'tcg-storage.packet.secure_data')) == [
            168, 179, 182]
        assert_frames_match(self.FILE, at(self.SPAN, [
            *[(frame, ('tcg-storage.packet.secure_data && !tcg-storage.subpacket'
                       ' && !tcg-storage.tok.uid && !_ws.expert')) for frame in (168, 179, 182)],
            *[(frame, 'tcg-storage.subpacket && tcg-storage.tok.uid && !_ws.expert')
              for frame in (178, 184, 186)],
        ]))

    def test_empty_compacket_direction_and_reserved_extents(self, fields_table, dissect_pdml):
        t = self.table(fields_table)
        selected = pdml_section(dissect_pdml(self.FILE, two_pass=True,
                                dfilter='frame.number in {' + ', '.join(
                                    str(frame_in(self.SPAN, n))
                                    for n in (188, 190, 192, 194, 196, 197, 199)) + '}'),
                   self.SPAN)
        for frame, text in ((188, 'inactive ComID'), (190, 'no pending response data'),
                            (192, 'response being prepared'),
                            (194, 'response available; allocation too small'),
                            (196, 'inactive ComID'), (197, 'empty ComPacket'),
                            (199, 'empty ComPacket')):
            assert text in t[frame]['_ws.col.info'], frame
            assert text in selected.field(frame, 'tcg-storage.compacket')['showname'], frame
        reserved = selected.fields(197, 'tcg-storage.compacket.reserved')
        assert [(f.get('size'), f.get('value')) for f in reserved] == [
            ('4', '00000000'), ('4', '11223344'), ('4', '55667788')]
        assert selected.fields(197, 'tcg-storage.compacket.outstanding') == []
        assert selected.fields(197, 'tcg-storage.compacket.min_transfer') == []


class TestNvmeMiCommandContracts:
    """Minimal MI command contracts, unknown MEB routing and correlated revisits."""

    FILE = 'nvme-mi-mi-commands.pcapng'
    SECTION = 3
    EXPERTS = (
        ('nvme-mi.mi.request_data_length', [1, 5, 9]),
        ('nvme-mi.mi.ae_list_invalid', [21, 24, 31]),
        ('nvme-mi.mi.ae.aeetl_mismatch', [17, 112]),
        ('nvme-mi.mi.truncated', [40, 67, 69, 82, 85, 88, 91, 94]),
        # Missing Response Data (F64-F76), then Figure 65 lengths.
        ('nvme-mi.mi.response_data_length',
         [64, 68, 72, 76, 81, 83, 84, 86, 87, 89, 90, 92, 93, 95]),
        ('nvme-mi.mi.aes.field_invalid', [24]),
    )
    OPCODE_NAMES = (
        (52, ['Reserved']), (54, ['Get LBA Status']), (56, ['Get LBA Status']),
        (58, ['Reserved']), (60, ['Identify', 'VPD Write']), (62, ['Load Program']),
    )
    # Figure 65's Composite Temperature info is one byte.
    SPECIFIC_LENGTH_COUNTS = (
        (81, 4), (83, 4), (84, 3), (86, 3), (87, 2), (89, 2), (90, 2), (92, 2), (93, 1), (95, 1),
    )
    # Reserved AESS 6h is a Note (NVMe-MI 2.2 Figure 62), not malformed.
    RESERVED_SCOPE = (93, 95)
    TRUNCATED = (40, 67, 69, 82, 85, 88, 91, 94)
    NO_ENABLE_LIST = ('Configuration Set (Asynchronous Event) omits the AE Enable'
                      ' List (NVMe-MI section 5.2.4)')

    def check_opcode_names(self, p):
        for frame, names in self.OPCODE_NAMES:
            fields = p.fields(frame, 'nvme-mi.mi.cmdlist.opc')
            assert len(fields) == len(names), frame
            assert all(f.get('showname').endswith(f'({name})') for f, name in zip(fields, names))

    def test_contracts(self, dissect_pdml):
        p = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        specific = dict(self.SPECIFIC_LENGTH_COUNTS)
        assert len(p.packets) == 113
        expected_counts = Counter()
        for field, frames in self.EXPERTS:
            assert p.frames_with(field) == frames, field
            expected_counts.update(frames)
        # One Figure 65 length expert per occurrence, not per frame.
        expected_counts.update({frame: count - 1 for frame, count in specific.items()})
        expected_counts.update(self.RESERVED_SCOPE)
        actual_counts = {}
        for number, packet in p.packets.items():
            experts = packet.findall(".//field[@name='_ws.expert']")
            if experts:
                actual_counts[number] = len(experts)
            for expert in experts:
                message = expert.find("./field[@name='_ws.expert.message']").get('show')
                severity = int(expert.find("./field[@name='_ws.expert.severity']").get('show'))
                group = int(expert.find("./field[@name='_ws.expert.group']").get('show'))
                if 'AE Occurrence Scope 0x6 is Reserved' in message:
                    assert number in self.RESERVED_SCOPE
                    assert (severity, group) == (0x400000, 0x9000000)  # Note, Protocol
                    continue
                if "shall be set to 3h (NVMe-MI 'AE Supported Data Structure')" in message:
                    assert (severity, group) == (0x600000, 0x9000000)  # Warning, Protocol
                    continue
                if 'should equal AEELHL plus the AE Enable entries' in message:
                    assert number in (17, 112)
                    assert message == ('AEETL 12 should equal AEELHL plus the AE Enable'
                                       " entries, 8 bytes (NVMe-MI 'AE Enable List Data Structure')")
                    assert (severity, group) == (0x400000, 0x9000000)  # Note, Protocol
                    continue
                if number in self.TRUNCATED[1:]:
                    assert message == self.NO_ENABLE_LIST
                assert severity == (0x600000 if number in self.TRUNCATED else 0x800000), message
                assert group == 0x7000000  # PI_MALFORMED
        assert actual_counts == dict(expected_counts)
        assert Counter(n for n in p.packets for m in p.fields(n, '_ws.expert.message')
                       if 'Specific Info bytes for AE' in m.get('show')) == specific

        # Adjacent list sizes, both decoded in full: NUMCMD is a 16-bit count
        # and NVMe-MI 2.2 states no maximum for it, so neither frame is diagnosed.
        for frame, count in ((36, 2048), (38, 2047)):
            assert [f.get('show') for f in p.fields(frame, 'nvme-mi.mi.cmdlist.numcmd')] == [
                str(count)]
            assert len(p.fields(frame, 'nvme-mi.mi.cmdlist.opc')) == count
        self.check_opcode_names(p)
        # Repeated occurrences each decode their own Unique ID.
        for frame, count in ((81, 4), (83, 4), (87, 2), (89, 2)):
            assert len(p.fields(frame, 'nvme-mi.mi.aeo.aeoui')) == count
        for frame in (93, 95):
            assert 'Reserved' in p.field(frame, 'nvme-mi.mi.aeo.aess')['showname']
        for frame in (27, 30, 96, 98):
            assert p.field(frame, 'nvme-mi.mi.data')['value'] == 'a5'
        assert [p.field(46, 'nvme-mi.mi.cmdlist.rsvd_high')['show'],
                p.field(46, 'nvme-mi.mi.cmdlist.rsvd_low')['show']] == ['0x01', '0x07']

    def test_unknown_meb_routing(self, fields_table):
        """Missing capabilities cannot turn MEB=1 into an inline contract."""
        fields = ('nvme-mi.mi.data_routing', 'nvme-mi.mi.opcode', 'nvme-mi.response_to',
                  'nvme-mi.meb', 'nvme-mi.mi.cdw1', 'nvme-mi.mi.rds.rdl', 'nvme-mi.mi.data',
                  'nvme-mi.mi.vpd.data', '_ws.expert')
        t = section(fields_table(self.FILE, fields), self.SPAN)
        expected = {}
        for request, opcode in ((104, 6), (106, 9), (108, 4), (110, 0), (112, 3)):
            # AE Enable Request Data is always inline; its response is not.
            expected[request] = ['1' if request == 112 else '0', f'0x{opcode:02x}', '', 'True',
                                 '0x00000008' if request in (104, 106) else '0x00000000',
                                 '', '', '']
            expected[request + 1] = ['0', f'0x{opcode:02x}', str(request), 'False', '',
                                     '2' if request == 110 else '', '', '']
        assert {n: [r[f] for f in fields[:-1]] for n, r in t.items() if n >= 104} == expected
        assert [n for n, v in column(t, '_ws.expert').items() if n >= 104] == [112]

    def test_correlated_response_revisit(self, dissect_pdml):
        """IOCSI and Config Set dispatch must survive request redissection."""
        frames = (52, 54, 56, 58, 60, 62, 64, 68, 72, 76, 83, 86, 89, 92, 95)
        p = pdml_section(dissect_pdml(self.FILE, two_pass=True,
                         dfilter=to_capture(self.SPAN, 'frame.number in {' + ', '.join(map(str, frames)) + '}')), self.SPAN)
        assert sorted(p.packets) == list(frames)
        self.check_opcode_names(p)
        specific = dict(self.SPECIFIC_LENGTH_COUNTS)
        for frame in frames:
            assert len(p.experts(frame)) == (
                {64: 1, 68: 1, 72: 1, 76: 1}.get(frame, 0)
                + specific.get(frame, 0)
                + (frame in self.RESERVED_SCOPE)), frame


class TestNvmeMiAeListMalformed:
    """The AE Enable and AE Supported Lists share one walker (MI 2.2 Figures 82/83, 91/92)."""

    FILE = 'nvme-mi-mi-commands.pcapng'
    SECTION = 5

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_field_values(self, fields_table, two_pass):
        t = section(fields_table(self.FILE, (
            'nvme-mi', '_ws.malformed.expert', '_ws.expert.message',
            'nvme-mi.mi.ae_list_invalid', 'nvme-mi.mi.aes.field_invalid',
            'nvme-mi.mi.ae.aeetl_mismatch', 'nvme-mi.mi.ae.numaee', 'nvme-mi.mi.ae.aeetl', 'nvme-mi.mi.ae.aeelhl',
            'nvme-mi.mi.ae.aeel', 'nvme-mi.mi.ae.id', 'nvme-mi.mi.ae.aeelver',
            'nvme-mi.mi.aes.numaes', 'nvme-mi.mi.aes.aestl', 'nvme-mi.mi.aes.aeslhl',
            'nvme-mi.mi.aes.aesl', 'nvme-mi.mi.aes.id', 'nvme-mi.mi.aes.aeslver',
            'nvme-mi.mi.config.aeelver', 'nvme-mi.mi.status', 'nvme-mi.mi.aeo.numaeo',
            'nvme-mi.mi.aeo.aeoltl', 'nvme-mi.mi.aeo.aeolhl', 'nvme-mi.mi.aeo.aemti',
            'nvme-mi.mi.aeo.aeoi', 'nvme-mi.mi.aeo.aess', 'nvme-mi.mi.aeo.aeosil',
            'nvme-mi.mi.aeo.aeovsil', 'nvme-mi.mi.aeosi.ctv', 'nvme-mi.mi.aeo.entry',
            'nvme-mi.mi.response_data_length'), two_pass=two_pass), self.SPAN)

        def row(frame, *names):
            return [t[frame][n] for n in names]

        enable = ('nvme-mi.mi.ae.numaee', 'nvme-mi.mi.ae.aeetl', 'nvme-mi.mi.ae.aeelhl',
                  'nvme-mi.mi.ae.aeel', 'nvme-mi.mi.ae.id', '_ws.expert.message')
        supported = ('nvme-mi.mi.aes.numaes', 'nvme-mi.mi.aes.aestl', 'nvme-mi.mi.aes.aeslhl',
                     'nvme-mi.mi.aes.aesl', 'nvme-mi.mi.aes.id', '_ws.expert.message')
        assert list(column(t, 'nvme-mi')) == list(range(1, 41))
        # The AE-list expert is PI_MALFORMED, but nothing throws.
        assert column(t, '_ws.malformed.expert') == {}
        # One check after the walk, once per list.  Only counts and lengths
        # that contradict the data present are flagged here.
        assert {n: r['_ws.expert.message'] for n, r in t.items()
                if r['nvme-mi.mi.ae_list_invalid']} == {
            3: list_invalid(0, 1, 'AE Enable', 6, 5, 6),
            6: list_invalid(2, 2, 'AE Supported', 40, 11, 11),
            29: list_invalid(2, 3, 'AE Enable', 11, 11, 11),
            32: list_invalid(2, 3, 'AE Supported', 11, 11, 11),
            33: list_invalid(0, 1, 'AE Enable', 7, 5, 7),
            38: list_invalid(1, 1, 'AE Supported', 6, 8, 8)}
        assert {n: r['_ws.expert.message'] for n, r in t.items()
                if r['nvme-mi.mi.ae.aeetl_mismatch']} == {
            35: ('AEETL 6 should equal AEELHL plus the AE Enable entries, 8 bytes'
                 " (NVMe-MI 'AE Enable List Data Structure')")}
        # Supported List fixed values (Figures 82/83, 'shall') are flagged;
        # the Enable List's 'should' values are not.
        assert {n: r['_ws.expert.message'] for n, r in t.items()
                if r['nvme-mi.mi.aes.field_invalid']} == {
            8: "AESL shall be set to 3h (NVMe-MI 'AE Supported Data Structure')",
            16: "NUMAES shall be 1h or greater (NVMe-MI 'AE Supported List Data Structure')",
            20: "AESLVER shall be cleared to 0h (NVMe-MI 'AE Supported List Data Structure')",
            24: "AESLHL shall be set to 5h (NVMe-MI 'AE Supported List Data Structure')",
            28: "AESL shall be set to 3h (NVMe-MI 'AE Supported Data Structure')"}
        # Controls decode in full and stay silent.
        assert row(9, *enable) == ['2', '11', '5', '3,3', '0x0006,0x0009', '']
        assert row(12, *supported) == ['2', '11', '5', '3,3', '0x0006,0x000b', '']
        # Recovery: a short header is clamped to 5 (F1), no entry is invented
        # (F3), a short entry length still advances by 3 (F8).
        assert row(1, 'nvme-mi.mi.ae.aeelhl', 'nvme-mi.mi.ae.aeel', 'nvme-mi.mi.ae.id') == [
            '3', '3', '0x0006']
        assert row(3, 'nvme-mi.mi.ae.numaee', 'nvme-mi.mi.ae.aeel', 'nvme-mi.mi.ae.id') == [
            '1', '', '']
        assert row(8, 'nvme-mi.mi.aes.numaes', 'nvme-mi.mi.aes.aesl', 'nvme-mi.mi.aes.id') == [
            '1', '1', '0x000b']
        # Enable List "should" values: silent, still decoded.
        assert {n: row(n, 'nvme-mi.mi.ae.numaee', 'nvme-mi.mi.ae.aeelver', 'nvme-mi.mi.ae.aeelhl',
                       'nvme-mi.mi.ae.aeel', '_ws.expert.message') for n in (13, 17, 21, 25)} == {
            13: ['0', '0', '5', '', ''], 17: ['1', '1', '5', '3', ''],
            21: ['1', '0', '7', '3', ''], 25: ['1', '0', '5', '4', '']}
        # Supported List fixed values are still decoded as sent; a longer
        # header really does move the body.
        assert {n: row(n, 'nvme-mi.mi.aes.numaes', 'nvme-mi.mi.aes.aeslver',
                       'nvme-mi.mi.aes.aeslhl', 'nvme-mi.mi.aes.aesl', 'nvme-mi.mi.aes.id')
                for n in (16, 20, 24, 28)} == {
            16: ['0', '0', '5', '', ''], 20: ['1', '1', '5', '3', '0x0006'],
            24: ['1', '0', '7', '3', '0x0006'], 28: ['1', '0', '5', '4', '0x0006']}
        # A shortfall still renders the entries that were sent.
        assert row(29, 'nvme-mi.mi.ae.id', 'nvme-mi.mi.aes.id') == ['0x0006,0x0009', '']
        assert row(32, 'nvme-mi.mi.ae.id', 'nvme-mi.mi.aes.id') == ['', '0x0006,0x000b']
        # Under-declared totals sit inside the data: an error on the
        # Supported List, a Note on the Enable List.
        assert row(35, *enable)[:5] == ['1', '6', '5', '3', '0x0006']
        assert row(38, *supported)[:5] == ['1', '6', '5', '3', '0x0006']
        # Figure 81's AEELVER (response) is decoded beside the list.
        assert row(40, 'nvme-mi.mi.config.aeelver', 'nvme-mi.mi.aes.numaes',
                   'nvme-mi.mi.aes.aestl', 'nvme-mi.mi.aes.id') == ['0x01', '2', '11', '0x0006,0x000b']
        assert [n for n, v in column(t, 'nvme-mi.mi.config.aeelver').items() if int(v, 0) == 0] == [
            6, 8, 12, 16, 20, 24, 28, 32, 38]
        syncs, ack, rejected = (2, 10, 18, 22, 26, 36), 14, (4, 30, 34)
        aeo = ('nvme-mi.mi.status', 'nvme-mi.mi.aeo.numaeo', 'nvme-mi.mi.aeo.aeoltl',
               'nvme-mi.mi.aeo.aeolhl', 'nvme-mi.mi.aeo.aemti', 'nvme-mi.mi.aeo.aeoi',
               'nvme-mi.mi.aeo.aess', 'nvme-mi.mi.aeo.aeosil', 'nvme-mi.mi.aeo.aeovsil',
               'nvme-mi.mi.aeosi.ctv', 'nvme-mi.mi.aeo.entry')
        # 5.2.4 AE Sync: one occurrence for the enabled AE 06h, NVM Subsystem
        # scope, CTV 30 C; Figure 61 AEMTI 0h; minimally sized.
        assert {n: row(n, *aeo) for n in syncs} == {
            n: ['0x00', '1', '17', '7', '0x00', '0x06', '0x02', '1', '0', '30', '1']
            for n in syncs}
        # AEM Ack in the AE Armed State: header only.
        assert row(ack, *aeo) == ['0x00', '0', '7', '7', '0x00', '', '', '', '', '', '']
        # Request Data short of its declared entries: Figure 29 status 06h.
        assert {n: row(n, *aeo) for n in rejected} == {
            n: ['0x06'] + [''] * (len(aeo) - 1) for n in rejected}
        assert not any(t[n]['nvme-mi.mi.response_data_length'] or t[n]['_ws.expert.message']
                       for n in syncs + (ack,) + rejected)

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_set_response_extent(self, dissect_pdml, two_pass):
        """The AEM Ack's AE Occurrence List is header-only (AEOLTL 7h)."""
        p = pdml_section(dissect_pdml(self.FILE, two_pass=two_pass), self.SPAN)
        assert p.field(2, 'nvme-mi.mi.aeo')['size'] == '17'
        assert p.field(14, 'nvme-mi.mi.aeo')['size'] == '7'
        assert p.fields(14, 'nvme-mi.mi.aeo.entry') == []

    def test_pairs_still_link(self, fields_table):
        """Body-level defects leave Command Slot tracking intact."""
        t = section(fields_table(self.FILE, ('nvme-mi.response_in',), two_pass=True), self.SPAN)
        assert {n: int(v) for n, v in column(t, 'nvme-mi.response_in').items()} == {
            n: n + 1 for n in range(1, 40, 2)}

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_management_response_version_is_a_shall(self, dissect_pdml, two_pass):
        """Figure 81's response AEELVER shall be 0h; Figure 91's request
        AEELVER draws no error."""
        p = pdml_section(dissect_pdml(self.FILE, two_pass=two_pass), self.SPAN)
        aeelver = 'nvme-mi.mi.config.aeelver'
        assert p.frames_with(aeelver + '_nonzero') == [40]
        assert [f.get('name') for f in p.fields(40, aeelver)[0].iter('field')] == [
            aeelver, '_ws.expert', aeelver + '_nonzero', '_ws.expert.message',
            '_ws.expert.severity', '_ws.expert.group']
        assert p.experts(40) == [("AEELVER shall be cleared to 0h (NVMe-MI 'Asynchronous Event -"
                                  " NVMe Management Response')")]
        assert p.values(40, aeelver) == [1]
        assert p.values(40, 'nvme-mi.mi.aes.id') == [0x0006, 0x000B]
        for frame in (11, 12, 17, 39):
            assert p.experts(frame) == [], frame
        assert p.values(17, 'nvme-mi.mi.ae.aeelver') == [1]
        assert p.frames_with('nvme-mi.mi.aes.field_invalid') == [8, 16, 20, 24, 28]


class TestNvmeMiErrorPaths:
    """Response formats decided by something other than the opcode."""

    FILE = 'nvme-mi-transactions.pcapng'
    SECTION = 4
    SUPERSEDED = ('The previous request on this command slot was left unanswered; request/response'
                  ' tracking assumes this request supersedes it, but the endpoint may instead have'
                  ' discarded this one and kept servicing the previous request')

    def test_decode(self, assert_frames_match):
        assert_frames_match(self.FILE, at(self.SPAN, [
            # The MIC verdict comes before the body, so a truncated body does
            # not hide it; both frames say Not present (3), unverified.
            (2, 'nvme-mi.mic.status == 3 && nvme-mi.mic_unverified && _ws.short'),
            (5, 'nvme-mi.mic.status == 3 && nvme-mi.mic_unverified && !_ws.short'),
            # DOFST FFFFFFFCh + LPO 4 must not wrap to the first window.
            (17, 'nvme-mi.admin.status == 0x00 && !nvme.cmd.get_logpage.smart.cw'),
            # An Invalid Parameter Error Response has a PEL and no CQE or data
            # (Figures 28/31/32), even though the bytes look like both.
            (19, ('nvme-mi.admin.status == 0x04 && nvme-mi.pel.byte == 28'
                  ' && !nvme-mi.admin.cqe_dw0 && !nvme-mi.admin.cqe_dw1 && !nvme-mi.admin.cqe_dw3'
                  ' && !nvme.cqe.dword0 && !nvme.cqe.status.sct && !nvme.cmd.identify.ctrl.vid')),
            # A window past 2^32 inside 16 GiB of completion data is conformant.
            (24, ('nvme-mi.admin.doff == 0xfffffe00 && nvme.cmd.get_logpage.numd == 0xffffffff'
                  ' && nvme-mi.admin.rae_handling && !_ws.expert')),
            (25, 'nvme-mi.admin.status == 0x00 && nvme-mi.response_to == 24'),
        ]))

    def test_field_values(self, fields_table):
        t = section(fields_table(self.FILE, (
            'nvme-mi', 'nvme-mi.response_to', '_ws.expert.message', 'nvme-mi.mic',
            'nvme-mi.mic.status', 'nvme-mi.mic_unverified',
            'nvme-mi.control.status', 'nvme-mi.control.tag',
            'nvme-mi.control.cpsr', 'nvme-mi.admin.invalid_dofst', 'nvme-mi.admin.invalid_dlen',
            'nvme-mi.admin.short_cqe', 'nvme-mi.pel.byte')), self.SPAN)

        def row(frame, *names):
            return [t[frame][n] for n in names]

        assert list(column(t, 'nvme-mi')) == list(range(1, 30))
        # A sliced request still takes the slot, and says what it displaced.
        assert t[3]['nvme-mi.response_to'] == '2'
        assert self.SUPERSEDED in t[2]['_ws.expert.message']
        assert t[5]['nvme-mi.mic.status'] == '3'
        assert t[5]['nvme-mi.mic_unverified'] == 'True'
        assert 'Message Integrity Check not verified' not in t[5]['_ws.expert.message']
        assert row(2, 'nvme-mi.mic', 'nvme-mi.mic.status') == row(5, 'nvme-mi.mic', 'nvme-mi.mic.status')
        # A CP error body is not the Success layout (Figures 27/28): no Tag or
        # CPSR invented from its Reserved bytes.
        cp = ('nvme-mi.control.status', 'nvme-mi.control.tag', 'nvme-mi.control.cpsr')
        assert row(7, *cp) == ['0x08', '', '']
        assert row(9, *cp) == ['0x04', '', '']
        assert row(11, *cp)[1:] == ['0x33', '0x4001']
        # Figure 139 bounds the Get Log Page completion window; the Security
        # Send and Receive offsets are likewise invalid for their transfer.
        assert 'outside the 4-byte Get Log Page completion data' in t[16]['_ws.expert.message']
        assert 'does not transfer Response Data' in t[26]['_ws.expert.message']
        assert t[24]['_ws.expert.message'] == ''
        assert t[28]['_ws.expert.message'] == ('Data Offset 4294963200 is outside'
                                               ' the 8192-byte Security Receive'
                                               ' Allocation Length')
        assert list(column(t, 'nvme-mi.admin.invalid_dofst')) == [16, 26, 28]
        assert {n: row(n, 'nvme-mi.response_to', 'nvme-mi.pel.byte', '_ws.expert.message')
                for n in (27, 29)} == {27: ['26', '28', ''], 29: ['28', '28', '']}
        # DLEN against the Request Data carried (6.3) and the data returned.
        assert ('Data Length 64 is shorter than the 128-byte NVMe Request Data field the message'
                ' carries') in t[20]['_ws.expert.message']
        assert ("NVMe Response Data is 16 bytes, more than the 8 bytes the request's Data Length"
                ' selected') in t[23]['_ws.expert.message']
        assert list(column(t, 'nvme-mi.admin.invalid_dlen')) == [20, 22, 23]
        # Short CQE is a Success Response diagnosis only.
        assert column(t, 'nvme-mi.admin.short_cqe') == {}

    def test_data_windows(self, dissect_pdml, cmd_tshark, capture_file, test_env):
        """CNS 1Ch (Figure 343): each byte rendered once, with no raw copy."""
        p = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        assert p.fields(13, 'nvme.data') == []
        vectors = p.fields(13, 'nvme.cmd.identify.iocsc')
        assert [(int(f.get('pos')), int(f.get('size')), f.get('value')) for f in vectors] == [
            (40 + off, 8, bytes(range(off, off + 8)).hex()) for off in range(0, 64, 8)]
        assert all(f.get('hide') != 'yes' for f in vectors)
        text = subprocess.check_output(
            [cmd_tshark, '-r', capture_file(self.FILE), '-V', '-Y',
             to_capture(self.SPAN, 'frame.number in {15, 19, 25}')],
            encoding='utf-8', env=test_env)
        frames = dict(zip((int(n) - self.SPAN[0] + 1
                           for n in re.findall(r'^Frame (\d+):', text, re.MULTILINE)),
                          re.split(r'^Frame \d+:', text, flags=re.MULTILINE)[1:]))
        assert 'PCI Vendor ID (VID): 0x144d' in frames[15]
        assert 'Data: 4d 14' not in frames[15]
        assert 'Data: ef be ad de' in frames[19]
        assert 'Telemetry Host-Initiated data block 8388607' in frames[25]
        assert 'Telemetry Host-Initiated data block 8388608' in frames[25]


class TestNvmeMiFramingConformance:
    """Rules decided by two header fields at once, each with its control."""

    FILE = 'nvme-mi-types.pcapng'
    SECTION = 5

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_decode(self, assert_frames_match, two_pass):
        assert_frames_match(self.FILE, at(self.SPAN, [
            # CSI on every Control Primitive is shown as sent (4.2.1); Pause
            # and Resume do not use it and draw a Note (4.2.1.1, 4.2.1.2).
            (1, 'nvme-mi.control.opcode == 0x00 && nvme-mi.csi == 1 && nvme-mi.cp_csi'),
            (2, 'nvme-mi.control.opcode == 0x01 && nvme-mi.csi == 1 && nvme-mi.cp_csi'),
            (3, 'nvme-mi.control.opcode == 0x02 && nvme-mi.csi == 1 && !nvme-mi.cp_csi'),
            (4, 'nvme-mi.control.opcode == 0x03 && nvme-mi.csi == 1'),
            (5, 'nvme-mi.control.opcode == 0x04 && nvme-mi.csi == 1'),
            (6, 'nvme-mi.control.opcode == 0x00 && nvme-mi.csi == 0'),
            # An unanswered CP predecessor is normal (4.2.1).
            (7, 'nvme-mi.control.opcode == 0x00 && !nvme-mi.req_superseded'),
            # A response's CSI names the request's slot: not flagged.
            (8, ('nvme-mi.control.opcode == 0x00 && nvme-mi.ror == 1 && nvme-mi.csi == 1'
                 ' && !nvme-mi.control.orphan_response && !nvme-mi.control.tag_mismatch'
                 ' && !nvme-mi.response_csi_mismatch')),
            # CPs pair by TAG (4.2.1); a response CSI other than the
            # request's is flagged (Figure 20).
            (10, ('nvme-mi.csi == 0 && !nvme-mi.control.orphan_response'
                  ' && nvme-mi.control.opcode == 0x03 && nvme-mi.control.tag == 0x31'
                  ' && nvme-mi.control.mes.ssta && nvme-mi.response_csi_mismatch'
                  ' && nvme-mi.response_to == 9')),
            # CIAP and MEB outside a Command Message are shown as sent.
            (11, 'nvme-mi.type == 0 && nvme-mi.ciap == 1 && nvme-mi.control_header_flags'),
            (12, 'nvme-mi.type == 0 && nvme-mi.meb == 1 && nvme-mi.control_header_flags'),
            (13, ('nvme-mi.type == 5 && nvme-mi.ciap == 1 && nvme-mi.aem'
                  ' && nvme-mi.aem_header && !nvme-mi.mi.truncated')),
            (14, 'nvme-mi.ciap == 1 && nvme-mi.meb == 1 && nvme-mi.control_header_flags'),
            (16, 'nvme-mi.type == 1 && nvme-mi.ror == 1 && nvme-mi.meb == 1'),
            (17, 'nvme-mi.type == 1 && nvme-mi.ror == 0 && nvme-mi.ciap == 1 && nvme-mi.meb == 1'),
            # A displaced Reset (RSTTYP 00h) was owed nothing (5.8).
            (19, 'nvme-mi.mi.opcode == 0x07 && nvme-mi.mi.reset.rsttyp == 0'),
            (20, 'nvme-mi.prev_no_response == 19 && !nvme-mi.req_superseded'),
            (23, 'nvme-mi.req_superseded && !nvme-mi.prev_no_response'),
        ]), two_pass=two_pass)

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_censuses_and_links(self, fields_table, two_pass):
        t = section(fields_table(self.FILE, (
            'nvme-mi', '_ws.expert', '_ws.expert.message', '_ws.malformed.expert',
            'nvme-mi.mi.response_data_length', 'nvme-mi.mi.data_routing',
            'nvme-mi.req_superseded', 'nvme-mi.type', 'nvme-mi.ror', 'nvme-mi.prev_no_response',
            'nvme-mi.response_in', 'nvme-mi.response_to'), two_pass=two_pass), self.SPAN)
        assert list(column(t, 'nvme-mi')) == list(range(1, 25))
        assert list(column(t, '_ws.expert')) == [1, 2, 10, 11, 12, 13, 14, 16, 21, 22, 23, 24]
        assert column(t, '_ws.malformed.expert') == {}
        # Only proven-inline HSP responses owe inline data; F18's MEB with
        # unknown capabilities stays silent.
        assert list(column(t, 'nvme-mi.mi.response_data_length')) == [16, 21, 24]
        assert [t[16]['nvme-mi.mi.data_routing'], t[18]['nvme-mi.mi.data_routing']] == ['1', '0']
        # Of eleven CP requests none is superseded; F23 displaces a command.
        assert list(column(t, 'nvme-mi.req_superseded')) == [23]
        assert [n for n, r in t.items() if int(r['nvme-mi.type'], 0) == 0
                and r['nvme-mi.ror'] == 'False'] == [1, 2, 3, 4, 5, 6, 7, 9, 11, 12, 14]
        assert 'may instead have discarded this one' in t[23]['_ws.expert.message']
        assert column(t, 'nvme-mi.prev_no_response') == {20: '19'}
        assert {n: int(v) for n, v in column(t, 'nvme-mi.response_to').items()
                if n in (8, 10, 16, 21)} == {8: 7, 10: 9, 16: 15, 21: 20}
        # F19 (owed nothing) and F22 (displaced) are never answered.
        if two_pass:
            assert {n: t[n]['nvme-mi.response_in'] for n in (7, 9, 15, 19, 20, 22, 23)} == {
                7: '8', 9: '10', 15: '16', 19: '', 20: '21', 22: '', 23: '24'}

class TestNvmeMiMi4Regressions:
    """MI-4 regressions for framing, Admin data windows, and Reset semantics."""

    FILE = 'nvme-mi-mi4.pcapng'
    SECTION = 1

    def test_wire_contracts(self, assert_frames_match):
        assert_frames_match(self.FILE, at(self.SPAN, [
            (2, 'nvme-mi.response_is_mpr'),
            (5, ('nvme-mi.response_to == 1 && nvme-mi.replay_request == 3'
                 ' && !nvme-mi.replay_of && !nvme-mi.replay_mpr'
                 ' && !nvme-mi.response_is_mpr')),
            (7, 'nvme-mi.control.status == 0x04'),
            (9, 'nvme-mi.mi.status == 0x04'),
            (11, 'nvme-mi.admin.status == 0x04'),
            (12, 'nvme-mi.control_header_flags && nvme-mi.meb && nvme-mi.ciap'),
            (13, 'nvme-mi.oob_response_ic'),
            (14, 'nvme-mi.meb && !nvme-mi.admin.invalid_dlen'),
            (15, ('nvme-mi.meb && !nvme-mi.admin.short_response'
                  ' && !nvme-mi.admin.invalid_dlen')),
            (17, ('nvme-mi.meb && nvme-mi.admin.data'
                  ' && nvme-mi.admin.meb_inline_data'
                  ' && !nvme-mi.admin.short_response'
                  ' && !nvme-mi.admin.invalid_dlen'
                  ' && !nvme.cmd.identify.ctrl.vid')),
            (18, ('nvme-mi.meb && nvme-mi.admin.meb_inline_data'
                  ' && !nvme-mi.admin.invalid_dlen')),
            (19, '!nvme-mi.admin.tper_reset_applied'),
            (20, 'nvme-mi.meb && !nvme-mi.admin.invalid_dlen'),
            (21, 'nvme-mi.meb && !nvme-mi.admin.short_response'),
            (22, 'nvme-mi.admin.invalid_dlen'),
            (24, 'nvme-mi.admin.invalid_dlen'),
            (26, 'nvme-mi.admin.invalid_dofst'),
            (28, 'nvme-mi.admin.invalid_dlen'),
            (30, 'nvme-mi.admin.invalid_dofst'),
            (32, '!nvme-mi.admin.invalid_dlen'),
            (35, 'nvme-mi.mi.reset_success_response'),
            (37, 'nvme-mi.admin.status == 0x00 && nvme.cqe.status.sc == 0x02'),
        ]))

    def test_response_links_info_and_status_layers(self, fields_table):
        t = section(fields_table(self.FILE, (
            'nvme-mi.response_to', 'nvme-mi.response_in', 'nvme-mi.replay_request',
            'nvme-mi.replay_of', 'nvme-mi.replay_mpr', 'nvme-mi.response_is_mpr',
            'nvme-mi.mi.status', 'nvme-mi.control.status', 'nvme-mi.admin.status',
            'nvme-mi.admin.cqe_dw3', 'nvme.cqe.status.sc', '_ws.col.info',
            'nvme-mi.admin.invalid_dlen', 'nvme-mi.admin.invalid_dofst',
            'nvme-mi.admin.short_response', 'nvme-mi.admin.tper_reset_applied'),
            two_pass=True), self.SPAN)
        assert t[1]['nvme-mi.response_in'] == '5'
        assert t[5]['nvme-mi.response_to'] == '1'
        assert t[5]['nvme-mi.replay_request'] == '3'
        assert not t[5]['nvme-mi.replay_of'] and not t[5]['nvme-mi.replay_mpr']
        assert 'More Processing Required' in t[2]['_ws.col.info']
        assert 'Invalid Parameter' in t[7]['_ws.col.info']
        assert 'Invalid Parameter' in t[9]['_ws.col.info']
        assert 'Invalid Parameter' in t[11]['_ws.col.info']
        assert t[37]['nvme-mi.admin.status'] == '0x00'
        assert t[37]['nvme.cqe.status.sc'] == '0x0002'
        assert 'Invalid Parameter' not in t[37]['_ws.col.info']
        assert t[19]['nvme-mi.admin.tper_reset_applied'] == ''

    def test_meb_inline_data_text(self, dissect_pdml):
        # MI 2.2 Figure 20 and section 4.2.3: with MEB set the data is in the
        # Management Endpoint Buffer, and MEB set is prohibited without one.
        p = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        assert p.experts(17) == [
            ('MEB set to 1 is prohibited outside a Command Message; a Response'
            " Message clears it (NVMe-MI 'NVMe-MI Message Fields')"),
            ('Response Data carried inline although the request set MEB to 1'
            " (NVMe-MI 'NVMe-MI Message Fields', section 4.2.3)")]
        assert p.experts(18) == [
            ('Request Data carried inline with MEB set to 1: MEB 1 places Request'
            ' Data in the Management Endpoint Buffer, and is prohibited where'
            " there is none (NVMe-MI 'NVMe-MI Message Fields', section 4.2.3)")]


class TestNvmeMiAsyncEventMessage:
    """AEM bodies and AE Occurrence Lists (MI 2.2 Figures 60-64, 4.4.4)."""

    FILE = 'nvme-mi-mi-commands.pcapng'
    SECTION = 6
    AEMS = (1, 6, 7, 8, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21)

    def test_decode(self, assert_frames_match):
        assert_frames_match(self.FILE, at(self.SPAN, [
            # The AEM body is an AE Occurrence List, not data; AEMTI counts.
            (1, ('nvme-mi.type == 5 && nvme-mi.aem && nvme-mi.mi.aeo'
                 ' && nvme-mi.mi.aeo.numaeo == 2 && nvme-mi.mi.aeo.aeolhl == 7'
                 ' && nvme-mi.mi.aeo.aeoltl == 27 && !data.data'
                 ' && nvme-mi.mi.aeo.aeoi == 0x06 && nvme-mi.mi.aeo.aeoi == 0x01'
                 ' && nvme-mi.mi.aeo.aess == 2 && nvme-mi.mi.aeo.aess == 1'
                 ' && nvme-mi.mi.aeo.aeocid == 1 && nvme-mi.mi.aeo.aelhlen == 9'
                 ' && nvme-mi.mi.aeo.aeosil == 1'
                 ' && nvme-mi.mi.aeo.aemti == 0x1a && nvme-mi.mi.aeo.aemgn == 3'
                 ' && nvme-mi.mi.aeo.aemrc == 2 && !nvme-mi.mi.aeo_list_invalid')),
            # Figure 61: AEMTI shall be 0h in the response to an AEM Ack.
            (3, ('nvme-mi.mi.opcode == 0x03 && nvme-mi.mi.aeo.aemti == 0x1a'
                 ' && nvme-mi.mi.aeo_list_invalid')),
            (5, ('nvme-mi.mi.opcode == 0x03 && nvme-mi.mi.aeo.aemti == 0x00'
                 ' && !nvme-mi.mi.aeo_list_invalid')),
            # 4.4.4 overflow: header only, AEOLTL 0h, NUMAEO 0h.
            (6, ('nvme-mi.aem && nvme-mi.mi.aeo.aeolo == 1 && nvme-mi.mi.aeo.aeoltl == 0'
                 ' && nvme-mi.mi.aeo.numaeo == 0 && !nvme-mi.mi.aeo.entry'
                 ' && !nvme-mi.mi.aeo_list_invalid')),
            # Below the 7-byte header: flagged, nothing read.
            (7, ('nvme-mi.aem && nvme-mi.mi.truncated && !nvme-mi.mi.aeo.numaeo'
                 ' && !nvme-mi.mi.aeo.aeolhl')),
            # The scope is shown as sent (Figure 63 says NVM Subsystem).
            (18, ('nvme-mi.mi.aeo.aeoi == 0x06 && nvme-mi.mi.aeo.aess == 1'
                  ' && !nvme-mi.mi.aeo_list_invalid')),
            (21, ('nvme-mi.mi.aeo.aeoi && !nvme-mi.mi.aeo_list_invalid'
                  ' && nvme-mi.mi.aeo.aeomeid == 0x2a && nvme-mi.mi.aeo.aeoegid == 7'
                  ' && nvme-mi.mi.aeo.subsys_rsvd == 0 && nvme-mi.mi.aeo.scope_rsvd == 0'
                  ' && !nvme-mi.mi.reserved_value')),
        ]))

    def test_field_values(self, fields_table):
        t = section(fields_table(self.FILE, (
            'nvme-mi', 'nvme-mi.aem', 'nvme-mi.mi', '_ws.expert', '_ws.malformed.expert',
            '_ws.expert.message', '_ws.col.info', 'nvme-mi.mi.opcode', 'nvme-mi.response_to',
            'nvme-mi.mi.orphan_response', 'nvme-mi.mi.ae.numaee', 'mctp.tag.to',
            'nvme-mi.mi.aeo_list_invalid', 'nvme-mi.mi.aeo.aemti',
            'nvme-mi.mi.aeo.aelver', 'nvme-mi.mi.aeo.numaeo', 'nvme-mi.mi.aeo.aeoltl',
            'nvme-mi.mi.aeo.aeolhl', 'nvme-mi.mi.aeo.aeoi', 'nvme-mi.mi.aeo.aess',
            'nvme-mi.mi.aeo.aeosil', 'nvme-mi.mi.aeo.aeovsil', 'nvme-mi.mi.aeo.aeopt',
            'nvme-mi.mi.aeo.scope_rsvd', 'nvme-mi.mi.aeo.meid_rsvd', 'nvme-mi.mi.aeo.port_rsvd',
            'nvme-mi.mi.aeo.subsys_rsvd', 'nvme-mi.mi.reserved_value')), self.SPAN)

        def ints(value):
            return [int(v, 0) for v in value.split(',')] if value else []

        def rows(*names, where):
            return {n: [r[f] for f in names] for n, r in t.items() if where(r)}

        assert list(column(t, 'nvme-mi')) == list(range(1, 24))
        assert list(column(t, '_ws.expert')) == [3, 7, 8, 10, 11, 12, 14, 15, 16, 18, 19]
        assert column(t, '_ws.malformed.expert') == {}
        # An AEM is its own message category (Figure 26), not an MI command.
        assert tuple(column(t, 'nvme-mi.aem')) == self.AEMS
        assert list(column(t, 'nvme-mi.mi')) == [2, 3, 4, 5, 9, 10, 22, 23]
        # AEMTI and AELVER are shown as sent on both paths.
        assert [n for n, r in t.items() if 0x1a in ints(r['nvme-mi.mi.aeo.aemti'])] == [1, 3]
        assert t[3]['_ws.expert.message'] == (
            'AEMTI shall be cleared to 0h in a response to an AEM Ack or AE Sync'
            " (NVMe-MI 'AE Occurrence List Data Structure')")
        # Figure 61: AELVER shall be 0h, on either path.
        aelver = "AELVER shall be cleared to 0h (NVMe-MI 'AE Occurrence List Data Structure')"
        assert rows('nvme-mi.mi.aeo.numaeo', '_ws.expert.message',
                    where=lambda r: 1 in ints(r['nvme-mi.mi.aeo.aelver'])) == {
            8: ['2', aelver], 10: ['2', aelver]}
        # AEOLTL shall equal the header plus every occurrence's full length.
        assert [t[11][f] for f in ('nvme-mi.mi.aeo.aeoltl', 'nvme-mi.mi.aeo.aeolhl',
                                   'nvme-mi.mi.aeo.aeoi', '_ws.expert.message')] == [
            '16', '7', '0x06,0x01', list_invalid(2, 2, 'AE Occurrence', 16, 27, 27)]
        # Vendor specific AEs (C0h-FFh) decode their lengths as sent.
        assert rows('nvme-mi.mi.aeo.aeoi', 'nvme-mi.mi.aeo.aeosil', 'nvme-mi.mi.aeo.aeovsil',
                    '_ws.expert.message',
                    where=lambda r: any(v >= 0xc0 for v in ints(r['nvme-mi.mi.aeo.aeoi']))) == {
            12: ['0xc0', '1', '0',
                 ("AEOSIL shall be 0h for a vendor specific AE (NVMe-MI 'AE Occurrence"
                  " Data Structure', 'AE Occurrence Specific Info Data Structure')")],
            13: ['0xc1', '0', '2', ''],
            20: ['0x00,0xc2,0x0b,0xc3,0x06', '1,0,1,0,1', '0,0,0,0,0', ''],
            21: ['0x00,0xc2,0x0b,0xc3,0x06', '1,0,1,0,1', '0,0,0,0,0', '']}
        # NUMAEO beyond the body is reported once, after what was rendered.
        assert [t[14][f] for f in ('_ws.expert.message', 'nvme-mi.mi.aeo.aeoi')] == [
            list_invalid(2, 3, 'AE Occurrence', 27, 27, 27), '0x06,0x01']
        assert t[15]['_ws.expert.message'] == list_invalid(0, 1, 'AE Occurrence', 7, 7, 7)
        # Figure 63 0Bh: the Port Type is shown as sent, and shall be 1.
        assert rows('nvme-mi.mi.aeo.aeopt', '_ws.expert.message',
                    where=lambda r: 0x0b in ints(r['nvme-mi.mi.aeo.aeoi'])) == {
            16: ['False', "PCIe Link Active shall set AEOPT to 1 (NVMe-MI 'Asynchronous Events')"],
            17: ['True', ''], 20: ['True', ''], 21: ['True', '']}
        # Figure 63 scopes Composite Temperature (06h) as NVM Subsystem.
        assert t[18]['_ws.expert.message'] == (
            'Composite Temperature is not reported with Controller scope'
            " (NVMe-MI 'Asynchronous Events')")
        # 4.4.4 (a): an AEM's Tag Owner bit is set.  F19 differs from F1 only
        # there.
        assert [n for n in self.AEMS if t[n]['mctp.tag.to'] == 'False'] == [19]
        assert t[19]['_ws.expert.message'] == (
            'An Asynchronous Event Message is sent with the MCTP Tag Owner bit'
            ' set (NVMe-MI section 4.4.4)')
        body = ('nvme-mi.mi.aeo.numaeo', 'nvme-mi.mi.aeo.aeoltl', 'nvme-mi.mi.aeo.aeoi',
                'nvme-mi.mi.aeo.aess')
        assert [t[19][f] for f in body] == [t[1][f] for f in body]
        # Figure 64 Reserved bits are shown as sent.
        assert [t[20][f] for f in ('nvme-mi.mi.aeo.scope_rsvd', 'nvme-mi.mi.aeo.meid_rsvd',
                                   'nvme-mi.mi.aeo.port_rsvd', 'nvme-mi.mi.aeo.subsys_rsvd')] == [
            '0x0000ffff,0x00000001', '0x000000ff', '0x00004000', '0x11223344']
        assert column(t, 'nvme-mi.mi.reserved_value') == {}
        # Info: the AEM summary, and AEM Ack vs AE Sync by NUMAEE (5.2.4).
        assert [t[n]['_ws.col.info'] for n in (1, 6, 7)] == [
            'NVMe-MI Asynchronous Event (2 AE occurrences)',
            'NVMe-MI Asynchronous Event (list overflow)', 'NVMe-MI Asynchronous Event']
        ack, sync = 'Asynchronous Event (AEM Ack))', 'Asynchronous Event (AE Sync))'
        assert {n: (r['nvme-mi.mi.ae.numaee'], r['_ws.col.info'].split('(Configuration Set: ')[-1])
                for n, r in t.items()
                if (r['nvme-mi.mi.opcode'] and int(r['nvme-mi.mi.opcode'], 0) == 3)
                or r['nvme-mi.mi.orphan_response'] or r['nvme-mi.response_to']} == {
            2: ('0', ack), 3: ('', ack), 4: ('0', ack), 5: ('', ack), 9: ('0', ack),
            10: ('', ack), 22: ('2', sync), 23: ('', sync)}

    def test_aems_take_no_command_slot(self, fields_table):
        """An AEM occupies no Command Slot (4.4) and the ROR bit does not
        apply: no AEM opens or closes a transaction."""
        t = section(fields_table(self.FILE, ('nvme-mi.response_in', 'nvme-mi.response_to'), two_pass=True), self.SPAN)
        assert {n: (t[n]['nvme-mi.response_in'], t[n]['nvme-mi.response_to'])
                for n in self.AEMS} == {n: ('', '') for n in self.AEMS}

    def test_configuration_set_without_an_enable_list_names_no_variation(self, fields_table):
        """With no AE Enable List the Info column names no variation."""
        t = section(fields_table(self.FILE, (
            'nvme-mi.mi.opcode', 'nvme-mi.mi.config.cid', 'nvme-mi.mi.ae.numaee',
            '_ws.col.info')), (205, 317))   # TestNvmeMiCommandContracts's section
        named, bare = [], []
        for n, r in t.items():
            if not (r['nvme-mi.mi.opcode'] and int(r['nvme-mi.mi.opcode'], 0) == 3
                    and r['nvme-mi.mi.config.cid'] and int(r['nvme-mi.mi.config.cid'], 0) == 4):
                continue
            variation = [v for v in ('AE Sync', 'AEM Ack') if v in r['_ws.col.info']]
            if variation:
                named.append((n, r['nvme-mi.mi.ae.numaee'], variation[0]))
            else:
                bare.append((n, r['nvme-mi.mi.ae.numaee']))
        assert bare == [(n, '') for n in (67, 69, 82, 85, 88, 91, 94)]
        assert named == [
            (17, '1', 'AE Sync'), (19, '1', 'AE Sync'), (21, '1', 'AE Sync'),
            (27, '1', 'AE Sync'), (31, '0', 'AEM Ack'), (33, '0', 'AEM Ack'),
            (100, '2', 'AE Sync'), (112, '1', 'AE Sync')]
        events = section(fields_table(self.FILE, ('_ws.col.info',)),
                         (75, 204))   # TestNvmeMiMiEventsConfig's section
        assert 'AE Sync' in events[14]['_ws.col.info']


class TestNvmeMiAeoOverrun:
    """AE Occurrences whose lengths run past the list data (MI 2.2 Figures 61/62)."""

    FILE = 'nvme-mi-mi-commands.pcapng'
    SECTION = 10

    def test_overrun(self, fields_table):
        t = section(fields_table(self.FILE, (
            'nvme-mi', 'nvme-mi.aem', 'nvme-mi.response_to', 'nvme-mi.mi.aeo.aeoltl',
            '_ws.expert.message', '_ws.malformed.expert')), self.SPAN)
        assert list(column(t, 'nvme-mi')) == list(range(1, 8))
        assert list(column(t, 'nvme-mi.aem')) == [1, 2, 3, 4, 5]
        assert column(t, 'nvme-mi.response_to') == {7: '6'}
        assert column(t, 'nvme-mi.mi.aeo.aeoltl') == {
            1: '16', 2: '16', 3: '16', 4: '16', 5: '7', 7: '16'}
        # One message per list, after the walk.
        assert column(t, '_ws.expert.message') == {
            1: list_invalid(1, 1, 'AE Occurrence', 16, 80, 16),
            2: list_invalid(1, 1, 'AE Occurrence', 16, 32, 16),
            3: list_invalid(1, 1, 'AE Occurrence', 16, 39, 16)
               + ",AELHLEN shall be set to 9h (NVMe-MI 'AE Occurrence Data Structure')",
            4: list_invalid(1, 1, 'AE Occurrence', 16, 80, 20),
            5: list_invalid(0, 0, 'AE Occurrence', 7, 32, 7)
               + ",AEOLHL shall be set to 7h (NVMe-MI 'AE Occurrence List Data Structure')",
            7: list_invalid(1, 1, 'AE Occurrence', 16, 80, 16)}
        assert column(t, '_ws.malformed.expert') == {}


class TestNvmeMiCommandSetCompleteness:
    """MI Command Set fields, reserved bits and data extents (MI 2.2 Figs
    61, 76-136, 151, 180, 197): mi9_command_set_vectors."""

    FILE = 'nvme-mi-mi-commands.pcapng'
    SECTION = 11

    def test_decode(self, assert_frames_match):
        assert_frames_match(self.FILE, at(self.SPAN, [
            # MEB Read/Write: DOFST is all of NMD0, DLEN NMD1 15:0.
            (1, 'nvme-mi.mi.meb.dofst == 256 && nvme-mi.mi.meb.dlen == 8'),
            (2, 'len(nvme-mi.mi.meb.data) == 8 && !_ws.expert'),
            (5, ('nvme-mi.mi.meb.dofst == 4 && nvme-mi.mi.meb.dlen == 4'
                 ' && nvme-mi.mi.nmd1_reserved == 0x00010000 && !_ws.expert'
                 ' && nvme-mi.mi.meb.data == de:ad:be:ef')),
            (6, 'nvme-mi.mi.nmresp_reserved == 0 && !nvme-mi.mi.data && !_ws.expert'),
            # SES Receive: PCODE, ALENGTH, then RDL bounds the page.
            (9, 'nvme-mi.mi.ses.pcode == 0x02 && nvme-mi.mi.ses.alength == 16'),
            (10, ('nvme-mi.mi.ses.rdl == 8 && len(nvme-mi.mi.ses.page) == 8'
                  ' && !_ws.expert')),
            (12, ('len(nvme-mi.mi.ses.page) == 8'
                  ' && nvme-mi.mi.response_surplus == ee:ee:ee:ee')),
            # SES Send: NMD0 is reserved; DLEN names the page.
            (15, ('nvme-mi.mi.ses.dlen == 4 && nvme-mi.mi.nmd0_reserved == 0xffffffff'
                  ' && len(nvme-mi.mi.ses.page) == 4 && !_ws.expert')),
            # Configuration Get/Set SMBus/I2C Frequency reserved bits.
            (20, ('nvme-mi.mi.nmresp_reserved_bits == 0xfffff0'
                  ' && !_ws.expert')),
            (21, ('nvme-mi.mi.nmd0_reserved == 0x00fff000'
                  ' && nvme-mi.mi.nmd1_reserved == 0xffffffff && !_ws.expert')),
            # Figures 180/197: a vendor specific Element Descriptor.
            (25, ('nvme-mi.mi.vpd.typ == 0xf0 && nvme-mi.mi.vpd.pcivid == 0x8086'
                  ' && nvme-mi.mi.vpd.raw == 11:22 && !_ws.expert')),
            (27, 'nvme-mi.mi.vpd.typ == 0xf1 && !nvme-mi.mi.vpd.pcivid && _ws.expert'),
            # Controller Information decodes what is present.
            (31, ('nvme-mi.mi.ctrlinfo.portid == 1 && nvme-mi.mi.ctrlinfo.prii == 0x01'
                  ' && !nvme-mi.mi.ctrlinfo.pri')),
            (33, ('nvme-mi.mi.ctrlinfo.pri == 0x0102'
                  ' && !nvme-mi.mi.ctrlinfo.pcivid')),
            (35, ('nvme-mi.mi.ctrlinfo.pcivid == 0x8086'
                  ' && nvme-mi.mi.ctrlinfo.pcisdid == 0x3906'
                  ' && !nvme-mi.mi.ctrlinfo.pciesn')),
            # CHSP: NMD0 bit 27 reserved; CHDS units.
            (36, 'nvme-mi.mi.nmd0_reserved == 0x08000000 && !nvme-mi.mi.nmd1_reserved'),
            (37, ('nvme-mi.mi.chds.ctemp == 300 && nvme-mi.mi.chds.pdlu == 5'
                  ' && nvme-mi.mi.chds.spare == 90 && !_ws.expert')),
        ]))

    def test_experts(self, fields_table):
        t = section(fields_table(self.FILE, ('_ws.expert.message',)), self.SPAN)
        fixed = ('Response Data has {} bytes; {} declares 0 bytes;'
                 ' the fixed data structure requires exactly 0 bytes')
        info = ('Response Data has {0} bytes; RDL declares {0} bytes;'
                ' the fixed data structure requires exactly 32 bytes')
        assert column(t, '_ws.expert.message') == {
            4: 'Response Data has 4 bytes but DLEN declares 8 bytes',
            8: fixed.format(2, 'Management Endpoint Buffer Write'),
            12: 'Response Data has 12 bytes but RDL declares 8 bytes',
            14: 'RDL 8 exceeds the request\'s ALENGTH 4',
            16: fixed.format(2, 'SES Send'),
            18: fixed.format(1, 'VPD Write'),
            23: ('An overflowed AE Occurrence List shall have AEOLTL 0h and'
                 " NUMAEO 0h (NVMe-MI 'AE Occurrence List Data Structure', section 4.4.4)"),
            27: 'VPD length or count contradicts the bounded structure',
            31: info.format(6), 33: info.format(8), 35: info.format(16)}

    def test_labels(self, dissect_pdml):
        p = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        # Figure 151: PCIe Command Set opcodes in the command list.
        assert [f.get('showname') for f in p.fields(29, 'nvme-mi.mi.cmdlist.opc')] == [
            'Opcode (OPC): 0x00 (PCIe Configuration Read)',
            'Opcode (OPC): 0x06 (Reserved)']
        assert p.shownames(37, 'nvme-mi.mi.chds.ctemp') == [
            'Composite Temperature (CTEMP): 300 K (27 \u00b0C)']
        assert p.shownames(37, 'nvme-mi.mi.chds.pdlu') == ['Percentage Used (PDLU): 5%']
        assert p.shownames(37, 'nvme-mi.mi.chds.spare') == ['Available Spare (SPARE): 90%']
        assert p.shownames(25, 'nvme-mi.mi.vpd.typ') == [
            'Element Type (TYP): Vendor Specific (0xf0)']


class TestNvmeMiResponseFormat:
    """Non-Success MI responses carry a four-byte status-specific body, not
    NMRESP (NVMe-MI 2.2 Figures 29-34): mi_response_format_vectors."""

    FILE = 'nvme-mi-mi-commands.pcapng'
    SECTION = 12

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_decode(self, assert_frames_match, two_pass):
        assert_frames_match(self.FILE, at(self.SPAN, [
            # Invalid Parameter to Configuration Get AE: byte 1 is the PEL.
            (2, ('nvme-mi.mi.status == 0x04 && nvme-mi.pel.byte == 4'
                 ' && nvme-mi.pel.bit == 1 && !nvme-mi.mi.config.aeelver'
                 ' && !_ws.expert')),
            (4, ('nvme-mi.mi.status == 0x02 && !nvme-mi.mi.response_surplus'
                 ' && !nvme-mi.mi.data && !_ws.expert')),
            (6, ('nvme-mi.mi.status == 0x02'
                 ' && nvme-mi.mi.response_surplus == a5:a5:a5:a5'
                 ' && !nvme-mi.mi.data')),
            (8, ('nvme-mi.pel.byte == 4 && nvme-mi.pel.bit == 1'
                 ' && !nvme-mi.mi.config.aeelver'
                 ' && nvme-mi.mi.response_surplus == a5:a5:a5:a5')),
            # MPR stays intermediate; the final response completes it.
            (9, 'nvme-mi.response_in == 11' if two_pass else '!_ws.expert'),
            (10, ('nvme-mi.response_is_mpr && nvme-mi.response_to == 9'
                  ' && nvme-mi.mprt == 10 && !nvme-mi.mi.response_surplus'
                  ' && !_ws.expert')),
            (11, 'nvme-mi.response_to == 9 && nvme-mi.mi.status == 0'),
            (12, 'nvme-mi.response_in == 14' if two_pass else '!_ws.expert'),
            (13, ('nvme-mi.response_is_mpr && nvme-mi.response_to == 12'
                  ' && nvme-mi.mprt == 10'
                  ' && nvme-mi.mi.response_surplus == a5:a5:a5:a5')),
            (14, ('nvme-mi.response_to == 12 && nvme-mi.mi.status == 0'
                  ' && !_ws.expert')),
            # Reserved and Vendor Specific: no format, so raw Data.
            (16, ('nvme-mi.reserved_status && nvme-mi.mi.data == a5:a5:a5:a5'
                  ' && !nvme-mi.mi.response_surplus')),
            (18, ('nvme-mi.reserved_status && nvme-mi.mi.data == a5:a5:a5:a5'
                  ' && !nvme-mi.mi.response_surplus')),
            (20, ('nvme-mi.mi.status == 0xe0 && nvme-mi.mi.data == a5:a5:a5:a5'
                  ' && !nvme-mi.mi.response_surplus && !_ws.expert')),
        ]), two_pass=two_pass)

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_surplus(self, dissect_pdml, two_pass):
        p = pdml_section(dissect_pdml(self.FILE, two_pass=two_pass), self.SPAN)
        assert p.frames_with('nvme-mi.mi.error_surplus') == [6, 8, 13]
        for frame, status in ((6, 'Internal Error'), (8, 'Invalid Parameter'),
                              (13, 'More Processing Required')):
            assert p.experts(frame) == [
                f'4 bytes follow the 4-byte {status} Response'], frame
            assert p.extents(frame, 'nvme-mi.mi.response_surplus') == [
                (p.extents(frame, 'nvme-mi.mi.status')[0][0] + 4, 4)], frame
        assert p.frames_with('nvme-mi.mi.config.aeelver_nonzero') == []


class TestNvmeMiAeEnableListExtra:
    """AE Enable List extent (NVMe-MI 2.2 5.2.4, Figure 91):
    build_ae_enable_list_extra_pcapng."""

    FILE = 'nvme-mi-mi-commands.pcapng'
    SECTION = 13

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_enable_list_extent(self, assert_frames_match, fields_table, two_pass):
        assert_frames_match(self.FILE, at(self.SPAN, [
            # Data past a consistent AEETL is ignored, shown raw.
            (1, ('nvme-mi.mi.ae.aeetl == 8 && nvme-mi.mi.data == aa:bb'
                 ' && !_ws.expert')),
            (2, 'nvme-mi.mi.aeo.numaeo == 1 && !_ws.expert'),
            # AEETL inside the data but not minimal: a "should".
            (3, ('nvme-mi.mi.ae.aeetl_mismatch && !nvme-mi.mi.ae_list_invalid'
                 ' && _ws.expert.message == "AEETL 10 should equal AEELHL plus'
                 ' the AE Enable entries, 8 bytes (NVMe-MI \'AE Enable List Data Structure\')"'
                 ' && _ws.expert.severity == note')),
            (4, 'nvme-mi.mi.aeo.numaeo == 1 && !_ws.expert'),
            # An entry the data cannot hold stays malformed.
            (5, ('nvme-mi.mi.ae_list_invalid && !nvme-mi.mi.ae.aeetl_mismatch'
                 ' && _ws.expert.message == "1 of 1 AE Enable entries present;'
                 ' Total Length 9, header plus entries 9, list data 8 bytes"')),
            (6, 'nvme-mi.mi.status == 0x06 && !_ws.expert'),
            # No AE Enable List: no NUMAEE, so no variation (5.2.4).
            (7, ('nvme-mi.mi.truncated && nvme-mi.meb == 0'
                 f' && _ws.expert.message == "{TestNvmeMiCommandContracts.NO_ENABLE_LIST}"'
                 ' && !(_ws.col.info contains "AE Sync")'
                 ' && !(_ws.col.info contains "AEM Ack")')),
            (8, 'nvme-mi.mi.status == 0x06 && !_ws.expert'),
            # MEB does not excuse it: AE Set Request Data is inline.
            (9, ('nvme-mi.mi.truncated && nvme-mi.meb == 1'
                 ' && nvme-mi.mi.data_routing == 1'
                 f' && _ws.expert.message == "{TestNvmeMiCommandContracts.NO_ENABLE_LIST}"'
                 ' && !(_ws.col.info contains "AE Sync")'
                 ' && !(_ws.col.info contains "AEM Ack")')),
            (10, 'nvme-mi.mi.status == 0x06 && !_ws.expert'),
            # A 5-byte AEM Ack list is complete.
            (11, 'nvme-mi.mi.ae.numaee == 0 && !_ws.expert'),
            (12, 'nvme-mi.mi.aeo.numaeo == 0 && !_ws.expert'),
            # A 1-4-byte list keeps its single truncated expert.
            (13, ('count(_ws.expert) == 1'
                  ' && _ws.expert.message == "MI command payload truncated"')),
            (14, 'nvme-mi.mi.status == 0x06 && !_ws.expert'),
            # Configuration Get carries no Request Data.
            (15, 'nvme-mi.mi.opcode == 0x04 && !_ws.expert'),
            (16, 'nvme-mi.mi.aes.numaes == 2 && !_ws.expert'),
        ]), two_pass=two_pass)
        t = section(fields_table(self.FILE, ('nvme-mi.mi.truncated',),
                                 two_pass=two_pass), self.SPAN)
        assert list(column(t, 'nvme-mi.mi.truncated')) == [7, 9, 13]


class TestNvmeMiFieldEncoding:
    """NVMe fields whose wire value is a scale, sentinel, bit split or 0's based count."""

    FILE = 'nvme-mi-admin-logpage.pcapng'
    SECTION = 6

    def test_decode(self, assert_frames_match):
        assert_frames_match(self.FILE, at(self.SPAN, [
            # Figure 210: the raw 16 bytes of DUR 2^31 / DUW 2^32 are unchanged.
            (4, ('nvme.cmd.get_logpage.smart.dur == '
                 '00:00:00:80:00:00:00:00:00:00:00:00:00:00:00:00'
                 ' && nvme.cmd.get_logpage.smart.duw == '
                 '00:00:00:00:01:00:00:00:00:00:00:00:00:00:00:00')),
            # Figure 209: STS 0303h is Phase Tag 1 / Status 181h.
            (6, ('nvme.cmd.get_logpage.errinf.sf == 0x0303'
                 ' && nvme.cmd.get_logpage.errinf.sf.ptag == 1'
                 ' && nvme.cmd.get_logpage.errinf.sf.val == 0x0181')),
            # Figure 474: 31:16 Reserved / 15:08 TIME / 07:00 THR, and the CQE
            # Dword 0 mirror (a different value, so neither reads the other).
            (11, ('nvme.cmd.set_features.dword11.irqc == 0x0000c81f'
                  ' && nvme.cmd.set_features.dword11.irqc.thr == 0x1f'
                  ' && nvme.cmd.set_features.dword11.irqc.time == 0xc8'
                  ' && nvme.cmd.set_features.dword11.irqc.rsvd == 0')),
            (14, ('nvme.cqe.dword0.get_features.irqc == 0x00002a07'
                  ' && nvme.cqe.dword0.get_features.irqc.thr == 0x07'
                  ' && nvme.cqe.dword0.get_features.irqc.time == 0x2a'
                  ' && nvme.cqe.dword0.get_features.irqc.rsvd == 0')),
            # OACS CFLS/HMLMS, FRMW SMUD, LPA MLPS/DA4S; GLSS and Reserved are
            # peers of bit 0, not its children.
            (20, ('nvme.cmd.identify.ctrl.oacs == 0x5d55'
                  ' && nvme.cmd.identify.ctrl.oacs.cfls == 1'
                  ' && nvme.cmd.identify.ctrl.oacs.hmlms == 1'
                  ' && nvme.cmd.identify.ctrl.oacs.sec == 1'
                  ' && nvme.cmd.identify.ctrl.oacs.glss == 0'
                  ' && nvme.cmd.identify.ctrl.oacs.enss == 1'
                  ' && nvme.cmd.identify.ctrl.oacs.ccfls == 0'
                  ' && nvme.cmd.identify.ctrl.oacs.rsvd == 0x1'
                  ' && nvme.cmd.identify.ctrl.frmw == 0xab'
                  ' && nvme.cmd.identify.ctrl.frmw.smud == 1'
                  ' && nvme.cmd.identify.ctrl.frmw.rsvd == 0x2'
                  ' && nvme.cmd.identify.ctrl.lpa == 0xb5'
                  ' && nvme.cmd.identify.ctrl.lpa.mlps == 1'
                  ' && nvme.cmd.identify.ctrl.lpa.da4s == 0'
                  ' && nvme.cmd.identify.ctrl.lpa.rsvd == 0x1')),
            # OAES bits 31:15 hold eight events and three Reserved runs;
            # CTRATT defines bits 21:10.
            (22, ('nvme.cmd.identify.ctrl.oaes == 0xdd5ed5a5'
                  ' && nvme.cmd.identify.ctrl.oaes.nnss == 1'
                  ' && nvme.cmd.identify.ctrl.oaes.tthr == 0'
                  ' && nvme.cmd.identify.ctrl.oaes.rgcns == 1'
                  ' && nvme.cmd.identify.ctrl.oaes.ansan == 1'
                  ' && nvme.cmd.identify.ctrl.oaes.ccrcn == 1'
                  ' && nvme.cmd.identify.ctrl.oaes.lhcn == 0'
                  ' && nvme.cmd.identify.ctrl.oaes.zdcn == 1'
                  ' && nvme.cmd.identify.ctrl.oaes.dlpcn == 1'
                  ' && nvme.cmd.identify.ctrl.oaes.rsvd0 == 0xa5'
                  ' && nvme.cmd.identify.ctrl.oaes.rsvd1 == 0x1'
                  ' && nvme.cmd.identify.ctrl.oaes.rsvd2 == 0x1'
                  ' && nvme.cmd.identify.ctrl.oaes.rlcc == 1'
                  ' && nvme.cmd.identify.ctrl.oaes.rsvd3 == 0xa'
                  ' && nvme.cmd.identify.ctrl.oaes.rsvd4 == 0x5'
                  ' && nvme.cmd.identify.ctrl.ctratt == 0x5575b6aa'
                  ' && nvme.cmd.identify.ctrl.ctratt.mds == 1'
                  ' && nvme.cmd.identify.ctrl.ctratt.fcm == 0'
                  ' && nvme.cmd.identify.ctrl.ctratt.vcm == 1'
                  ' && nvme.cmd.identify.ctrl.ctratt.deg == 1'
                  ' && nvme.cmd.identify.ctrl.ctratt.dnvms == 0'
                  ' && nvme.cmd.identify.ctrl.ctratt.elbas == 1'
                  ' && nvme.cmd.identify.ctrl.ctratt.mem == 1'
                  ' && nvme.cmd.identify.ctrl.ctratt.hmbr == 0'
                  ' && nvme.cmd.identify.ctrl.ctratt.fdps == 0'
                  ' && nvme.cmd.identify.ctrl.ctratt.pls == 1'
                  ' && nvme.cmd.identify.ctrl.ctratt.pms == 1'
                  ' && nvme.cmd.identify.ctrl.ctratt.vms == 1'
                  ' && nvme.cmd.identify.ctrl.ctratt.iiellss == 2'
                  ' && nvme.cmd.identify.ctrl.ctratt.rsvd == 0x2a')),
            (24, ('nvme.cmd.identify.ctrl.oaes.nnss == 0'
                  ' && nvme.cmd.identify.ctrl.oaes.tthr == 1'
                  ' && nvme.cmd.identify.ctrl.oaes.rgcns == 0'
                  ' && nvme.cmd.identify.ctrl.oaes.ansan == 0'
                  ' && nvme.cmd.identify.ctrl.oaes.ccrcn == 0'
                  ' && nvme.cmd.identify.ctrl.oaes.lhcn == 1'
                  ' && nvme.cmd.identify.ctrl.oaes.zdcn == 0'
                  ' && nvme.cmd.identify.ctrl.oaes.dlpcn == 0'
                  ' && nvme.cmd.identify.ctrl.oaes.rsvd3 == 0'
                  ' && nvme.cmd.identify.ctrl.oaes.rsvd4 == 0')),
            (26, ('nvme.cmd.identify.ctrl.dsto == 0xaa'
                  ' && nvme.cmd.identify.ctrl.dsto.sdso == 0'
                  ' && nvme.cmd.identify.ctrl.dsto.hirs == 1'
                  ' && nvme.cmd.identify.ctrl.dsto.rsvd == 0x2a')),
            (28, ('nvme.cmd.identify.ctrl.sanicap == 0x7000042d'
                  ' && nvme.cmd.identify.ctrl.sanicap.vers == 1'
                  ' && nvme.cmd.identify.ctrl.sanicap.nvers == 0'
                  ' && nvme.cmd.identify.ctrl.sanicap.sprrs == 1'
                  ' && nvme.cmd.identify.ctrl.sanicap.rsvd == 0x400010'
                  ' && nvme.cmd.identify.ctrl.sanicap.ndi == 1')),
            # ONCS defines 12:8; FNA's Reserved run is 7:4 with FNVMBS out.
            (30, ('nvme.cmd.identify.ctrl.oncs == 0xbd55'
                  ' && nvme.cmd.identify.ctrl.oncs.cpys == 1'
                  ' && nvme.cmd.identify.ctrl.oncs.csa == 0'
                  ' && nvme.cmd.identify.ctrl.oncs.afc == 1'
                  ' && nvme.cmd.identify.ctrl.oncs.maxwzd == 1'
                  ' && nvme.cmd.identify.ctrl.oncs.nszs == 1'
                  ' && nvme.cmd.identify.ctrl.oncs.rsvd == 0x5'
                  ' && nvme.cmd.identify.ctrl.fna == 0x08'
                  ' && nvme.cmd.identify.ctrl.fna.rsvd == 0')),
            (32, 'nvme.cmd.identify.ctrl.fna == 0x07 && nvme.cmd.identify.ctrl.fna.rsvd == 0'),
            # CDFS was a Reserved item; SGLS SDT is one 8-bit count.
            (34, ('nvme.cmd.identify.ctrl.cdfs == 0x80ad'
                  ' && nvme.cmd.identify.ctrl.cdfs.cdf0s == 1'
                  ' && nvme.cmd.identify.ctrl.cdfs.cdf1s == 0'
                  ' && nvme.cmd.identify.ctrl.cdfs.cdf2s == 1'
                  ' && nvme.cmd.identify.ctrl.cdfs.cdf3s == 1'
                  ' && nvme.cmd.identify.ctrl.cdfs.cdf4s == 0'
                  ' && nvme.cmd.identify.ctrl.cdfs.rsvd == 0x405'
                  ' && nvme.cmd.identify.ctrl.sgls == 0x81755aae'
                  ' && nvme.cmd.identify.ctrl.sgls.sdt == 90'
                  ' && nvme.cmd.identify.ctrl.sgls.rsvd0 == 0x15'
                  ' && nvme.cmd.identify.ctrl.sgls.rsvd1 == 0x205')),
            # Figure 210: IPMV 15:00, IPMS 17:16, Reserved 19:18, PMT 23:20,
            # Reserved 31:24.
            (40, ('nvme.cmd.get_logpage.smart.olec == 1234605616436508552'
                  ' && nvme.cmd.get_logpage.smart.ipm == 0xa5061f40'
                  ' && nvme.cmd.get_logpage.smart.ipm.ipmv == 8000'
                  ' && nvme.cmd.get_logpage.smart.ipm.ipms == 2'
                  ' && nvme.cmd.get_logpage.smart.ipm.pmt == 0'
                  ' && nvme.cmd.get_logpage.smart.ipm.rsvd0 == 1'
                  ' && nvme.cmd.get_logpage.smart.ipm.rsvd1 == 0xa5')),
        ]))

    def test_field_values(self, fields_table):
        t = section(fields_table(self.FILE, (
            '_ws.malformed.expert', '_ws.expert.message',
            'nvme.cmd.get_logpage.sanitize.sprog', 'nvme.cmd.get_logpage.sanitize.sstat.sos',
            'nvme.cmd.identify.ctrl.acwu',
            'nvme.cmd.identify.ctrl.nvmeof.fcatt', 'nvme.cmd.identify.ctrl.nvmeof.fcatt.dcm')), self.SPAN)
        assert column(t, '_ws.malformed.expert') == {}
        # SPROG filters on the wire value, whatever SOS says (Figure 302).
        assert [(n, r['nvme.cmd.get_logpage.sanitize.sprog'],
                 r['nvme.cmd.get_logpage.sanitize.sstat.sos'], r['_ws.expert.message'])
                for n, r in t.items() if r['nvme.cmd.get_logpage.sanitize.sprog']] == [
            (8, '0xffff', '0x0001', ''),
            (10, '0x4000', '0x0002', ''),
            (42, '0x4000', '0x0001', '')]
        assert column(t, 'nvme.cmd.identify.ctrl.acwu') == {16: '7', 18: '0'}
        # DCMS's strings are display text; the field is still the bit.
        assert [(t[n]['nvme.cmd.identify.ctrl.nvmeof.fcatt'],
                 t[n]['nvme.cmd.identify.ctrl.nvmeof.fcatt.dcm']) for n in (36, 38)] == [
            ('0x01', 'True'), ('0x02', 'False')]

    def test_labels(self, dissect_pdml):
        p = pdml_section(dissect_pdml(self.FILE), self.SPAN)

        def label(frame, name):
            return p.field(frame, name)['showname']

        def show(frame, name):
            return p.field(frame, name)['show']

        # OWPASS 0h is 16 passes (Figure 388); 3 needs no gloss.
        assert show(1, 'nvme.cmd.sanitize.dword10.owpass') == '0x00000003'
        assert 'passes)' not in label(1, 'nvme.cmd.sanitize.dword10.owpass')
        assert show(2, 'nvme.cmd.sanitize.dword10.owpass') == '0x00000000'
        assert '(16 passes)' in label(2, 'nvme.cmd.sanitize.dword10.owpass')
        # DUR/DUW are thousands of 512-byte units, rounded up (Figure 210).
        assert label(4, 'nvme.cmd.get_logpage.smart.dur').endswith(
            decimal_forms('(<= 1000.00 TiB)'))
        assert label(4, 'nvme.cmd.get_logpage.smart.duw').endswith(
            decimal_forms('(<= 1.95 PiB)'))
        # Bit-position prefixes show which bits each mask covers.
        for frame, name, prefix in (
                (6, 'nvme.cmd.get_logpage.errinf.sf.val', '0000 0011 0000 001. ='),
                (6, 'nvme.cmd.get_logpage.errinf.sf.ptag', '.... .... .... ...1 ='),
                (11, 'nvme.cmd.set_features.dword11.irqc.thr',
                 '.... .... .... .... .... .... 0001 1111 ='),
                (11, 'nvme.cmd.set_features.dword11.irqc.time',
                 '.... .... .... .... 1100 1000 .... .... ='),
                (11, 'nvme.cmd.set_features.dword11.irqc.rsvd',
                 '0000 0000 0000 0000 .... .... .... .... ='),
                (22, 'nvme.cmd.identify.ctrl.oaes.rsvd2',
                 '.... .... .... .1.. .... .... .... .... ='),
                (22, 'nvme.cmd.identify.ctrl.oaes.rlcc',
                 '.... .... .1.. .... .... .... .... .... ='),
                (22, 'nvme.cmd.identify.ctrl.oaes.rsvd3',
                 '.... .101 0... .... .... .... .... .... ='),
                (22, 'nvme.cmd.identify.ctrl.oaes.rsvd4',
                 '.101 .... .... .... .... .... .... .... =')):
            assert label(frame, name).startswith(prefix), (name, label(frame, name))
        # SPROG FFFFh is the not-applicable sentinel, not 99.998%.
        assert 'not applicable' in label(8, 'nvme.cmd.get_logpage.sanitize.sprog')
        assert '%' not in label(8, 'nvme.cmd.get_logpage.sanitize.sprog')
        assert label(10, 'nvme.cmd.get_logpage.sanitize.sprog').endswith(
            decimal_forms('(25.00% complete)'))
        assert 'Overwrite Passes Completed (OPC)' in label(
            8, 'nvme.cmd.get_logpage.sanitize.sstat.opc')
        # THR is 0's based (Figure 474).
        assert '1f (32)' in label(11, 'nvme.cmd.set_features.dword11.irqc.thr')
        assert '7 (8)' in label(14, 'nvme.cqe.dword0.get_features.irqc.thr')
        # ACWU is 0's based logical blocks; 0h may also mean unsupported.
        assert label(16, 'nvme.cmd.identify.ctrl.acwu').endswith('8 logical blocks')
        acwu0 = label(18, 'nvme.cmd.identify.ctrl.acwu')
        assert '1 logical block' in acwu0 and 'Compare and Write is not supported' in acwu0
        # Bits whose meaning is not "supported: True/False".
        assert 'Host Identifier required to be non-zero' in label(
            22, 'nvme.cmd.identify.ctrl.ctratt.rhii')
        assert label(24, 'nvme.cmd.identify.ctrl.ctratt.rhii').endswith('Not reported')
        assert show(20, 'nvme.cmd.identify.ctrl.lpa') == '0xb5'
        assert label(20, 'nvme.cmd.identify.ctrl.lpa').endswith('(LPA): 0xb5')
        # ONCS Support Variants: a cleared bit points at the limit field.
        assert label(30, 'nvme.cmd.identify.ctrl.oncs.dsms').endswith(
            'Supported; DMRL, DMSL and DMRSL give the limits, if any')
        for name, figure_name, limit in (
                ('nvme.cmd.identify.ctrl.oncs.wus', 'Write Uncorrectable Support Variants',
                 'WUSL'),
                ('nvme.cmd.identify.ctrl.oncs.dsms', 'Dataset Management Support Variants',
                 None),
                ('nvme.cmd.identify.ctrl.oncs.wzs', 'Write Zeroes Support Variants', 'WZSL'),
                ('nvme.cmd.identify.ctrl.oncs.vers', 'Verify Support (NVMVFYS)', 'VSL')):
            text = label(30, name)
            assert figure_name in text and 'Supports ' not in text, text
            assert 'Support Write' not in text, text
            if limit:
                assert text.endswith(f'Support indicated by a non-zero {limit} instead'), text
        assert label(30, 'nvme.cmd.identify.ctrl.fna.fnvmbs').endswith(
            'Broadcast NSID (FFFFFFFFh) not supported')
        assert label(32, 'nvme.cmd.identify.ctrl.fna.fnvmbs').endswith(
            'Broadcast NSID (FFFFFFFFh) supported')
        assert label(34, 'nvme.cmd.identify.ctrl.sgls.sdt').endswith(
            'SGL Descriptor Threshold (SDT): 90')
        assert label(36, 'nvme.cmd.identify.ctrl.nvmeof.fcatt.dcm').endswith(
            'Static controller model')
        assert label(38, 'nvme.cmd.identify.ctrl.nvmeof.fcatt.dcm').endswith(
            'Dynamic controller model')
        assert label(40, 'nvme.cmd.get_logpage.smart.ipm.ipms').endswith(
            'Interval Power Measurement Scale: 0.01 W (0x2)')
        # SMART Reserved is 511:244, after OLEC (232) and IPM.
        rsvd = p.field(40, 'nvme.cmd.get_logpage.smart.rsvd1')
        assert rsvd['size'] == '268'
        assert int(rsvd['pos']) == int(p.field(40, 'nvme.cmd.get_logpage.smart.olec')['pos']) + 12


class TestNvmeMiSlicedContext:
    """A snaplen-sliced request publishes no request context."""

    FILE = 'nvme-mi-sliced-context.pcapng'

    def test_decode(self, assert_frames_match):
        assert_frames_match(self.FILE, [
            (1, ('nvme-mi.admin.opcode == 0x06 && nvme-mi.admin.doff == 0 && nvme-mi.admin.dlen == 64'
                 ' && !nvme-mi.admin.truncated && !_ws.short')),
            (2, 'nvme.cmd.identify.ctrl.vid == 0x144d && !nvme-mi.admin.invalid_dlen'),
            # The opcode was captured; no SQE field after it was.
            (3, ('nvme-mi.admin.opcode == 0x06 && !nvme-mi.admin.truncated && _ws.short'
                 ' && !nvme-mi.admin.doff && !nvme-mi.admin.dlen')),
            # No CNS was captured, so no Identify Namespace decode and no DLEN
            # complaint; the data stays raw.
            (4, ('!nvme.cmd.identify.ns.nsze && !nvme.cmd.identify.ns.ncap'
                 ' && !nvme.cmd.identify.ns.nuse && !nvme.cmd.identify.ns.nsfeat'
                 ' && !nvme.cmd.identify.ns.nlbaf && !nvme.cmd.identify.ns.flbas'
                 ' && !nvme.cmd.identify.ns.mc && !nvme-mi.admin.invalid_dlen && nvme-mi.admin.data')),
            (5, ('nvme-mi.mi.opcode == 0x00 && !nvme-mi.mi.truncated && _ws.short'
                 ' && !nvme-mi.mi.rds.dtyp')),
            (6, ('!nvme-mi.mi.subsys.nump && !nvme-mi.mi.subsys.mjr && !nvme-mi.mi.subsys.mnr'
                 ' && nvme-mi.mi.data')),
            (7, 'nvme-mi.mi.opcode == 0x04 && !nvme-mi.mi.truncated && _ws.short'),
            (8, 'nvme-mi.mi.status == 0x00 && !nvme-mi.mi.data && !_ws.expert'),
            # Header only: no opcode is invented, and the responses are honest
            # orphans with raw data.
            (9, ('!nvme-mi.admin.truncated && _ws.short && !nvme-mi.admin.opcode'
                 ' && !nvme-mi.admin.data && !nvme-mi.admin.doff && !nvme-mi.admin.dlen')),
            (10, ('nvme-mi.admin.orphan_response && !nvme-mi.admin.opcode && nvme-mi.admin.data'
                  ' && !nvme.cmd.identify.ns.nsze && !nvme.cmd.identify.ctrl.vid'
                  ' && !nvme-mi.admin.invalid_dlen')),
            (11, ('!nvme-mi.mi.truncated && _ws.short && !nvme-mi.mi.opcode && !nvme-mi.mi.data'
                  ' && !nvme-mi.mi.rds.dtyp')),
            (12, ('nvme-mi.mi.orphan_response && !nvme-mi.mi.opcode && nvme-mi.mi.data'
                  ' && !nvme-mi.mi.subsys.mjr && !nvme-mi.mi.subsys.nump')),
            (13, ('nvme-mi.admin.opcode == 0x09 && !nvme-mi.admin.truncated && _ws.short'
                  ' && !nvme-mi.admin.data')),
            (14, 'nvme-mi.admin.opcode == 0x09 && !nvme-mi.admin.invalid_dlen'),
            # A body shorter than its fixed fields, cut right after byte 0:
            # nothing is left to render raw, and the frame must not throw.
            (15, ('nvme-mi.mi.opcode == 0x04 && nvme-mi.mi.truncated && !_ws.short'
                  ' && !nvme-mi.mi.data')),
            (16, 'nvme-mi.mi.status == 0x00 && !nvme-mi.mi.truncated && !_ws.expert'),
            (17, 'nvme-mi.mi.opcode == 0x04 && !nvme-mi.mi.truncated'),
            (18, ('nvme-mi.mi.status == 0x00 && nvme-mi.mi.truncated && !_ws.short'
                  ' && !nvme-mi.mi.data')),
            (19, ('nvme-mi.admin.opcode == 0x06 && nvme-mi.admin.truncated && !_ws.short'
                  ' && !nvme-mi.admin.data')),
            (20, 'nvme-mi.admin.status == 0x00 && !nvme-mi.admin.truncated'),
            (21, 'nvme-mi.admin.opcode == 0x06 && nvme-mi.admin.dlen == 64'),
            (22, ('nvme-mi.admin.status == 0x00 && nvme-mi.admin.truncated && !_ws.short'
                  ' && !nvme-mi.admin.data')),
            # One byte past the opcode was captured, and it is still shown.
            (23, ('nvme-mi.mi.opcode == 0x04 && nvme-mi.mi.truncated && !_ws.short'
                  ' && nvme-mi.mi.data == 00')),
            (24, 'nvme-mi.mi.status == 0x00 && !nvme-mi.mi.data'),
        ])
        # The complete MI twin in the types capture still selects its structure.
        assert_frames_match('nvme-mi-types.pcapng', [
            (73, 'nvme-mi.mi.opcode == 0x00 && nvme-mi.mi.rds.dtyp == 0'),
            (74, 'nvme-mi.mi.subsys.mjr == 2 && nvme-mi.mi.subsys.mnr == 1'),
        ])

    def test_field_values(self, fields_table):
        t = fields_table(self.FILE, (
            'nvme-mi', 'frame.cap_len', 'frame.len', '_ws.short', '_ws.expert.message',
            'nvme-mi.mi.truncated', 'nvme-mi.admin.truncated', 'nvme-mi.admin.invalid_dlen',
            'nvme-mi.response_to', 'nvme-mi.mic.status', 'nvme-mi.mic_unverified'))
        sliced = [3, 5, 7, 9, 11, 13, 15, 18, 19, 22, 23]
        assert list(column(t, 'nvme-mi')) == list(range(1, 25))
        # Two bytes in, one, none, and one short of a whole entry; then short
        # bodies one byte in, and the control two bytes in.
        assert {n: (r['frame.cap_len'], r['frame.len']) for n, r in t.items()
                if int(r['frame.cap_len']) < int(r['frame.len'])} == {
            3: ('26', '92'), 5: ('25', '40'), 7: ('25', '40'), 9: ('24', '92'),
            11: ('24', '40'), 13: ('87', '124'), 15: ('25', '33'), 18: ('25', '31'),
            19: ('25', '33'), 22: ('25', '31'), 23: ('26', '33')}
        assert list(column(t, 'nvme-mi.mi.truncated')) == [15, 18, 23]
        assert list(column(t, 'nvme-mi.admin.truncated')) == [19, 22]
        assert column(t, 'nvme-mi.admin.invalid_dlen') == {}
        assert list(column(t, '_ws.short')) == [3, 5, 7, 9, 11, 13]
        # The header was captured everywhere, so every pair links.
        assert {n: int(v) for n, v in column(t, 'nvme-mi.response_to').items()} == {
            2: 1, 4: 3, 6: 5, 8: 7, 10: 9, 12: 11, 14: 13, 16: 15, 18: 17, 20: 19,
            22: 21, 24: 23}
        # Every frame still carries a MIC verdict; the sliced ones cannot verify.
        assert {n: v for n, v in column(t, 'nvme-mi.mic.status').items()} == {
            n: '3' if n in sliced else '1' for n in range(1, 25)}
        assert list(column(t, 'nvme-mi.mic_unverified')) == sliced

    def test_no_pass_or_selection_fabricates_a_selector(self, tshark_fields):
        """Output parity across passes and printed frames (a -Y run still
        dissects every frame, so this is not a first-visit model)."""
        fields = ('frame.number', 'nvme.cmd.identify.ns.nsze', 'nvme-mi.mi.subsys.mjr',
                  'nvme-mi.mi.subsys.mnr', 'nvme-mi.admin.invalid_dlen', 'nvme-mi.admin.data',
                  'nvme-mi.mi.data')
        one = tshark_fields(self.FILE, fields=fields, separator='|')
        assert one == tshark_fields(self.FILE, fields=fields, separator='|', two_pass=True)
        selected = tshark_fields(self.FILE, 'frame.number in {4, 6, 10, 12}',
                                 fields=('nvme.cmd.identify.ns.nsze', 'nvme-mi.mi.subsys.mjr'))
        assert selected.split() == []


class TestNvmeMiMicIntegrity:
    """Failed-MIC slot policy, verdicts on throwing bodies and Appendix B payloads."""

    FILE = 'nvme-mi-types.pcapng'
    SECTION = 8
    # Canonical CRC-32C (Figure 21) over the 4-byte header (84h 20h 00h 00h)
    # plus each payload, computed independently of the generator, and the
    # covered span's length.
    KAT_FRAMES = (
        (12, 0x8862A7EF, 36),   # Figure 200, 32 x 00h
        (13, 0x605B3A06, 36),   # Figure 201, 32 x FFh
        (14, 0x189529BC, 34),   # Figure 202, 30 incrementing
        (15, 0x13CC4A19, 36),   # Figure 203, 32 decrementing
        (16, 0xB2307DC6, 33),   # 29-byte payload, residue 1
        (17, 0x11150329, 35),   # 31-byte payload, residue 3
    )
    LINKS = ('nvme-mi.response_to', 'nvme-mi.response_time', 'nvme-mi.response_in')

    def table(self, fields_table, prefs=None, two_pass=False):
        return section(fields_table(self.FILE, (
            'nvme-mi', 'nvme-mi.type', 'frame.len', '_ws.expert.message', 'nvme-mi.mic',
            'nvme-mi.mic.status', 'nvme-mi.mic_bad', 'nvme-mi.mic_unverified', 'nvme-mi.mctp-ic',
            'nvme-mi.mi.orphan_response',
            'nvme-mi.resp_vendor', 'nvme-mi.resp_reserved', 'nvme-mi.resp_undefined',
            'nvme-mi.control.truncated', *self.LINKS), prefs=prefs, two_pass=two_pass), self.SPAN)

    def test_decode(self, assert_frames_match):
        assert_frames_match(self.FILE, at(self.SPAN, [
            (3, 'nvme-mi.mic.status == 0 && nvme-mi.mic_bad'),
            # By default a bad-MIC request still opens its slot.
            (4, 'nvme-mi.response_to == 3 && !nvme-mi.mi.orphan_response'),
            # Figure 29: E0h-FFh is Vendor Specific, not the Generic Error
            # layout; the three bytes are resp_vendor.
            (11, 'nvme-mi.mi.status == 0xe0 && nvme-mi.resp_vendor == aa:bb:cc && nvme-mi.mi.data == 11:22'),
            # The verdict is emitted before the body, so a body that cannot be
            # read does not hide it.
            (18, 'nvme-mi.mic.status == 1 && !_ws.short && !_ws.expert'),
            (19, 'nvme-mi.mic.status == 3 && nvme-mi.mic_unverified && !_ws.short && !nvme-mi.mi.truncated'),
            (20, 'nvme-mi.mic.status == 3 && nvme-mi.mic_unverified && _ws.short && !nvme-mi.mi.truncated'),
            # A bad verdict and an undecodable body coexist.
            (21, 'nvme-mi.mic.status == 0 && nvme-mi.mic_bad && nvme-mi.mi.truncated && !_ws.short'),
            (22, ('nvme-mi.control.opcode == 0x03 && nvme-mi.control.cesf == 1'
                  ' && nvme-mi.mic.status == 1 && !_ws.expert')),
            (23, ('nvme-mi.control.status == 0x00 && nvme-mi.control.mes.ssta == 0'
                  ' && nvme-mi.mic.status == 1 && !_ws.expert')),
            # The CP body cut by the capture is short; the verdict survives.
            (24, ('!nvme-mi.control.truncated && nvme-mi.mic && nvme-mi.mic.status == 3'
                  ' && nvme-mi.mic_unverified && _ws.short && nvme-mi.control.opcode == 3'
                  ' && !nvme-mi.control.cpsp')),
        ]))
        # A bad-MIC response answers and closes nothing, but keeps its opcode.
        assert_frames_match(self.FILE, at(self.SPAN, [
            (5, 'nvme-mi.response_in == 7'),
            (6, ('!nvme-mi.response_to && !nvme-mi.response_time && nvme-mi.mic.status == 0'
                 ' && nvme-mi.mic_bad && nvme-mi.mi.opcode == 0x01 && !nvme-mi.mi.orphan_response')),
            (7, 'nvme-mi.response_to == 5 && !nvme-mi.mi.orphan_response && nvme-mi.mic.status == 1'),
        ]), two_pass=True)

    def test_verdicts_and_values(self, fields_table, dissect_pdml):
        t = self.table(fields_table)

        def where(field, value):
            return [n for n, v in column(t, field).items() if v == value]

        assert list(column(t, 'nvme-mi')) == list(range(1, 25))
        # Which integer the field shows is display policy; whether a frame's
        # MIC matches is not, so these sets pin the convention too.
        assert where('nvme-mi.mic.status', '0') == list(column(t, 'nvme-mi.mic_bad')) == [3, 6, 21]
        assert where('nvme-mi.mic.status', '1') == [1, 2, 4, 5, 7, 10, 11, 12, 13, 14, 15, 16,
                                                    17, 18, 22, 23]
        assert where('nvme-mi.mic.status', '3') == [19, 20, 24]
        assert list(column(t, 'nvme-mi.mic')) == [n for n in range(1, 25) if n not in (8, 9)]
        # F3 corrupts F1's MIC, so it should have carried F1's value.
        assert t[3]['_ws.expert.message'] == (
            'Message Integrity Check does not match the computed CRC-32C [should be 0x3677d4d2]')
        assert t[1]['nvme-mi.mic'] == '0x3677d4d2'
        # The IC = 0 pair is shown as sent.
        assert where('nvme-mi.mctp-ic', 'False') == [8, 9]
        assert column(t, 'nvme-mi.mi.orphan_response') == {}
        # F19 and F20 report the same MIC and verdict.
        assert [t[19]['nvme-mi.mic'], t[19]['nvme-mi.mic.status']] == [
            t[20]['nvme-mi.mic'], t[20]['nvme-mi.mic.status']]
        assert list(column(t, 'nvme-mi.resp_vendor')) == [11]
        assert column(t, 'nvme-mi.resp_reserved') == column(t, 'nvme-mi.resp_undefined') == {}
        assert list(column(t, 'nvme-mi.control.truncated')) == []
        vendor = pdml_section(dissect_pdml(self.FILE), self.SPAN).field(11, 'nvme-mi.resp_vendor')
        status = pdml_section(dissect_pdml(self.FILE), self.SPAN).field(11, 'nvme-mi.mi.status')
        assert (vendor['size'], int(vendor['pos']) - int(status['pos'])) == ('3', 1)
        # Appendix B: each NMIMT 4h frame verifies with the reference's MIC
        # over a span of every length residue (16 SLL + 4 MCTP header bytes).
        kat = [n for n, v in column(t, 'nvme-mi.type').items() if int(v, 0) == 4]
        assert {n: (int(t[n]['nvme-mi.mic'], 16), t[n]['nvme-mi.mic.status'],
                    int(t[n]['frame.len']) - 24) for n in kat} == {
            n: (mic, '1', span) for n, mic, span in self.KAT_FRAMES}
        assert {span % 4 for _, _, span in self.KAT_FRAMES} == {0, 1, 2, 3}

    def test_links_with_and_without_mic_checking(self, fields_table):
        """A bad-MIC request still opens its slot; with check_mic off no
        verdict exists, so F6 answers F5 too."""
        def links(t):
            return {n: int(v) for n, v in column(t, 'nvme-mi.response_to').items()}

        default = self.table(fields_table, two_pass=True)
        assert links(default) == {2: 1, 4: 3, 7: 5, 9: 8, 11: 10, 23: 22}
        assert list(column(default, 'nvme-mi.response_in')) == [1, 3, 5, 8, 10, 22]
        unchecked = self.table(fields_table, {'nvme-mi.check_mic': 'FALSE'})
        assert links(unchecked) == {2: 1, 4: 3, 6: 5, 9: 8, 11: 10, 23: 22}
        assert [v for v in column(unchecked, 'nvme-mi.mic.status').values() if v in ('0', '1')] == []
        assert column(unchecked, 'nvme-mi.mic_unverified') == {}

    def test_links_are_read_back(self, fields_table, tshark_fields):
        """Decided once on the first pass and recorded per frame: a second
        pass or a selected frame returns it rather than recomputing."""
        one = self.table(fields_table)
        two = self.table(fields_table, two_pass=True)
        for frame in one:
            assert [one[frame][f] for f in self.LINKS[:2]] == [two[frame][f] for f in self.LINKS[:2]]
        fields = ('frame.number', *self.LINKS)
        selected = in_section(tshark_fields, self.SPAN)(
            self.FILE, 'frame.number in {3, 4, 5, 6, 7}', fields=fields, separator='|',
            two_pass=True)
        assert selected.strip().splitlines() == [
            '|'.join([str(n), *(two[n][f] for f in self.LINKS)]) for n in range(3, 8)]


class TestNvmeMiSlotLifecycle:
    """Command Slot handling of responses it should not accept."""

    FILE = 'nvme-mi-transactions.pcapng'
    SECTION = 1
    # From the deterministic wire/lifecycle table, not runtime output.
    LINKS = (
        (3, 1), (5, 4), (8, 6), (9, 7), (11, 10), (13, 12), (14, 10), (17, 15),
        (19, 18), (21, 20), (23, 22), (25, 24), (27, 26), (29, 28), (31, 30),
        (34, 33), (36, 32), (37, 35), (40, 39), (42, 38), (43, 41), (46, 45),
        (48, 44), (49, 47), (52, 51), (54, 50), (55, 53), (58, 57), (60, 56),
        (61, 59), (64, 63), (66, 62), (67, 65), (70, 69), (72, 68), (73, 71),
        (78, 74), (79, 77), (84, 80), (85, 83), (88, 87), (90, 86), (91, 89),
        (94, 93), (96, 92), (97, 95), (100, 99), (102, 101), (103, 98),
        (105, 104), (107, 106), (109, 108), (111, 110), (116, 114), (117, 98),
        (119, 118), (122, 120), (124, 123), (126, 120), (130, 129), (134, 133),
        (135, 120), (137, 136), (139, 138), (140, 136), (141, 136), (143, 142),
        (151, 120), (153, 152), (155, 154), (160, 158), (162, 161), (166, 163),
        (169, 167), (171, 170), (172, 168), (175, 173), (177, 176), (178, 174),
    )
    SUPERSEDED = (7, 53, 59, 65, 71, 77, 83, 89, 95, 168)
    REPLAY_OF = ((14, 11), (126, 122), (135, 122), (140, 137), (149, 122), (151, 122))
    SOM_ONLY = frozenset({121, 125, 127, 131, 144, 146, 148, 150, 156, 159, 164})
    ORPHANS = (128, 132, 145, 147, 157, 165)

    def test_decode(self, assert_frames_match):
        conditions = defaultdict(list)

        def need(frame, condition):
            conditions[frame].append(condition)

        # No STATUS, no closure (Figure 28); a status-only response closes.
        need(2, 'nvme-mi.status_absent && _ws.malformed && !nvme-mi.response_to'
                ' && !nvme-mi.response_time')
        need(3, 'nvme-mi.response_to == 1 && !nvme-mi.admin.orphan_response')
        need(5, 'nvme-mi.response_to == 4')
        # A CP response that does not echo the Tag is refused, still decoded.
        need(16, 'nvme-mi.control.tag_mismatch && !nvme-mi.response_to && !nvme-mi.response_time'
                 ' && nvme-mi.control.opcode == 0x03 && nvme-mi.control.tag == 0xb2')
        need(17, 'nvme-mi.response_to == 15 && !nvme-mi.control.tag_mismatch')
        # A replay arrives on the Replay primitive's tag (4.2.1.5).
        need(13, 'nvme-mi.response_to == 12 && nvme-mi.control.opcode == 0x04')
        need(14, '!nvme-mi.mi.orphan_response && nvme-mi.response_to == 10'
                 ' && nvme-mi.replay_of == 11 && nvme-mi.replay_request == 12')
        # Only Success with CPAS 0/1/2 releases occupancy (Figures 29/42).
        for frame, cond in ((34, 'nvme-mi.control.cpas == 0 && nvme-mi.control.status == 0'),
                            (40, 'nvme-mi.control.cpas == 1 && nvme-mi.control.status == 0'),
                            (46, 'nvme-mi.control.cpas == 2 && nvme-mi.control.status == 0'),
                            (52, 'nvme-mi.control.status == 8 && !nvme-mi.control.cpas'),
                            (58, 'nvme-mi.control.status == 2 && !nvme-mi.control.cpas'),
                            (64, 'nvme-mi.control.cpas == 3 && nvme-mi.control.status == 0')):
            need(frame, cond)
        for frame in (35, 41, 47, 174):
            need(frame, '!nvme-mi.req_superseded')
        for frame in self.SUPERSEDED:
            need(frame, 'nvme-mi.req_superseded')
        for base in range(32, 93, 6):
            need(base + 4, f'nvme-mi.response_to == {base}')
        need(70, 'nvme-mi.response_to == 69')
        need(94, 'nvme-mi.response_to == 93')
        # Get State reports the slot state as sent (Figure 43).
        for frame in (102, 105):
            need(frame, 'nvme-mi.control.mes.ssta == 2')
        need(116, 'nvme-mi.response_to == 114')
        # A partial replay is associated, kept raw, and noted once.
        need(135, 'nvme-mi.response_to == 120 && nvme-mi.replay_request == 133'
                  ' && nvme-mi.partial_replay && nvme-mi.replay_data'
                  ' && _ws.expert.severity == 0x00400000 && !nvme-mi.mi.status'
                  ' && !nvme-mi.mi.opcode && !nvme-mi.mic_bad && !nvme-mi.mic_unverified'
                  ' && !nvme-mi.mi.orphan_response')
        # Replay is one-shot and scoped: nothing else borrows its history.
        need(126, 'nvme-mi.response_to == 120 && nvme-mi.replay_of == 122')
        for frame in self.ORPHANS:
            need(frame, 'nvme-mi.mi.orphan_response && !nvme-mi.response_to && !nvme-mi.replay_of')
        need(130, 'nvme-mi.control.rr == 0 && !nvme-mi.mi.orphan_response')
        need(149, 'nvme-mi.mic_bad && !nvme-mi.response_to && nvme-mi.replay_of == 122')
        need(151, 'nvme-mi.response_to == 120 && nvme-mi.replay_of == 122')
        # A replayed MPR is not a second interim.
        need(137, 'nvme-mi.response_to == 136 && nvme-mi.response_is_mpr && nvme-mi.mprt == 10')
        need(140, 'nvme-mi.response_to == 136 && nvme-mi.replay_mpr'
                  ' && !nvme-mi.response_is_mpr && nvme-mi.mprt == 4')
        need(141, 'nvme-mi.response_to == 136 && !nvme-mi.response_is_mpr')
        # A late completion keeps the newer request and the other slot.
        for frame, req in ((169, 167), (172, 168), (175, 173), (178, 174)):
            need(frame, f'nvme-mi.response_to == {req}')
        assert_frames_match(self.FILE, at(self.SPAN, [(f, ' && '.join(c)) for f, c in sorted(conditions.items())]))

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_censuses(self, fields_table, two_pass):
        """Every link, census and response time; the commit decision is taken
        once, so both passes agree."""
        t = section(fields_table(self.FILE, (
            'nvme-mi', 'nvme-mi.response_to', 'nvme-mi.response_time', 'nvme-mi.response_in',
            'nvme-mi.status_absent', 'nvme-mi.req_superseded',
            'nvme-mi.control.tag_mismatch', 'nvme-mi.partial_replay',
            'nvme-mi.response_is_mpr', 'nvme-mi.replay_mpr', 'nvme-mi.mi.orphan_response',
            'nvme-mi.admin.orphan_response', 'nvme-mi.mic_bad', 'nvme-mi.replay_of',
            'nvme-mi.mic', 'nvme-mi.mi.opcode', 'nvme-mi.admin.opcode', 'nvme-mi.control.opcode',
            'nvme-mi.response_csi_mismatch'),
            two_pass=two_pass), self.SPAN)

        def frames(field):
            return list(column(t, field))

        links = dict(self.LINKS)
        replays = dict(self.REPLAY_OF)
        assert len(t) == 178
        # Eleven first fragments assemble only at their EOM.
        assert frames('nvme-mi') == [n for n in range(1, 179) if n not in self.SOM_ONLY]
        assert {n: int(v) for n, v in column(t, 'nvme-mi.response_to').items()} == links
        # Response Time only where Request In is, from request EOM to
        # response SOM (fragmented replays start earlier).
        starts = {122: 121, 126: 125, 151: 150, 160: 159}
        assert {n: float(v) for n, v in column(t, 'nvme-mi.response_time').items()} == {
            f: starts.get(f, f) - req for f, req in links.items()}
        assert {
            field: frames(field) for field in (
                'nvme-mi.status_absent', 'nvme-mi.req_superseded',
                'nvme-mi.control.tag_mismatch', 'nvme-mi.partial_replay',
                'nvme-mi.response_is_mpr', 'nvme-mi.replay_mpr', 'nvme-mi.mi.orphan_response',
                'nvme-mi.mic_bad', 'nvme-mi.response_csi_mismatch')} == {
            'nvme-mi.status_absent': [2],
            # Occupancy is per endpoint, not per tag (1.8.15, 4.2).
            'nvme-mi.req_superseded': list(self.SUPERSEDED),
            'nvme-mi.control.tag_mismatch': [16, 76, 115],
            'nvme-mi.partial_replay': [135],
            'nvme-mi.response_is_mpr': [103, 137],
            'nvme-mi.replay_mpr': [140],
            'nvme-mi.mi.orphan_response': list(self.ORPHANS),
            'nvme-mi.mic_bad': [82, 87, 113, 149],
            # Still paired by TAG; Pause and Resume name no slot (4.2.1.1-2).
            'nvme-mi.response_csi_mismatch': [19, 21, 23, 70, 109]}
        assert all(not t[n]['nvme-mi.response_csi_mismatch'] for n in (25, 27, 29, 31))
        # No frame both links and calls itself unusable.
        assert [n for n, r in t.items() if r['nvme-mi.response_to'] and (
            r['nvme-mi.status_absent'] or r['nvme-mi.control.tag_mismatch']
            or r['nvme-mi.mi.orphan_response'] or r['nvme-mi.admin.orphan_response'])] == []
        assert {n: int(v) for n, v in column(t, 'nvme-mi.replay_of').items()} == replays
        # An RRO 1 replay carries the original MIC, not a CRC over its suffix.
        assert len({t[n]['nvme-mi.mic'] for n in (122, 126, 135, 151)} - {''}) == 1
        if two_pass:
            # Replay never overwrites Response In; an MPR never installs one.
            assert {n: int(v) for n, v in column(t, 'nvme-mi.response_in').items()} == {
                req: rsp for rsp, req in self.LINKS if rsp not in replays and rsp not in (103, 137)}
        else:
            opcodes = {n: [int(r[f], 0) for f in ('nvme-mi.mi.opcode', 'nvme-mi.admin.opcode',
                                                  'nvme-mi.control.opcode') if r[f]]
                       for n, r in t.items()}
            assert {n for n, v in opcodes.items() if v} == (
                set(range(1, 179)) - self.SOM_ONLY - set(self.ORPHANS) - {135})
            assert all(len(v) <= 1 for v in opcodes.values())
            assert {f: opcodes[f][0] for f in (14, 19, 21, 23, 126, 140, 149, 151)} == {
                14: 1, 19: 2, 21: 3, 23: 4, 126: 5, 140: 1, 149: 5, 151: 5}

    def test_one_expert_on_frame_135(self, dissect_pdml):
        p = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        assert len(p.experts(135)) == 1
        assert p.fields(135, 'nvme-mi.partial_replay')

    def test_control_expert_json_anchors(self, cmd_tshark, capture_file, test_env):
        """The expert sits under its Tag field, not the body."""
        stdout = subprocess.check_output([
            cmd_tshark, '-r', capture_file(self.FILE),
            '-Y', 'frame.number in {16}', '-Tjson', '-x',
        ], encoding='utf-8', env=test_env)
        expectations = {
            16: ('nvme-mi.control.tag', 'nvme-mi.control.tag_mismatch', 25, 1),
        }

        def objects(value):
            if isinstance(value, dict):
                yield value
                for child in value.values():
                    yield from objects(child)
            elif isinstance(value, list):
                for child in value:
                    yield from objects(child)

        seen = set()
        for packet in json.loads(stdout):
            layers = packet['_source']['layers']
            frame = int(layers['frame']['frame.number'])
            field, expert, pos, size = expectations[frame]
            container, = [obj for obj in objects(layers) if field + '_raw' in obj]
            assert container[field + '_raw'][1:3] == [pos, size]
            assert expert in json.dumps(container[field + '_tree'])
            seen.add(frame)
        assert seen == set(expectations)


class TestNvmeMiResetOwedNothing:
    """A Reset NVM Subsystem is owed no response, whatever follows byte 11 (MI 2.2 5.9)."""

    FILE = 'nvme-mi-mi-commands.pcapng'
    SECTION = 8
    EVENTS_SPAN = (75, 204)   # TestNvmeMiMiEventsConfig's section

    def test_sliced(self, fields_table):
        t = section(fields_table(self.FILE, (
            'nvme-mi', 'frame.cap_len', 'frame.len', 'nvme-mi.mi.opcode',
            'nvme-mi.mi.truncated', 'nvme-mi.prev_no_response', 'nvme-mi.req_superseded',
            'nvme-mi.response_to', '_ws.malformed.expert')), self.SPAN)
        assert list(column(t, 'nvme-mi')) == list(range(1, 10))
        assert {n: (r['frame.cap_len'], r['frame.len']) for n, r in t.items()
                if r['frame.cap_len'] != r['frame.len']} == {1: ('32', '40'), 4: ('31', '40')}
        # Every Reset's opcode was captured; F1 and F4 are cut by the capture,
        # F7's reported body is short.
        assert list(column(t, 'nvme-mi.mi.truncated')) == [7]
        assert {n: t[n]['nvme-mi.mi.opcode'] for n in (1, 4, 7)} == dict.fromkeys(
            (1, 4, 7), '0x07')
        assert column(t, 'nvme-mi.prev_no_response') == {2: '1'}
        assert list(column(t, 'nvme-mi.req_superseded')) == [5, 8]
        assert {n: int(v) for n, v in column(t, 'nvme-mi.response_to').items()} == {
            3: 2, 6: 5, 9: 8}
        assert column(t, '_ws.malformed.expert') == {}

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_body_disabled(self, tshark_fields, two_pass):
        fields = ('frame.number', 'nvme-mi', 'nvme-mi.mi', 'nvme-mi.prev_no_response',
                  'nvme-mi.req_superseded')
        out = tshark_fields(self.FILE, fields=fields, two_pass=two_pass,
                            args=('--disable-protocol', 'nvme-mi.mi'))
        rows = {}
        for line in out.splitlines():
            number, *values = line.split('\t')
            rows[int(number)] = dict(zip(fields[1:], values))
        assert column(rows, 'nvme-mi') and column(rows, 'nvme-mi.mi') == {}
        # As with the body: TestNvmeMiMiEventsConfig F1-F9 (RSTTYP 00h, 01h,
        # 02h) and this class's section.
        for span in (self.EVENTS_SPAN, self.SPAN):
            t = section(rows, span)
            assert column(t, 'nvme-mi.prev_no_response') == {2: '1'}, span
            assert list(column(t, 'nvme-mi.req_superseded')) == [5, 8], span


class TestNvmeMiMiEventsConfig:
    """Reset validity and Management Endpoint Buffer routing."""

    FILE = 'nvme-mi-mi-commands.pcapng'
    SECTION = 2
    FIELDS = (
        'nvme-mi', 'nvme-mi.ror', '_ws.expert', '_ws.expert.message', 'nvme-mi.mi.rds.dtyp',
        'nvme-mi.mi.reserved_dtyp', 'nvme-mi.mi.reserved_value', 'nvme-mi.prev_no_response',
        'nvme-mi.req_superseded', 'nvme-mi.meb',
        'nvme-mi.mi.meb_routed', 'nvme-mi.mi.request_data_length',
        'nvme-mi.mi.response_data_length', 'nvme-mi.mic_bad', 'nvme-mi.mi.truncated',
        'nvme-mi.mi.data_routing', 'nvme-mi.response_to', 'nvme-mi.response_in',
        'nvme-mi.response_time', 'nvme-mi.mi.orphan_response', 'nvme-mi.admin.orphan_response',
        'nvme-mi.mi.opcode', 'nvme-mi.admin.opcode', 'nvme-mi.mi.port.cmeaddr',
        'nvme-mi.mi.port.mebs')

    def test_decode(self, assert_frames_match):
        # MEB routing needs both sources (DTYP 05h list and non-zero MEBS),
        # the matching port and membership, at request time (4.2.3).
        controls = (19, 23, 27, 47, 49, 53, 59, 66, 72, 78, 84, 90, 96, 102, 106, 112, 118)
        assert_frames_match(self.FILE, at(self.SPAN, [
            (2, 'nvme-mi.prev_no_response == 1'),
            # A Reserved Reset is an ordinary unanswered predecessor.
            (5, 'nvme-mi.req_superseded && !nvme-mi.prev_no_response'),
            (8, 'nvme-mi.req_superseded && !nvme-mi.prev_no_response'),
            # Responses to a Reset NVM Subsystem pair as usual.
            (11, 'nvme-mi.response_to == 10 && nvme-mi.mi.status == 0x00'),
            (17, 'nvme-mi.response_to == 16 && nvme-mi.mi.status == 0x02'),
            # Capability-free MEB requests raise no routing expert (F14 is
            # also exempt by 5.2.4); the inline data really is there.
            (12, ('nvme-mi.meb == 1 && nvme-mi.admin.dlen == 8 && nvme-mi.admin.opcode == 0x09'
                  ' && nvme-mi.admin.data == 41:42:43:44:45:46:47:48')),
            (14, 'nvme-mi.meb == 1 && nvme-mi.mi.opcode == 0x03'),
            (21, 'nvme-mi.mi.cmdlist.numcmd == 3 && nvme-mi.response_to == 20'),
            (29, 'nvme-mi.mi.port.mebs == 4096 && nvme-mi.response_to == 28'),
            (30, 'nvme-mi.mi.meb_routed && nvme-mi.mi.opcode == 6 && !_ws.expert'),
            (32, 'nvme-mi.mi.meb_routed && !nvme-mi.mi.data && !nvme-mi.mi.vpd.data'),
            (35, ('nvme-mi.mi.meb_routed && nvme-mi.response_to == 34'
                  ' && nvme-mi.mi.data == 41:42:43:44:45:46:47:48 && !nvme-mi.mi.vpd.data'
                  ' && !_ws.expert')),
            (37, 'nvme-mi.mi.meb_routed && !nvme-mi.mi.data && !nvme-mi.mi.vpd.data'),
            *[(f, '!nvme-mi.mi.meb_routed && nvme-mi.mi.vpd.data')
              for f in (*controls, 38, 41)],
            (43, '!nvme-mi.mi.meb_routed'),
            (44, ('nvme-mi.meb == 1 && nvme-mi.mi.config.cid == 4 && nvme-mi.mi.ae.numaee == 2'
                  ' && !nvme-mi.mi.meb_routed')),
            (123, 'nvme-mi.mi.meb_routed'),
        ]))

    def test_censuses(self, fields_table):
        t = section(fields_table(self.FILE, self.FIELDS, two_pass=True), self.SPAN)

        def frames(field):
            return list(column(t, field))

        assert frames('nvme-mi') == list(range(1, 131))
        # Figure 125 reserves every RSTTYP but 00h, and only a Reset NVM
        # Subsystem is owed no response; the three displacements each carry
        # exactly one of the two notes.
        assert frames('nvme-mi.mi.reserved_value') == [4, 7]
        assert frames('nvme-mi.prev_no_response') == [2]
        assert frames('nvme-mi.req_superseded') == [5, 8]
        # DTYP 05h is a defined selector whatever the port's MEBS (F127, F129).
        assert frames('nvme-mi.mi.reserved_dtyp') == []
        assert [n for n, r in t.items() if r['nvme-mi.mi.rds.dtyp']
                and int(r['nvme-mi.mi.rds.dtyp'], 0) == 5 and r['nvme-mi.ror'] == 'False'][-2:] == [
            127, 129]
        assert [n for n, v in column(t, 'nvme-mi.meb').items() if n <= 17 and v == 'True'] == [12, 14]
        assert {f: frames(f) for f in (
            'nvme-mi.mi.meb_routed', 'nvme-mi.mi.request_data_length',
            'nvme-mi.mi.response_data_length', 'nvme-mi.mic_bad', 'nvme-mi.mi.truncated')} == {
            'nvme-mi.mi.meb_routed': [30, 31, 32, 33, 34, 35, 36, 37, 45, 113, 114, 123, 124],
            'nvme-mi.mi.request_data_length': [],
            # The three empty inline HSP responses, not unknown-route F15, and
            # F76's short Read Data Structure.
            'nvme-mi.mi.response_data_length': [3, 6, 9, 76],
            'nvme-mi.mic_bad': [56, 63],
            'nvme-mi.mi.truncated': [69, 82]}
        # AE Enable is inline but its response is not; MEB 0 stays inline.
        routing = {14: 1, 15: 0, 18: 0, 19: 0, 30: 2, 31: 2, 32: 2, 33: 2, 34: 2, 35: 2,
                   36: 2, 37: 2, 38: 1, 39: 1, 40: 1, 41: 1, 44: 1, 45: 2, 107: 0, 112: 0,
                   113: 2, 114: 2, 123: 2, 124: 2}
        assert {n: t[n]['nvme-mi.mi.data_routing'] for n in routing} == {
            n: str(r) for n, r in routing.items()}
        assert t[15]['_ws.expert'] == ''
        # Pairing and response times; no orphans (F63 is a bad-MIC response).
        pairs = {3: 2, 6: 5, 9: 8, 11: 10, 13: 12, 15: 14, 17: 16}
        pairs.update({f: f - 1 for f in range(19, 62, 2)})
        pairs[64] = 62
        pairs.update({f: f - 1 for f in range(66, 107, 2)})
        pairs.update({109: 108, 111: 110, 112: 107, 114: 113, 116: 115, 118: 117, 120: 119,
                      122: 121, 124: 123, 126: 125, 128: 127, 130: 129})
        assert {n: int(v) for n, v in column(t, 'nvme-mi.response_to').items()} == pairs
        assert {n: float(v) for n, v in column(t, 'nvme-mi.response_time').items()} == {
            f: f - req for f, req in pairs.items()}
        assert frames('nvme-mi.mi.orphan_response') == frames('nvme-mi.admin.orphan_response') == []
        assert sorted({*frames('nvme-mi.mi.opcode'), *frames('nvme-mi.admin.opcode')}) == list(
            range(1, 131))
        # Figure 119's CMEADDR in the 8-bit form (F120) proves the port; F25's
        # 3Bh is another port, so its probe F27 stays capability-free.
        assert {n: [t[n][f] for f in ('nvme-mi.mi.port.cmeaddr', 'nvme-mi.mi.port.mebs',
                                      'nvme-mi.mi.meb_routed')]
                for n in (25, 27, 120, 123, 124)} == {
            25: ['0x3b', '4096', ''], 27: ['', '', ''], 120: ['0x74', '4096', ''],
            123: ['', '', 'True'], 124: ['', '', 'True']}
        # A Reset owed no response frees the slot (F2 -> F3, F1 unanswered),
        # and history never borrows a later observation.
        assert {n: (t[n]['nvme-mi.response_in'], t[n]['nvme-mi.response_to'])
                for n in (1, 2, 3, 107, 112, 113, 114, 117, 118)} == {
            1: ('', ''), 2: ('3', ''), 3: ('', '2'), 107: ('112', ''), 112: ('', '107'),
            113: ('114', ''), 114: ('', '113'), 117: ('118', ''), 118: ('', '117')}

    def test_check_mic_off_does_not_invent_capability(self, fields_table):
        t = section(fields_table(self.FILE, ('nvme-mi.mi.meb_routed',),
                         prefs={'nvme-mi.check_mic': 'FALSE'}), self.SPAN)
        assert column(t, 'nvme-mi.mi.meb_routed') == {}

    def test_no_reset_or_routing_experts(self, dissect_pdml):
        p = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        messages = {n: p.experts(n) for n in p.packets if p.experts(n)}
        assert not [m for msgs in messages.values() for m in msgs
                    if 'no Success Response is transmitted' in m]
        assert not [n for n, msgs in messages.items()
                    if any('require buffer routing' in m for m in msgs)]

    def test_address_form_is_named(self, dissect_pdml):
        """Figure 119 does not say which form CMEADDR is in, so the item says
        which one matched; F25's 3Bh matches neither."""
        p = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        assert p.field(120, 'nvme-mi.mi.port.cmeaddr')['showname'].endswith(
            "0x74 (8-bit form of this port's 2-Wire address)")
        assert p.field(29, 'nvme-mi.mi.port.cmeaddr')['showname'].endswith(
            "0x3a (7-bit form of this port's 2-Wire address)")
        f25 = p.field(25, 'nvme-mi.mi.port.cmeaddr')['showname']
        assert f25.endswith('0x3b') and 'form of' not in f25


class TestNvmeMiMebPortLists:
    """DTYP 05h MEB Command Support Lists per port (MI 2.2 Figure 112)."""

    FILE = 'nvme-mi-mi-commands.pcapng'
    SECTION = 9

    def test_routing(self, fields_table):
        t = section(fields_table(self.FILE, (
            'nvme-mi', 'nvme-mi.meb', 'nvme-mi.mi.rds.portid', 'nvme-mi.mi.port.mebs',
            'nvme-mi.mi.cmdlist.numcmd', 'nvme-mi.mi.data_routing', 'nvme-mi.mi.meb_routed',
            'nvme-mi.response_to', '_ws.expert')), self.SPAN)
        assert list(column(t, 'nvme-mi')) == list(range(1, 33))
        # Every capability read was admitted: MEBS from Port Info, and each
        # port's list, for the port its request named.
        assert {n: int(v) for n, v in column(t, 'nvme-mi.mi.port.mebs').items()} == dict.fromkeys(
            (2, 10, 18, 30), 4096)
        assert {n: (t[n - 1]['nvme-mi.mi.rds.portid'], v)
                for n, v in column(t, 'nvme-mi.mi.cmdlist.numcmd').items()} == {
            4: ('7', '3'), 6: ('8', '1'), 12: ('8', '1'), 14: ('7', '3'),
            20: ('7', '1'), 22: ('8', '3'), 26: ('7', '3'), 28: ('8', '1')}
        assert [n for n, v in column(t, 'nvme-mi.meb').items() if v == 'True'] == [7, 15, 23, 31]
        # Port 7's own list decides: another port's list neither hides it
        # (F7, F31) nor stands in for it (F23).
        assert list(column(t, 'nvme-mi.mi.meb_routed')) == [7, 8, 15, 16, 31, 32]
        assert {n: t[n]['nvme-mi.mi.data_routing'] for n in (7, 8, 15, 16, 23, 24, 31, 32)} == {
            7: '2', 8: '2', 15: '2', 16: '2', 23: '0', 24: '0', 31: '2', 32: '2'}
        assert {n: int(v) for n, v in column(t, 'nvme-mi.response_to').items()} == {
            f: f - 1 for f in range(2, 33, 2)}
        assert column(t, '_ws.expert') == {}


class TestNvmeMiSubsystemInformation:
    """NVM Subsystem Information responses, well formed and malformed (Figure 115)."""

    FILE = 'nvme-mi-transactions.pcapng'
    SECTION = 2
    FIELDS = (
        'frame.interface_id', 'mctp.src', 'mctp.dst',
        'nvme-mi.mi.subsys.mjr', 'nvme-mi.mi.subsys.mnr', 'nvme-mi.mi.subsys.sre',
        'nvme-mi.mi.chds.csts.tcida', 'nvme-mi.mi.port.ciaps', 'nvme-mi.mi.port.aems',
        'nvme-mi.mic.status', 'nvme-mi.response_to', 'nvme-mi.response_in', '_ws.expert',
        '_ws.short', 'nvme-mi.mi.response_data_length', 'nvme-mi.mi.truncated')

    def test_decode(self, assert_frames_match):
        assert_frames_match(self.FILE, at(self.SPAN, [
            # NNSC bit 0 is conformant under 2.1 and 2.2; only its meaning
            # differs, so neither admitted advertisement is flagged.
            (4, 'nvme-mi.mi.subsys.sre == 1 && nvme-mi.mic.status == 1 && !_ws.expert'),
            (6, 'nvme-mi.mi.subsys.sre == 1 && nvme-mi.mic.status == 1 && !_ws.expert'),
            # A bad-MIC response renders but answers nothing.
            (17, '!nvme-mi.response_in'),
            (18, ('nvme-mi.mic.status == 0 && nvme-mi.mic_bad && !nvme-mi.response_to'
                  ' && !nvme-mi.response_time && nvme-mi.mi.subsys.mjr == 2'
                  ' && !nvme-mi.mi.orphan_response')),
            # Refused advertisements still render whatever they safely select.
            (22, 'nvme-mi.mi.response_data_length && nvme-mi.mic.status == 1 && !nvme-mi.mi.subsys.mnr'),
            (26, 'nvme-mi.mi.status == 0x02 && !nvme-mi.mi.subsys.mjr'),
            (29, 'nvme-mi.mi.orphan_response && !nvme-mi.mi.subsys.mjr && !nvme-mi.mi.subsys.mnr'),
            (31, 'nvme-mi.mi.chds.csts.tcida == 1'),
            (33, 'nvme-mi.mic.status == 3 && nvme-mi.mi.subsys.mnr == 2'),
            (41, 'nvme-mi.mi.rds.rdl == 4 && nvme-mi.mi.subsys.mnr == 2'),
            (49, 'nvme-mi.mi.rds.rdl == 32 && nvme-mi.mi.subsys.mnr == 2'),
            (53, ('nvme-mi.mi.rds.rdl == 0 && !nvme-mi.mi.subsys.mnr'
                  ' && len(nvme-mi.mi.response_surplus) == 32')),
            # M: the request's MIC is bad, though its DTYP was parsed.
            (56, 'nvme-mi.mic.status == 0 && nvme-mi.mi.rds.dtyp == 0'),
            (57, 'nvme-mi.mic.status == 1 && nvme-mi.response_to == 56 && nvme-mi.mi.subsys.mnr == 2'),
            # N: no DTYP, so no structure to choose; refusing to retain (F66)
            # and refusing to decode (F61) are different refusals.
            (60, ('!nvme-mi.mi.truncated && _ws.short && !nvme-mi.mi.rds.dtyp'
                  ' && nvme-mi.mi.opcode == 0x00')),
            (61, ('nvme-mi.response_to == 60 && nvme-mi.mi.data && !nvme-mi.mi.subsys.mjr'
                  ' && !nvme-mi.mi.subsys.mnr')),
            (66, ('nvme-mi.mi.rds.rdl == 32 && nvme-mi.mi.subsys.mjr == 2'
                  ' && nvme-mi.mi.subsys.mnr == 2')),
        ]))

    def test_fixture_shape_and_rendered_fields(self, fields_table):
        t = section(fields_table(self.FILE, self.FIELDS), self.SPAN)
        assert {frozenset((r['mctp.src'], r['mctp.dst'])) for r in t.values()} == {
            frozenset(('10', str(eid))) for eid in (8, 29, 46, 60, 77, 94, 111, 113, 130, 131,
                                                     132, 133, 134, 135, 136)}
        # Complete field-bearing prefixes render without admission; F22 has
        # no MNR, F29 no request, F53 selects nothing, F61 no DTYP.  F18 is
        # paired (it renders) but not credited (no Request In).
        assert {n: (r['nvme-mi.mi.subsys.mjr'], r['nvme-mi.mi.subsys.mnr'], r['nvme-mi.response_to'])
                for n, r in t.items() if r['nvme-mi.mi.subsys.mjr']} == {
            4: ('2', '2', '3'), 6: ('2', '1', '5'), 18: ('2', '2', ''), 33: ('2', '2', '32'),
            37: ('2', '3', '36'), 41: ('2', '2', '40'), 45: ('2', '2', '44'),
            49: ('2', '2', '48'), 57: ('2', '2', '56'), 66: ('2', '2', '65')}
        # 2.3 is in neither revision's table, and is not called Reserved.
        assert t[37]['_ws.expert'] == ''
        # CSTS bit 8 on every endpoint state.
        assert [n for n, r in t.items() if r['nvme-mi.mi.chds.csts.tcida'] == 'True'] == [
            2, 8, 10, 16, 20, 24, 28, 31, 35, 39, 43, 47, 51, 55, 59, 63, 68]
        assert [n for n, r in t.items() if r['nvme-mi.mi.port.ciaps'] == 'True'] == [12, 14]
        # Only extent contradictions are diagnosed.
        assert list(column(t, 'nvme-mi.mi.response_data_length')) == [22, 41, 45, 49, 53, 66]
        assert [n for n in column(t, '_ws.expert')
                if n not in {18, 19, 22, 29, 33, 41, 45, 49, 53, 56, 60, 66}] == []
        assert column(t, 'nvme-mi.mi.truncated') == {}
        assert t[60]['nvme-mi.mic.status'] == '3'
        assert list(column(t, '_ws.short')) == [60]
    def test_bad_mic_request_and_response_links(self, fields_table):
        """F17 is the only request left unanswered by its bad-MIC response."""
        t = section(fields_table(self.FILE, self.FIELDS, two_pass=True), self.SPAN)
        assert list(column(t, 'nvme-mi.response_in')) == [
            1, 3, 5, 7, 9, 11, 13, 15, 19, 21, 23, 25, 27, 30, 32, 34, 36, 38, 40, 42, 44, 46,
            48, 50, 52, 54, 56, 58, 60, 62, 65, 67]

    def test_inadmissible_rendering_stays_bounded(self, dissect_pdml):
        """Selected prefixes and raw tails cover every byte, without admission."""
        lengths = {18: 32, 22: 2, 33: 32, 41: 4, 45: 31, 49: 4, 53: 32, 57: 32, 66: 33}
        p = pdml_section(dissect_pdml(self.FILE,
                         dfilter=to_capture(self.SPAN, 'frame.number in {' + ','.join(
                             map(str, lengths)) + '}')), self.SPAN)
        assert sorted(p.packets) == sorted(lengths)
        for frame, length in lengths.items():
            covered = set()
            for field in p[frame].iter('field'):
                if not field.get('name', '').startswith('nvme-mi.mi.') or field.get('hide') == 'yes':
                    continue
                pos, size = int(field.get('pos', 0)), int(field.get('size', 0))
                if pos >= 28 and size:
                    assert pos + size <= 28 + length, (frame, field.attrib)
                    covered.update(range(pos, pos + size))
            assert covered == set(range(28, 28 + length)), frame

    def test_labels_do_not_depend_on_version(self, dissect_pdml):
        """Labels do not depend on the endpoint's NVMe-MI version."""
        p = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        assert len({p.field(n, 'nvme-mi.mi.chds.csts.tcida')['showname'] for n in (8, 10, 16)}) == 1
        assert len({p.field(n, 'nvme-mi.mi.port.ciaps')['showname'] for n in (12, 14)}) == 1


class TestNvmeMiNmimtRange:
    """Every Message Type is named from Figure 20 by the header, Info column and command lists."""

    FILE = 'nvme-mi-types.pcapng'
    SECTION = 7
    NAMES = ((0x1, 'MI command'), (0x2, 'NVMe Admin command'), (0x3, 'Reserved'),
             (0x4, 'PCIe command'), (0x5, 'Asynchronous Event'), (0x6, 'Reserved'),
             (0xF, 'Reserved'))
    HEADER_TYPES = ((1, 0x2), (2, 0x2), (3, 0x3), (4, 0x4), (5, 0x4), (6, 0x5), (7, 0x6),
                    (8, 0xF), (9, 0x1), (10, 0x1))
    INFO_PREFIXES = (
        (1, 'NVMe-MI NVMe Admin command Request'), (2, 'NVMe-MI NVMe Admin command Response'),
        (3, 'NVMe-MI Reserved Request'), (4, 'NVMe-MI PCIe command Request'),
        (5, 'NVMe-MI PCIe command Response'), (6, 'NVMe-MI Asynchronous Event'),
        (7, 'NVMe-MI Reserved Request'), (8, 'NVMe-MI Reserved Request'),
        (9, 'NVMe-MI MI command Request'), (10, 'NVMe-MI MI command Response'))

    def test_decode(self, assert_frames_match):
        # Naming a Reserved value does not make it decodable.
        reserved = ('nvme-mi.reserved_type && data.data && !nvme-mi.admin && !nvme-mi.mi'
                    ' && !nvme-mi.control')
        assert_frames_match(self.FILE, at(self.SPAN, [
            (1, 'nvme-mi.admin'), (3, reserved), (6, 'nvme-mi.aem'), (7, reserved), (8, reserved),
            (10, 'nvme-mi.mi'),
        ]))

    def test_field_values(self, fields_table):
        t = section(fields_table(self.FILE, (
            'nvme-mi', 'nvme-mi.type', '_ws.col.info', 'nvme-mi.mi.cmdlist.numcmd',
            'nvme-mi.mi.cmdlist.nmimt', 'nvme-mi.reserved_type', 'nvme-mi.req_superseded',
            'nvme-mi.response_in', 'nvme-mi.response_to'), two_pass=True), self.SPAN)
        assert list(column(t, 'nvme-mi')) == list(range(1, 11))
        assert {n: int(r['nvme-mi.type'], 0) for n, r in t.items()} == dict(self.HEADER_TYPES)
        # The framing layer's own Info text; an AEM has no direction word, and
        # the old private wording "Reserved type" is gone.
        for frame, prefix in self.INFO_PREFIXES:
            assert t[frame]['_ws.col.info'].startswith(prefix), frame
            assert 'Unknown' not in t[frame]['_ws.col.info'], frame
        assert [t[n]['_ws.col.info'] for n in (3, 7, 8)] == ['NVMe-MI Reserved Request'] * 3
        assert not any('Reserved type' in r['_ws.col.info'] for r in t.values())
        assert t[10]['nvme-mi.mi.cmdlist.numcmd'] == '6'
        assert [int(v, 0) for v in t[10]['nvme-mi.mi.cmdlist.nmimt'].split(',')] == [
            0x2, 0x3, 0x4, 0x5, 0x6, 0xF]
        assert list(column(t, 'nvme-mi.reserved_type')) == [3, 7, 8]
        # Reserved types and the AEM own no Command Slot.
        assert column(t, 'nvme-mi.req_superseded') == {}
        assert {n: (r['nvme-mi.response_in'], r['nvme-mi.response_to']) for n, r in t.items()} == {
            1: ('2', ''), 2: ('', '1'), 3: ('', ''), 4: ('5', ''), 5: ('', '4'), 6: ('', ''),
            7: ('', ''), 8: ('', ''), 9: ('10', ''), 10: ('', '9')}

    def test_every_reader_names_every_type(self, dissect_pdml):
        p = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        names = dict(self.NAMES)
        for frame, value in self.HEADER_TYPES:
            label = p.field(frame, 'nvme-mi.type')['showname']
            assert names[value] in label and 'Unknown' not in label, (frame, label)
        entries = p.fields(10, 'nvme-mi.mi.cmdlist.nmimt')
        assert len(set(field_depths(p[10], 'nvme-mi.mi.cmdlist.nmimt'))) == 1
        assert [int(e.get('show'), 0) for e in entries] == [0x2, 0x3, 0x4, 0x5, 0x6, 0xF]
        for entry in entries:
            label = entry.get('showname')
            assert names[int(entry.get('show'), 0)] in label and 'Unknown' not in label, label


class TestNvmeMiControlCoverage:
    """The Control Primitive value domain."""

    FILE = 'nvme-mi-control.pcapng'

    def test_decode(self, assert_frames_match):
        assert_frames_match(self.FILE, [
            (1, 'nvme-mi.control.opcode == 0x01 && nvme-mi.control.tag == 0x11 && nvme-mi.control.cpsp == 0x0000'),
            (2, ('nvme-mi.control.opcode == 0x01 && nvme-mi.control.status == 0x00'
                 ' && nvme-mi.control.tag == 0x11 && nvme-mi.control.cpsr == 0x0000')),
            # Resume's reserved words are rendered raw and never read through
            # another primitive's layout.
            *[(n, (f'nvme-mi.control.{word} == 0xffff'
                   ' && !nvme-mi.control.cesf && !nvme-mi.control.rro && !nvme-mi.control.cpas'
                   ' && !nvme-mi.control.rr && !nvme-mi.control.mes.ssta'))
              for n, word in ((3, 'cpsp'), (4, 'cpsr'))],
            (11, 'nvme-mi.control.cesf == 0'),
            (13, 'nvme-mi.control.cesf == 1'),
            # Transmit rides with BMICE so the neighbouring bits are exercised.
            (14, 'nvme-mi.control.mes.bmice == 1 && nvme-mi.control.mes.pflg == 0'),
            (15, 'nvme-mi.control.rro == 0'),
            (17, 'nvme-mi.control.rro == 7'),
            # Only a Success Response has Tag and CPSR (Figures 39/40); 08h
            # takes Figure 30's Reserved bytes.
            (19, 'nvme-mi.control.opcode == 0x02 && nvme-mi.control.tag == 0x11'),
            (20, ('nvme-mi.control.status == 0x08 && nvme-mi.resp_reserved == 0'
                  ' && !nvme-mi.control.tag && !nvme-mi.control.cpsr && !_ws.expert')),
            (33, 'nvme-mi.control.opcode == 0x05 && nvme-mi.control.reserved_opcode'),
            (34, 'nvme-mi.control.opcode == 0xef && nvme-mi.control.reserved_opcode'),
            (35, 'nvme-mi.control.opcode == 0xf0'),
            (37, 'nvme-mi.control.opcode == 0xff'),
            # A vendor opcode has no CPSR layout: raw, nothing decoded.
            *[(n, (f'nvme-mi.control.cpsr == {cpsr} && !nvme-mi.control.cpas'
                   ' && !nvme-mi.control.rr && !nvme-mi.control.mes.ssta'))
              for n, cpsr in ((36, '0xbeef'), (38, '0xc0de'))],
        ])

    def test_field_values(self, fields_table):
        t = fields_table(self.FILE, (
            'nvme-mi.type', 'nvme-mi.response_to', 'nvme-mi.req_superseded', 'nvme-mi.control.cpas',
            'nvme-mi.control.mes.ssta', 'nvme-mi.control.cesf', 'nvme-mi.control.rr',
            'nvme-mi.control.status', 'nvme-mi.reserved_status',
            'nvme-mi.resp_reserved', 'nvme-mi.resp_undefined',
            'nvme-mi.resp_vendor', 'nvme-mi.control.data',
            'nvme-mi.control.reserved_opcode', '_ws.expert',
            '_ws.malformed.expert', '_ws.short', 'nvme-mi.mic.status'))

        def ints(field):
            return {n: int(v == 'True') if v in ('True', 'False') else int(v, 0)
                    for n, v in column(t, field).items()}

        assert [n for n, v in ints('nvme-mi.type').items() if v == 0] == list(range(1, 39))
        # Isolated exchanges; the two Reserved-opcode requests go unanswered
        # and are not superseded.
        assert {n: int(v) for n, v in column(t, 'nvme-mi.response_to').items()} == {
            **{n + 1: n for n in range(1, 33, 2)}, 36: 35, 38: 37}
        assert column(t, 'nvme-mi.req_superseded') == {}
        # Every encoding of the small fields (Figures 42, 43, 47).
        assert ints('nvme-mi.control.cpas') == {6: 0, 8: 1, 10: 3}
        assert ints('nvme-mi.control.mes.ssta') == {12: 0, 14: 3}
        assert [n for n, v in column(t, 'nvme-mi.control.cesf').items() if v in ('1', 'True')] == [13]
        assert ints('nvme-mi.control.rr') == {16: 0, 18: 1}
        # Figure 29's statuses at both ends of every run, plus 08h.
        assert ints('nvme-mi.control.status') == {
            **{n: 0 for n in (2, 4, 6, 8, 10, 12, 14, 16, 18, 36, 38)},
            20: 0x08, 22: 0x09, 24: 0x1F, 26: 0x2B, 28: 0xDF, 30: 0xE0, 32: 0xFF}
        # Bytes 7:5 take the format Figure 29 assigns each class.
        assert list(column(t, 'nvme-mi.resp_reserved')) == [20]
        assert list(column(t, 'nvme-mi.resp_undefined')) == [22, 24, 26, 28]
        # A Vendor Specific status keeps its whole body opaque.
        assert list(column(t, 'nvme-mi.resp_vendor')) == []
        assert list(column(t, 'nvme-mi.control.data')) == [30, 32]
        # Reserved opcodes are flagged, vendor ones are not; plus Resume's
        # reserved words and CPAS 3h.
        assert list(column(t, 'nvme-mi.control.reserved_opcode')) == [33, 34]
        # Reserved statuses are flagged (Figure 29); vendor specific are not.
        assert list(column(t, 'nvme-mi.reserved_status')) == [22, 24, 26, 28]
        assert list(column(t, '_ws.expert')) == [22, 24, 26, 28, 33, 34]
        assert column(t, '_ws.malformed.expert') == column(t, '_ws.short') == {}
        assert column(t, 'nvme-mi.mic.status') == {n: '1' for n in range(1, 39)}

    def test_status_and_opcode_labels(self, dissect_pdml):
        """The format fields sit right after the status byte, three bytes
        long, one class per frame; ranges are named."""
        p = dissect_pdml(self.FILE)
        for frame, status, name, field in (
                (22, 0x09, 'Reserved', 'nvme-mi.resp_undefined'),
                (24, 0x1f, 'Reserved', 'nvme-mi.resp_undefined'),
                (26, 0x2b, 'Reserved', 'nvme-mi.resp_undefined'),
                (28, 0xdf, 'Reserved', 'nvme-mi.resp_undefined'),
                (30, 0xe0, 'Vendor Specific', 'nvme-mi.control.data'),
                (32, 0xff, 'Vendor Specific', 'nvme-mi.control.data')):
            label = p.field(frame, 'nvme-mi.control.status')
            assert name in label['showname'] and f'0x{status:02x}' in label['showname'], frame
            item = p.field(frame, field)
            assert (item['size'], int(item['pos']) - int(label['pos'])) == ('3', 1), frame
        assert 'Slot Command Servicing State (SSTA):' in p.field(
            12, 'nvme-mi.control.mes.ssta')['showname']
        assert 'Reserved' in p.field(33, 'nvme-mi.control.opcode')['showname']
        assert 'Vendor Specific' in p.field(35, 'nvme-mi.control.opcode')['showname']


class TestNvmeMiSpecRevisions:
    """Values NVMe-MI 2.2, NVMe Base 2.4 and NVM Command Set 1.3 assigned or renamed."""

    FILE = 'nvme-mi-spec-revisions.pcapng'

    def test_decode(self, assert_frames_match):
        assert_frames_match(self.FILE, [
            *[(n, f'nvme-mi.mi.opcode == {op} && !nvme-mi.mi.reserved_opcode')
              for n, op in ((1, 0x0d), (3, 0x0e), (5, 0x0f))],
            (7, 'nvme-mi.mi.opcode == 0x10 && nvme-mi.mi.reserved_opcode'),
            (8, 'nvme-mi.mi.aeo.aeoi == 0x0f'),
            (10, 'nvme-mi.mi.vpd.ff == 0x5c'),
            (19, 'nvme-mi.admin.opcode == 0x2a'),
            *[(n, f'nvme.cqe.status.sct == 1 && nvme.cqe.status.sc == {sc}')
              for n, sc in ((22, 0x42), (24, 0x43), (26, 0x44), (28, 0x45))],
            *[(n, f'nvme.cmd.get_logpage.dword10.id == {lid}')
              for n, lid in ((29, 0x24), (31, 0x27), (33, 0x28))],
            *[(n, f'nvme.cmd.set_features.dword10.fid == {fid}')
              for n, fid in ((35, 0x26), (37, 0x27), (39, 0x28))],
            (36, 'nvme.cqe.status.sct == 0 && nvme.cqe.status.sc == 0x2d'),
            (38, 'nvme.cqe.status.sct == 0 && nvme.cqe.status.sc == 0x2e'),
            (41, 'nvme.features.cdp.perid == 0x03'),
            (43, 'nvme.features.cdp.perid == 0xc5'),
            (46, 'nvme.features.cdp.perid == 0x02'),
            (47, 'nvme.cmd.get_logpage.dword14.csi == 0x30'),
            (50, 'nvme.cmd.get_logpage.errinf.cmdset == 0x30'),
            (52, 'nvme.cmd.identify.ctrl.nvscc == 0x01'),
            (54, ('nvme.cmd.identify.pcc.crt == 0x03'
                  ' && nvme.cmd.identify.pcc.crt.vqrs == 1'
                  ' && nvme.cmd.identify.pcc.crt.virs == 1')),
            (55, 'nvme.cmd.get_features.dword10.fid == 0x7a'),
            (57, 'nvme.cmd.get_features.dword10.fid == 0x78'),
            (59, 'nvme-mi.admin.opcode == 0x15'),
            (62, 'nvme.cqe.status.sct == 0 && nvme.cqe.status.sc == 0x01'),
            (64, 'nvme-mi.mi.nshds.ctemp == 0x80'),
            (66, 'nvme-mi.mi.port.mvpdfreq == 0x04'),
            (68, 'nvme.cmd.get_logpage.cmd_feat_lockdown.cfila.ss == 3'),
        ])

    def test_labels(self, dissect_pdml):
        p = dissect_pdml(self.FILE)
        for frame, name, text in (
                (1, 'nvme-mi.mi.opcode', 'NVMe-MI PDA Read (0x0d)'),
                (3, 'nvme-mi.mi.opcode', 'NVMe-MI PDA Write (0x0e)'),
                (5, 'nvme-mi.mi.opcode', 'NVMe-MI PDA Write Zeroes (0x0f)'),
                (7, 'nvme-mi.mi.opcode', 'Reserved (0x10)'),
                (8, 'nvme-mi.mi.aeo.aeoi', 'Voltage Threshold Event (0x0f)'),
                (10, 'nvme-mi.mi.vpd.ff', 'PCIe, E2 - (SFF-TA-1042) 9.5 mm (0x5c)'),
                (19, 'nvme-mi.admin.opcode', 'Manage Exported NVM Subsystem Receive'),
                (21, 'nvme-mi.admin.opcode', 'Manage Exported NVM Subsystem Send'),
                (22, 'nvme.cqe.status.sc', 'Controller Active'),
                (24, 'nvme.cqe.status.sc', 'Invalid Exported Association'),
                (26, 'nvme.cqe.status.sc', 'Invalid Exported Configuration State'),
                (28, 'nvme.cqe.status.sc', 'Reserved'),
                (36, 'nvme.cqe.status.sc', 'Failed to Restore Configuration'),
                (38, 'nvme.cqe.status.sc', 'Reserved'),
                (29, 'nvme.cmd.get_logpage.dword10.id', 'Manufacturer Default Configuration Status'),
                (31, 'nvme.cmd.get_logpage.dword10.id', 'Voltage Measurement'),
                (33, 'nvme.cmd.get_logpage.dword10.id', 'Rate Limiting'),
                (35, 'nvme.cmd.set_features.dword10.fid', 'Voltage Threshold'),
                (37, 'nvme.cmd.set_features.dword10.fid', 'Voltage Measurement'),
                (39, 'nvme.cmd.set_features.dword10.fid', 'Rate Limiting'),
                (41, 'nvme.features.cdp.perid',
                 'Revert to Subsystem Manufacturing Settings Personality (0x03)'),
                (43, 'nvme.features.cdp.perid', 'Vendor Specific (0xc5)'),
                (46, 'nvme.features.cdp.perid', 'Lockdown Persistence Personality (0x02)'),
                (47, 'nvme.cmd.get_logpage.dword14.csi', 'Vendor Specific (0x30)'),
                (50, 'nvme.cmd.get_logpage.errinf.cmdset', 'Vendor Specific (0x30)'),
                (52, 'nvme.cmd.identify.ctrl.nvscc',
                 'I/O Command Set Vendor Specific Command Configuration (ICSVSCC)'),
                (52, 'nvme.cmd.identify.ctrl.nvscc.std',
                 'Same NVM Vendor Specific Command Format (SNVSCF)'),
                (54, 'nvme.cmd.identify.pcc.crt', 'Controller Resource Types (CRT)'),
                (54, 'nvme.cmd.identify.pcc.rsvd', 'Reserved'),
                (55, 'nvme.cmd.get_features.dword10.fid', 'Reserved for Management Features (0x7a)'),
                (57, 'nvme.cmd.get_features.dword10.fid',
                 'Embedded Management Controller Address (0x78)'),
                (59, 'nvme-mi.admin.opcode', 'Namespace Attachment'),
                (62, 'nvme.cqe.status.sc', 'Invalid Command Opcode'),
                (64, 'nvme-mi.mi.nshds.ctemp', 'Temperature data is more than 5 s old'),
                (66, 'nvme-mi.mi.port.mvpdfreq', 'Reserved (0x04)'),
                (68, 'nvme.cmd.get_logpage.cmd_feat_lockdown.cfila.ss',
                 'NVMe-MI Command Set opcodes (0x3)'),
                (11, 'nvme-mi.mi.nshsp.cs', 'Clear Change Flags (CCF)'),
                (12, 'nvme-mi.mi.nshds.ccs', 'Composite Controller Status Flags (CCSF)'),
                (12, 'nvme-mi.mi.hsf.csts', 'Controller Status Change Flag (CSF)'),
                (13, 'nvme-mi.mi.chsp.ccf', 'Clear Change Flags (CCF)'),
                (13, 'nvme-mi.mi.chsp.csts', 'Select on Controller Status Change (CSC)'),
                (14, 'nvme-mi.mi.chds.chsc', 'Controller Health Status Changed Flags (CHSCF)'),
                (14, 'nvme-mi.mi.hsf.tcida',
                 'Telemetry Controller-Initiated Data Available Flag (TCIDAF)'),
                (14, 'nvme-mi.mi.chds.csts.tcida', 'obsolete in MI 2.2, shall be 1'),
                (16, 'nvme-mi.mi.subsys.sre', 'obsolete in MI 2.2, shall be 1'),
                (18, 'nvme-mi.mi.port.ciaps', 'obsolete in MI 2.2, shall be 1')):
            assert text in p.field(frame, name)['showname'], (frame, name)
        pcc_reserved, = p.fields(54, 'nvme.cmd.identify.pcc.rsvd')
        assert (pcc_reserved.get('size'), pcc_reserved.get('value')) == ('27', ''.join(
            f'{value:02x}' for value in range(1, 28)))
        # Frames 1/3/5 carry PDA DFORMAT 0h, Reserved in MI 2.2 Figure 107.
        # Frames 19/39/57/59 send DLEN 0h where the command dwords define
        # a data transfer (MI 2.2 Figure 139).
        assert p.frames_with('_ws.expert') == [1, 3, 5, 7, 19, 22, 24, 26, 28,
                                               36, 38, 39, 47, 49, 57, 59, 62, 67]
        for frame in (1, 3, 5):
            assert p.fields(frame, 'nvme-mi.mi.reserved_value')



class TestNvmeMiSpecRevisionFields:
    """Bits and bytes NVMe Base 2.4, NVM Command Set 1.3 and NVMe-MI 2.2
    added to structures that earlier revisions already defined."""

    FILE = 'nvme-mi-spec-revisions-fields.pcapng'
    IC = 'nvme.cmd.identify.ctrl.'
    LD = 'nvme.cmd.get_logpage.cmd_feat_lockdown.enh.'

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_decode(self, assert_frames_match, two_pass):
        i, ld = self.IC, self.LD
        assert_frames_match(self.FILE, [
            (2, (f'{i}chsi.chs == 1 && {i}rmdca == 0x05 && {i}rmdca.rdscs == 1'
                f' && {i}rmdca.rdncs == 0 && {i}rmdca.rdccs == 1'
                f' && {i}mnens == 16 && {i}mnecpens == 4 && {i}mensnn == 256'
                f' && {i}ensa.ensts == 1 && {i}ensa.ensms == 1'
                f' && {i}endsfs.enf0 == 1 && {i}endsfs.enf1 == 0'
                f' && {i}vsen1.vsrs == 3 && {i}vsen1.vsrv == 10 && {i}vsen1.volss == 2'
                f' && {i}vsen1.pisl == 1 && {i}vsen1.pisv == 240'
                f' && {i}vsen2.volss == 1 && {i}vsen2.pisv == 66 && {i}vsen3 == 0'
                f' && {i}msvmt == 30 && {i}psds.psd.miiell == 5')),
            (4, ('nvme.cmd.identify.nvm_ctrl.rla.hls == 1 && nvme.cmd.identify.nvm_ctrl.rla.sls == 1'
                ' && nvme.cmd.identify.nvm_ctrl.rla.rsvd == 0 && nvme.cmd.identify.nvm_ctrl.slmc == 3')),
            (5, 'nvme.cmd.sanitize.dword10.preq == 1 && nvme.cmd.sanitize.dword10.rsvd == 0'),
            (7, 'nvme.cmd.sanitize_ns.preq == 1'),
            (10, 'nvme.cmd.get_logpage.sanitize.sstat.prgd == 1'),
            (11, 'nvme.cmd.set_features.dword11.aec.rlccn == 1'),
            (13, 'nvme.cmd.set_features.dword11.pm.iiell == 5'),
            (16, 'nvme.cqe.dword0.get_features.pm.iiell == 20'),
            (18, ('nvme.features.hostid == 30:31:32:33:34:35:36:37'
                 ' && nvme.features.hostid.rsvd == a0:a1:a2:a3:a4:a5:a6:a7')),
            (20, ('nvme.features.hostid == 40:41:42:43:44:45:46:47:48:49:4a:4b:4c:4d:4e:4f'
                 ' && !nvme.features.hostid.rsvd')),
            (21, 'nvme.cmd.lockdown.dword10.csel == 1 && nvme.cmd.lockdown.dword14.css == 5'),
            *[(n, 'nvme.cmd.get_logpage.lsp.elpf == 1') for n in (23, 25, 27)],
            (24, (f'{ld}ver == 1 && {ld}cfia.ss == 0 && {ld}cfia.cs == 1'
                 f' && {ld}cntlid == 0xffff && {ld}sze == 28 && {ld}ncfid == 3 && {ld}cfids == 4')),
            (26, f'{ld}cfia.ss == 2 && {ld}ncfid == 2 && {ld}cfids == 1 && !{ld}desc'),
            (28, f'!{ld}ncfid && !{ld}desc'),
            (30, ('nvme.cmd.get_logpage.feat_sup_and_eff.fids.fsp.ruhs == 1'
                 ' && nvme.cmd.get_logpage.feat_sup_and_eff.fids.fsp.rsvd == 0'
                 ' && nvme.cmd.get_logpage.feat_sup_and_eff.fids.fsp.cdqscp == 0')),
            (32, ('nvme-mi.mi.port.pdas == 8 && nvme-mi.mi.port.sdformat == 0x0d'
                 ' && nvme-mi.mi.port.sdformat.byte == 1 && nvme-mi.mi.port.sdformat.512b == 0'
                 ' && nvme-mi.mi.port.sdformat.4kib == 1 && nvme-mi.mi.port.sdformat.rsvd == 1')),
            (34, 'nvme-mi.mi.port.pdas == 0 && nvme-mi.mi.port.sdformat == 0'),
        ], two_pass=two_pass)

    def test_labels(self, dissect_pdml):
        p = dissect_pdml(self.FILE)
        i, ld = self.IC, self.LD
        for frame, name, text in (
                (2, i + 'vsen1.vsrs', '100 microseconds (0x03)'),
                (2, i + 'vsen1.volss', '0.01 V (0x2)'),
                (2, i + 'vsen2.volss', '0.001 V (0x1)'),
                (2, i + 'vsen3.volss', 'Reserved (0x0)'),
                (2, i + 'msvmt', '30 minutes'),
                (2, i + 'psds.psd.miiell', '5 (500 us)'),
                (4, 'nvme.cmd.identify.nvm_ctrl.slmc', '3 (4)'),
                (13, 'nvme.cmd.set_features.dword11.pm.iiell', '5 (500 us)'),
                (16, 'nvme.cqe.dword0.get_features.pm.iiell', '20 (2000 us)'),
                (21, 'nvme.cmd.lockdown.dword10.csel', 'Specific Controller (0x1)'),
                (23, 'nvme.cmd.get_logpage.dword11.lsi', 'Controller Identifier (CNTLID)'),
                (24, ld + 'cntlid', '0xffff (NVM subsystem-wide)'),
                (24, ld + 'desc.cfi', '0x06 (Identify)'),
                (26, ld + 'cfia.ss', 'Feature Identifiers (0x2)'),
                (32, 'nvme-mi.mi.port.pdas', '8 (2^8 = 256 bytes)'),
                (34, 'nvme-mi.mi.port.pdas', '0 (No NVMe-MI PDA)')):
            assert text in p.label(frame, name), (frame, name, p.label(frame, name))
        for name, text in (('vsen1.pisv', '240 (12.00 V)'), ('vsen2.pisv', '66 (3.30 V)')):
            assert p.label(2, i + name).endswith(decimal_forms(text)), p.label(2, i + name)
        # Every PSD carries MIIELL; only PSD 0 sets it.
        assert p.values(2, i + 'psds.psd.miiell') == [5] + [0] * 31
        # Descriptor reserved bytes follow CFIDS; the window decodes no list
        # when CFIDS cannot hold a descriptor.
        assert [f.get('showname') for f in p.fields(24, ld + 'desc')] == [
            f'Command and Feature Identifier Descriptor {n}' for n in range(3)]
        assert p.shows(24, ld + 'desc.cfi') == ['0x06', '0x09', '0x24']
        assert p.values(24, ld + 'desc.cfia.acntl') == [1, 0, 1]
        assert [f.get('value') for f in p.fields(24, ld + 'desc.rsvd')] == [
            '0000', 'aabb', '0000']
        assert p.sizes(18, 'nvme.features.hostid') == [8]
        assert p.sizes(20, 'nvme.features.hostid') == [16]
        assert p.experts(26) == [
            "CFIDS 1 is smaller than the 2-byte descriptor (NVMe Base 'Command and Feature Identifier Descriptor')"]
        assert p.shows(28, 'nvme.window_decode_skipped') == [SKIP_RAW]
        assert p.experts(28) == []
        # MI 2.2 Figure 148 prohibits the Host Identifier Set.
        assert p.experts(11) == [
            ('Set Features of this Feature is prohibited on NVMe-MI Management'
            " Endpoints (NVMe-MI 'Management Endpoint - Feature Support')")]
        assert p.frames_with('_ws.expert') == [11, 26]


class TestNvmeMiVoltage:
    """Device Voltage Monitor over NVMe-MI: Base 2.4 FID 26h/27h, LID 27h
    and the NVMe-MI 2.2 Voltage Threshold Event AE (0Fh)."""

    FILE = 'nvme-mi-voltage.pcapng'
    F = 'nvme.features.'
    VM = 'nvme.cmd.get_logpage.vm.'

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_decode(self, assert_frames_match, two_pass):
        f, vm = self.F, self.VM
        assert_frames_match(self.FILE, [
            (1, (f'{f}voltage.vsens == 2 && {f}voltage.evt == 1 && {f}voltage.ovt == 300'
                f' && {f}voltage.uvt == 200 && {f}voltage.rsvd == 0')),
            (3, f'{f}voltage.vsens == 2 && !{f}voltage.ovt && !{f}voltage.evt'),
            (4, (f'{f}voltage.vsens == 2 && {f}voltage.evt == 1 && {f}voltage.ovt == 300'
                f' && {f}voltage.uvt == 200')),
            (5, (f'{f}vmeas.act == 1 && {f}vmeas.rsvd == 0 && {f}vmeas.lvolta.vssel == 1'
                f' && {f}vmeas.lvolta.vmlt == 1 && {f}vmeas.lvolta.rsvd == 0'
                f' && {f}vmeas.svmt == 10 && {f}vmeas.lvolt.luvt == 180'
                f' && {f}vmeas.lvolt.lovt == 330 && {f}vmeas.lvolt.rsvd0 == 0'
                f' && {f}vmeas.lvolt.rsvd1 == 0 && len({f}vmeas.rsvd_data) == 4088')),
            (7, f'{f}vmeas.act == 1'),
            (8, (f'{f}vmeas.act == 1 && {f}vmeas.lvolta.vssel == 1 && {f}vmeas.svmt == 10'
                f' && {f}vmeas.lvolt.lovt == 330 && !{f}vmeas.rsvd_data')),
            (9, f'{f}vmeas.act == 2'),
            (12, (f'{vm}vmgn == 3 && {vm}vma.vme == 1 && {vm}vma.ivolts == 1'
                 f' && {vm}vma.vsm == 1 && {vm}vma.vmc == 1 && {vm}vma.rsvd == 0'
                 f' && {vm}vsi.vssv == 240 && {vm}vsi.vssl == 1 && {vm}vsi.vsss == 1'
                 f' && {vm}vmlsz == 72 && {vm}nvmds == 4 && {vm}nvmde == 2 && {vm}svmtr == 7'
                 f' && {vm}svmts.tstmp == 1000 && {vm}svmts.sync == 1 && {vm}svmts.tstmpo == 1'
                 f' && {vm}cntlid == 1 && {vm}vlvss == 4'
                 f' && {vm}ovol.movv == 12600 && {vm}ovol.ovv == 1 && {vm}ovc == 3'
                 f' && {vm}ovlt == 12500 && {vm}ovts.tstmp == 2000 && {vm}iovpe == 2'
                 f' && {vm}uvol.muvv == 11400 && {vm}uvol.uvv == 1 && {vm}uvc == 5'
                 f' && {vm}uvlt == 11500 && {vm}uvts.tstmp == 3000 && {vm}iuvpe == 255'
                 f' && {vm}vlvs == de:ad:be:ef')),
            (14, f'{vm}nvmds == 1 && {vm}nvmde == 2 && !{vm}vlvs'),
            (15, ('nvme-mi.mi.aeo.aeoi == 0x0f && nvme-mi.mi.aeosi.pwril == 1'
                 ' && nvme-mi.mi.aeosi.pwriv == 240 && nvme-mi.mi.aeosi.vsent == 2'
                 ' && nvme-mi.mi.aeosi.vtht == 0 && nvme-mi.mi.aeosi.volv == 12500')),
            (16, 'nvme-mi.mi.aeo.aeosil == 1 && !nvme-mi.mi.aeosi.volv'),
        ], two_pass=two_pass)

    def test_labels(self, dissect_pdml):
        p = dissect_pdml(self.FILE)
        f, vm = self.F, self.VM
        for frame, name, text in (
                (1, f + 'voltage.vsens', 'Voltage Sensor 3 (VSEN3) (0x2)'),
                (5, f + 'vmeas.act', 'Start Voltage Measurements (0x1)'),
                (5, f + 'vmeas.svmt', '10 minutes'),
                (9, f + 'vmeas.act', 'Clear Overvoltage Valid and Undervoltage Valid (0x2)'),
                (12, vm + 'vsi.vsss', '0.001 V (0x1)'),
                (12, vm + 'iovpe', '2%'),
                (12, vm + 'iuvpe', 'Not reported (255)'),
                (15, 'nvme-mi.mi.aeosi.vtht', 'Overvoltage Threshold (0x0)')):
            assert text in p.label(frame, name), (frame, name, p.label(frame, name))
        for frame, name in ((12, vm + 'vsi.vssv'), (15, 'nvme-mi.mi.aeosi.pwriv')):
            assert p.label(frame, name).endswith(decimal_forms('240 (12.00 V)')), (
                frame, name, p.label(frame, name))
        assert p.values(12, vm + 'ivolm.volv') == [12000, 12100]
        assert p.values(12, vm + 'ivolm.ncvm') == [0, 1]
        assert p.values(14, vm + 'ivolm.volv') == [12000, 12100]
        assert p.experts(14) == ["NVMDE 2 exceeds NVMDS 1 (NVMe Base 'Voltage Measurement Log Page')"]
        assert p.experts(16) == [
            ("NVMe-MI 'AE Occurrence Specific Info Data Structure' defines 4"
             ' Specific Info bytes for AE 0xf, not 1')]
        # ACT 2h transfers no data (Base 2.4 5.2.30.1.30); DLEN 0h is correct.
        assert p.experts(9) == []
        assert p.frames_with('_ws.expert') == [14, 16]


class TestNvmeMiRateLimiting:
    """Rate Limiting over the NVMe-MI Admin tunnel: NVM CS 1.3 FID 28h
    (Figures 106-108) and LID 28h (Figures 117-121)."""

    FILE = 'nvme-mi-rate-limiting.pcapng'
    F = 'nvme.features.ratelim.'
    L = 'nvme.cmd.get_logpage.rl.'

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_decode(self, assert_frames_match, two_pass):
        f, lp = self.F, self.L
        data = (f'{f}rlc.rle == 1 && {f}rlc.rlm == 1 && {f}rlc.rsvd == 0 && {f}bwsf == 1'
                f' && {f}tbwv == 300 && {f}wbwv == 100 && {f}tiops == 500000'
                f' && {f}wiops == 200000 && {f}wriopsr.riopsr == 1 && {f}wrbwr.rbwr == 1'
                f' && {f}wrbwr.wbwr == 2 && {f}vs[0] == 5a && len({f}vs) == 512'
                f' && len({f}rsvd1) == 476')
        assert_frames_match(self.FILE, [
            (1, f'{f}tgt == 0 && {f}tid == 1 && {f}rsvd == 0 && {f}wriopsr.wiopsr == 3 && ' + data),
            (3, f'{f}tgt == 0 && {f}tid == 1 && !{f}rlc'),
            (4, f'{f}wriopsr.wiopsr == 3 && ' + data),
            (5, f'{f}tgt == 192 && {f}tid == 7 && {f}wriopsr.wiopsr == 0'),
            (8, (f'{lp}np == 0 && {lp}lpl == 477 && {lp}gc == 9 && {lp}nst == 1'
                f' && {lp}port_off == 5 && {lp}port.portid == 0 && {lp}port.nc == 1'
                f' && {lp}port.abwsf == 3 && {lp}port.arbwv == 10 && {lp}port.awbwv == 8'
                f' && {lp}port.ariops == 2000000 && {lp}port.awiops == 500000'
                f' && {lp}vs[0] == a5 && len({lp}pad) == 2')),
            (10, (f'{lp}np == 1 && {lp}port.portid == 1 && {lp}ctrl.cntlid == 2'
                 f' && {lp}nsma.sc == 0 && !{lp}tgt && !{lp}pad')),
            (12, f'{lp}lpl == 477 && {lp}port_off == 5 && !{lp}port && !{lp}tgt'),
        ], two_pass=two_pass)

    def test_log_graph(self, dissect_pdml):
        p = dissect_pdml(self.FILE)
        lp = self.L
        assert p.values(8, lp + 'ctrl_off') == [263, 345]
        assert p.values(8, lp + 'ctrl.cntlid') == [0, 1]
        assert p.values(8, lp + 'nnsmad') == [2, 0, 1, 0, 2]
        assert p.values(8, lp + 'nsma_off') == [427, 443, 460, 427, 443]
        assert p.values(8, lp + 'nsma.sc') == [2, 2, 3]
        assert p.values(8, lp + 'nsma.si') == [1, 2, 5]
        assert p.values(8, lp + 'rlma.mbsf') == [3, 2, 1, 1, 1, 2]
        assert p.values(8, lp + 'rlma.mrbwv') == [14, 140, 50, 50, 50, 140]
        assert p.values(8, lp + 'rlma.mwiops') == [1000000, 500000, 250000, 250000,
                                                  250000, 500000]
        assert p.values(8, lp + 'tgt') == [0, 192]
        assert [x.get('showname') for x in p.fields(8, lp + 'nsma')] == [
            'Non-Volatile Storage Medium Access Descriptor at byte 1708',
            'Non-Volatile Storage Medium Access Descriptor at byte 1772',
            'Non-Volatile Storage Medium Access Descriptor at byte 1840']
        assert p.sizes(8, lp + 'port') == [1032]
        assert p.sizes(8, lp + 'ctrl') == [328, 328]
        assert p.sizes(8, lp + 'nsma') == [64, 68, 64]
        assert p.values(10, lp + 'port_off') == [2, 6]
        assert p.values(10, lp + 'ctrl_off') == [264, 264]
        assert p.values(10, lp + 'nsma_off') == [345, 345]
        assert len(p.fields(10, lp + 'ctrl')) == 1
        assert len(p.fields(10, lp + 'nsma')) == 1

    def test_labels(self, dissect_pdml):
        p = dissect_pdml(self.FILE)
        f, lp = self.F, self.L
        for frame, name, text in (
                (1, f + 'tgt', 'Controller (0)'),
                (1, f + 'rlc.rlm', 'Soft Limit (0x1)'),
                (1, f + 'bwsf', '10 MiB/second (0x01)'),
                (5, f + 'tgt', 'Vendor Specific (192)'),
                (8, lp + 'np', '0 (1 entry)'),
                (8, lp + 'nst', '1 (2 entries)'),
                (8, lp + 'port_off', '5 (byte 20)'),
                (8, lp + 'port.abwsf', '1 GiB/second (0x03)'),
                (8, lp + 'port.arbwv', '10 x 1 GiB/second'),
                (8, lp + 'rlma.mrbwv', '14 x 1 GiB/second'),
                (8, lp + 'nsma.sc', 'Endurance Group (0x02)'),
                (8, lp + 'tgt', 'Controller (0)')):
            assert text in p.label(frame, name), (frame, name, p.label(frame, name))
        shared = [x.get('showname') for x in p.fields(8, lp + 'nsma_off')]
        assert [x.endswith('[descriptor decoded at its first reference]') for x in shared] == [
            False, False, False, True, True]

    def test_experts(self, dissect_pdml):
        p = dissect_pdml(self.FILE)
        assert p.experts(5) == [
            ('A Write to Read IOPS or Bandwidth Ratio portion is 0h; '
            "each shall be non-zero (NVM Command Set 'Rate Limiting - Data Buffer')")]
        assert p.experts(10) == [
            "Offset 2 dwords is outside the Rate Limiting Data field (NVM Command Set 'Rate Limiting Log Page')",
            "NNSMAD shall be 0h for the NVM subsystem scope (NVM Command Set 'Non-Volatile Storage Medium Access Descriptor')",
            ('The 4-entry Supported Target list at byte 1448 runs past the Log Page Length'
            " (NVM Command Set 'Rate Limiting Log Page')")]
        assert p.frames_with('_ws.expert') == [5, 10, 14]

    def test_overlapping_lists_are_read_once(self, dissect_pdml):
        """200 Port descriptors a dword apart each list 65536 offsets to the
        end of the 4096 bytes.  Each dword is read as an offset once: the first
        list reads its 564, the 199 others overlap it.  Before, every list
        was read to the end, 90 thousand reads."""
        experts = dissect_pdml(self.FILE).experts(14)
        outside = [e for e in experts if 'outside the Rate Limiting Data' in e]
        overlap = [e for e in experts if 'overlaps one already read' in e]
        # Each list is also declared 65536 entries, past the page length.
        assert (len(outside), len(overlap), len(experts)) == (564, 199, 963)


class TestNvmeMiMfrDefaults:
    """Restore Manufacturing Default Settings (TP4195) and the Lockdown
    Persistence Personality (TP4200): Base 2.4 LID 24h (Figure 304), FID 22h
    PERID 02h CDW11 and CQE Dword 1 (Figures 518-519), and the restore
    operations of Namespace Management and Capacity Management."""

    FILE = 'nvme-mi-mfr-defaults.pcapng'
    M = 'nvme.cmd.get_logpage.mdcs.'

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_decode(self, assert_frames_match, two_pass):
        m = self.M
        assert_frames_match(self.FILE, [
            (2, (f'{m}mdcsv == 0 && {m}mdcs == 0x05 && {m}dscs == 1 && {m}dncs == 0'
                f' && {m}dccs == 1 && {m}rsvd == 0')),
            (4, (f'!{m}mdcsv && {m}mdcs == 0xfe && {m}dscs == 0 && {m}dncs == 1'
                f' && {m}dccs == 1 && {m}rsvd == 0x1f')),
            (5, ('nvme.features.cdp.perid == 2 && nvme.features.cdp.chps == 1'
                ' && nvme.features.cdp.ldpe == 1 && nvme.features.cdp.ldp_rsvd == 0')),
            (8, ('nvme.features.cdp.perid == 2 && nvme.features.cdp.pmdss == 0'
                ' && nvme-mi.admin.cqe_dw1 == 1 && nvme.cqe.dword1.cdp.ldps == 1'
                ' && nvme.cqe.dword1.cdp.rsvd == 0')),
            (10, ('nvme.features.cdp.perid == 1 && nvme-mi.admin.cqe_dw1 == 1'
                 ' && !nvme.cqe.dword1.cdp.ldps')),
            (12, 'nvme-mi.admin.cqe_dw1 == 1 && !nvme.cqe.dword1.cdp.ldps'),
            (14, 'nvme.cqe.status.sc == 0x02 && !nvme.cqe.dword1.cdp.ldps'),
            (15, ('nvme.features.cdp.perid == 3 && !nvme.features.cdp.ldpe'
                 ' && nvme.cmd.dword11 == 1')),
            (17, 'nvme.cmd.ns_mgmt.sel == 2'),
            (19, 'nvme.cmd.cap_mgmt.oper == 5'),
            (20, 'nvme.cqe.status.sct == 0 && nvme.cqe.status.sc == 0x2d'),
            # LDPS for SEL 0h-2h only; 011b and Reserved 4h-7h keep DW1 raw.
            *((n, 'nvme-mi.admin.cqe_dw1 == 1 && nvme.cqe.dword1.cdp.ldps == 1')
              for n in (22, 24)),
            *((n, 'nvme-mi.admin.cqe_dw1 == 1 && !nvme.cqe.dword1.cdp.ldps')
              for n in (26, 28, 30, 32)),
            *((n, 'nvme.cmd.get_features.sel_reserved') for n in (25, 27, 29, 31)),
        ], two_pass=two_pass)

    def test_labels(self, dissect_pdml):
        p = dissect_pdml(self.FILE)
        for frame, name, text in (
                (1, 'nvme.cmd.get_logpage.dword10.id',
                 'Manufacturer Default Configuration Status (0x24)'),
                (17, 'nvme.cmd.ns_mgmt.sel', 'Restore Default Namespace Configuration (0x2)'),
                (19, 'nvme.cmd.cap_mgmt.oper',
                 'Restore Default Capacity Management Configuration (0x5)'),
                (20, 'nvme.cqe.status.sc', 'Failed to Restore Configuration')):
            assert text in p.label(frame, name), (frame, name, p.label(frame, name))
        # Get CDP PERID 01h returns an 8-byte structure (Base 2.4 Figure 516).
        assert p.experts(9) == [
            'Data Length is zero; the Get Features FID and SEL defines a data transfer']
        assert p.frames_with('nvme.cqe.dword1.cdp.ldps') == [8, 22, 24]
        assert p.experts(25) == [
            ("Get Features Select value is reserved (NVMe Base 'Get Features - Command Dword 10'); completion"
            ' Dword 0 and data are shown raw')]


class TestNvmeMiCsiLidNames:
    """I/O Command Set specific Get Log Page names are chosen by CDW14.CSI
    (Base 2.4 Figure 31, MI 2.2 Figure 144): 82h-84h Computational
    Programs, 85h Subsystem Local Memory, BFh Zoned Namespace. Under any
    other CSI the generic name stays."""

    FILE = 'nvme-mi-csi-lid-names.pcapng'
    CS = 'nvme.cmd.get_logpage.cs_name'
    SPECIFIC = (
        (1, 'Program List'),
        (3, 'Downloadable Program Types List'),
        (5, 'Memory Range Set List'),
        (7, 'Host Addressable Namespaces'),
        (9, 'Changed Zone List'),
    )
    GENERIC = (
        (11, 'I/O Command Set Specific (0x85)'),
        (13, 'I/O Command Set Specific (0x82)'),
        (15, 'Zoned Namespace Command Set (0xbf)'),
    )

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_decode(self, assert_frames_match, two_pass):
        cs = self.CS
        assert_frames_match(self.FILE, [
            (1, f'{cs} == "Program List" && nvme.cmd.get_logpage.dword14.csi == 4'),
            (3, f'{cs} == "Downloadable Program Types List"'),
            (5, f'{cs} == "Memory Range Set List"'),
            (7, (f'{cs} == "Host Addressable Namespaces"'
                ' && nvme.cmd.get_logpage.dword14.csi == 3')),
            (9, f'{cs} == "Changed Zone List" && nvme.cmd.get_logpage.dword14.csi == 2'),
            (11, f'!{cs} && nvme.cmd.get_logpage.dword10.id == 0x85'),
            (13, f'!{cs} && nvme.cmd.get_logpage.dword14.csi == 3'),
            (15, f'!{cs} && nvme.cmd.get_logpage.dword10.id == 0xbf'),
        ], two_pass=two_pass)

    def test_labels(self, dissect_pdml):
        p = dissect_pdml(self.FILE)
        for frame, name in self.SPECIFIC:
            assert f'NVMe Get Log Page ({name})' in p.label(frame + 1, 'nvme.data')
        for frame, text in self.GENERIC:
            assert text in p.label(frame, 'nvme.cmd.get_logpage.dword10.id')
            assert f'NVMe Get Log Page ({text.rsplit(" (", 1)[0]})' in \
                p.label(frame + 1, 'nvme.data')

    def test_info(self, cmd_tshark, capture_file, test_env):
        out = subprocess.check_output([cmd_tshark, '-r', capture_file(self.FILE),
                                       '-T', 'fields', '-e', 'frame.number',
                                       '-e', '_ws.col.info'],
                                      encoding='utf-8', env=test_env)
        info = dict(line.split('\t', 1) for line in out.splitlines())
        for frame, name in self.SPECIFIC:
            assert info[str(frame)].endswith(name), info[str(frame)]
        assert info['11'].endswith('I/O Command Set Specific')
        assert info['15'].endswith('Zoned Namespace Command Set')


class TestNvmeMiIdentifyUnderlying:
    """Identify CNS 21h Get Underlying Controller List (a Controller List,
    Base 2.4 section 5.2.14.3.1) and CNS 22h Exported NVM Subsystem Template
    UUID List (Figure 359); CNS 23h stays reserved (Figure 336)."""

    FILE = 'nvme-mi-identify-underlying.pcapng'
    I = 'nvme.cmd.identify.'

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_decode(self, assert_frames_match, two_pass):
        i = self.I
        e1 = '10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f'
        e2 = 'a0:a1:a2:a3:a4:a5:a6:a7:a8:a9:aa:ab:ac:ad:ae:af'
        assert_frames_match(self.FILE, [
            (1, ('nvme.cmd.identify.dword10.cns == 0x21'
                ' && nvme.cmd.identify.dword10.cntid == 5')),
            (2, (f'{i}ctrl_list.num == 2 && {i}ctrl_list.id == 5 && {i}ctrl_list.id == 7'
                ' && !nvme.identify.cns_reserved')),
            (4, (f'{i}enst.rsvd == 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00'
                f' && {i}enst.uuid == {e1} && {i}enst.uuid == {e2}'
                ' && !nvme.identify.cns_reserved')),
            (6, (f'!{i}enst.rsvd && {i}enst.uuid == {e2} && !({i}enst.uuid == {e1})'
                ' && nvme.window.partial == 18:19:1a:1b:1c:1d:1e:1f')),
            (8, (f'{i}enst.rsvd == ee:ee:ee:ee:ee:ee:ee:ee:ee:ee:ee:ee:ee:ee:ee:ee'
                f' && {i}enst.uuid == {e1}')),
            (10, 'nvme.identify.cns_reserved && !nvme.cmd.identify.enst.uuid'),
        ], two_pass=two_pass)

    def test_counts_and_labels(self, dissect_pdml):
        p = dissect_pdml(self.FILE)
        assert len(p.shownames(2, self.I + 'ctrl_list.id')) == 2
        assert len(p.shownames(4, self.I + 'enst.uuid')) == 2
        assert len(p.shownames(6, self.I + 'enst.uuid')) == 1
        assert 'Get Underlying Controller List (0x21)' in \
            p.label(1, 'nvme.cmd.identify.dword10.cns')
        assert 'Exported NVM Subsystem Template UUID List (0x22)' in \
            p.label(3, 'nvme.cmd.identify.dword10.cns')


class TestNvmeMiPda:
    """NVMe-MI PDA Read, Write and Write Zeroes (NVMe-MI 2.2 section 5.7,
    Figures 106-111): DFORMAT, unit-scaled DOFST/DLEN and data extents."""

    FILE = 'nvme-mi-pda.pcapng'
    P = 'nvme-mi.mi.pda.'

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_decode(self, assert_frames_match, two_pass):
        p = self.P
        assert_frames_match(self.FILE, [
            (1, (f'{p}dformat == 3 && {p}dofst == 16 && {p}dlen == 8'
                f' && {p}byte_offset == 16 && {p}byte_length == 8'
                ' && !nvme-mi.mi.reserved && !nvme-mi.mi.reserved_value')),
            (2, (f'{p}data == 01:02:03:04:05:06:07:08'
                ' && nvme-mi.mi.nmresp_reserved == 0'
                ' && !nvme-mi.mi.response_data_length')),
            (3, (f'{p}dformat == 2 && {p}byte_offset == 1024'
                f' && {p}byte_length == 512')),
            (4, f'len({p}data) == 512 && !nvme-mi.mi.response_data_length'),
            (5, f'{p}dformat == 1 && {p}dlen == 0 && {p}byte_length == 0'),
            (6, f'!{p}data && !nvme-mi.mi.response_data_length'),
            (7, f'{p}byte_length == 8'),
            (8, f'nvme-mi.mi.response_data_length && len({p}data) == 6'),
            (9, (f'{p}dformat == 0 && nvme-mi.mi.reserved_value'
                f' && !{p}byte_length')),
            (10, f'len({p}data) == 4 && !nvme-mi.mi.response_data_length'),
            (11, (f'{p}data == de:ad:be:ef'
                 ' && !nvme-mi.mi.request_data_length')),
            (12, '!nvme-mi.mi.response_data_length && !nvme-mi.mi.data'),
            (13, f'{p}data == de:ad:be && nvme-mi.mi.request_data_length'),
            (14, 'nvme-mi.mi.status == 0x06'),
            (15, (f'{p}dformat == 3 && !{p}dofst && !{p}dlen'
                 ' && nvme-mi.mi.nmd0_reserved == 0x1234'
                 ' && nvme-mi.mi.nmd1_reserved == 0x5678')),
            (16, 'nvme-mi.mi.status == 0 && !nvme-mi.mi.response_data_length'),
            (17, f'{p}dofst == 0xffffff00 && {p}byte_offset == 0xffffff00'),
            (18, 'nvme-mi.mi.status == 0x04 && nvme-mi.pel.byte == 8'),
            (19, 'nvme-mi.mi.truncated && !nvme-mi.mi.pda.dformat'),
            # Conservative DLEN ceilings: 4096 for 1h and Write 3h, 512 for
            # 2h, none for Read 3h (Figures 109/111).
            (20, f'{p}dlen_max && {p}byte_length == 16781312'),
            (22, f'!{p}dlen_max'),
            (24, f'{p}dlen_max'),
            (26, f'!{p}dlen_max && {p}byte_length == 4097'),
            (28, f'{p}dlen_max && !nvme-mi.mi.request_data_length'),
            (30, '!_ws.expert'),
            (32, f'{p}dlen_max && nvme-mi.mi.request_data_length'),
            (34, f'!{p}dlen_max && nvme-mi.mi.request_data_length'),
            (36, f'{p}dlen_max && nvme-mi.mi.request_data_length'),
            (38, f'{p}dlen_max && nvme-mi.mi.request_data_length'),
            (40, f'{p}dlen_max && {p}byte_length == 262656'),
            (42, f'!{p}dlen_max && {p}byte_length == 262144'),
            (44, f'{p}dlen_max && nvme-mi.mi.request_data_length'),
            (46, f'!{p}dlen_max && nvme-mi.mi.request_data_length'),
        ], two_pass=two_pass)

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_experts(self, dissect_pdml, two_pass):
        p = dissect_pdml(self.FILE, two_pass=two_pass)
        assert p.frames_with(self.P + 'dlen_max') == [
            20, 24, 28, 32, 36, 38, 40, 44]
        assert p.frames_with('nvme-mi.mi.request_data_length') == [
            13, 32, 34, 36, 38, 44, 46]
        for frame, dlen in ((32, 4097), (36, 4097), (38, 4096), (44, 513)):
            messages = p.experts(frame)
            assert len(messages) == 2, frame
            assert sum(m.startswith(f'DLEN {dlen} (') for m in messages) == 1, frame
            assert sum(m.startswith('Request Data length is') for m in messages) == 1, frame
        assert p.experts(20) == [
            ('DLEN 4097 (DFORMAT 4KiB) exceeds the conservative maximum 4096'
            " (NVMe-MI 'NVMe-MI PDA Read NVMe Management Dword 1')")]
        assert p.experts(28) == [
            ('DLEN 4097 (DFORMAT Byte Level) exceeds the conservative maximum'
            " 4096 (NVMe-MI 'NVMe-MI PDA Write NVMe Management Dword 1')")]
        assert p.experts(40) == [
            ('DLEN 513 (DFORMAT 512B) exceeds the conservative maximum 512'
            " (NVMe-MI 'NVMe-MI PDA Read NVMe Management Dword 1')")]
        assert p.experts(42) == []
        assert any(m.startswith('DLEN 513 (DFORMAT 512B) exceeds the'
                                ' conservative maximum 512 (NVMe-MI'
                                " 'NVMe-MI PDA Write NVMe Management Dword 1')") for m in p.experts(44))

    def test_info(self, cmd_tshark, capture_file, test_env):
        out = subprocess.check_output(
            [cmd_tshark, '-r', capture_file(self.FILE)],
            encoding='utf-8', env=test_env)
        lines = out.splitlines()
        assert 'NVMe-MI PDA Read: Byte Level, offset 16, length 8' in lines[0]
        assert 'NVMe-MI PDA Read: 512B, offset 2, length 1' in lines[2]
        assert 'NVMe-MI PDA Write: Byte Level, offset 32, length 4' in lines[10]
        assert 'NVMe-MI PDA Write Zeroes' in lines[14]


class TestNvmeMiRorTagOwner:
    """NVMe-MI 2.2 Figure 20 (TP6042): ROR set on a message that arrives as
    a request is dropped by the Responder; ROR must agree with the MCTP Tag
    Owner bit, and a message where it does not takes no part in pairing."""

    FILE = 'nvme-mi-ror-tag-owner.pcapng'

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_decode(self, assert_frames_match, two_pass):
        assert_frames_match(self.FILE, [
            (1, '!nvme-mi.ror_tag_owner'
                + (' && nvme-mi.response_in == 3' if two_pass else '')),
            (2, ('nvme-mi.ror == 1 && mctp.tag.to == 1 && nvme-mi.ror_tag_owner'
                ' && !nvme-mi.response_to && nvme-mi.mi.orphan_response')),
            (3, ('!nvme-mi.ror_tag_owner && nvme-mi.response_to == 1'
                ' && nvme-mi.mi.opcode == 0x01')),
            (4, ('nvme-mi.ror == 0 && mctp.tag.to == 0 && nvme-mi.ror_tag_owner'
                ' && !nvme-mi.response_in')),
            (5, '!nvme-mi.ror_tag_owner && !_ws.expert'),
        ], two_pass=two_pass)


CP_FLAG = '{} set to 1 is prohibited in a Control Primitive'
CP_INVALID = ('; the Management Endpoint returns an Invalid Parameter Error'
              ' Response with PEL indicating {}')
CP_FIG20 = " (NVMe-MI 'NVMe-MI Message Fields')"


class TestNvmeMiFrameRules:
    """Header and MI command field rules (NVMe-MI 2.2 Figures 20, 29 and
    61-64; IPMI FRU 1.0r1.3 Table 16-2): each violation is flagged and its
    conformant control stays silent."""

    FILE = 'nvme-mi-frame-rules.pcapng'
    DATA = ('Request Data on a command that defines none; a Responder returns'
            " Invalid Command Size (NVMe-MI 'Response Message Status Values', 05h)")
    EXPERTS: ClassVar = {
        1: [('MEB set to 1 is prohibited outside a Command Message'
            " (NVMe-MI 'NVMe-MI Message Fields')")],
        5: [DATA],
        7: [DATA],
        19: ["AEOLHL shall be set to 7h (NVMe-MI 'AE Occurrence List Data Structure')",
             "AELHLEN shall be set to 9h (NVMe-MI 'AE Occurrence Data Structure')"],
        20: [('The most-significant byte of AEOPID shall be cleared to 0h when'
             " AEOPT is 1 (NVMe-MI 'AE Occurrence Scope ID Info Field Format')")],
        21: ["AE Occurrence ID 0x20 is Reserved (NVMe-MI 'Asynchronous Events')"],
        22: ["AE Occurrence Scope 0x7 is Reserved (NVMe-MI 'AE Occurrence Data Structure')"],
        24: [CP_FLAG.format('CIAP') + CP_INVALID.format('CIAP') + CP_FIG20],
        25: [CP_FLAG.format('MEB') + CP_INVALID.format('MEB') + CP_FIG20],
        26: [CP_FLAG.format('CIAP') + CP_INVALID.format('CIAP') + CP_FIG20,
             CP_FLAG.format('MEB') + CP_INVALID.format('MEB') + CP_FIG20],
        28: [CP_FLAG.format('MEB') + CP_FIG20],
    }

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_experts(self, dissect_pdml, two_pass):
        p = dissect_pdml(self.FILE, two_pass=two_pass)
        for frame in range(1, 29):
            assert p.experts(frame) == self.EXPERTS.get(frame, []), frame
        assert p.frames_with('nvme-mi.aem_header') == [1]
        assert p.frames_with('nvme-mi.mi.unexpected_request_data') == [5, 7]
        assert p.frames_with('nvme-mi.mi.aeo_field_invalid') == [19, 20]
        assert p.frames_with('nvme-mi.mi.reserved_value') == [21, 22]
        assert p.frames_with('nvme-mi.cp_csi') == []
        assert p.values(4, 'nvme-mi.csi') == [1]
        assert p.frames_with('nvme-mi.response_csi_mismatch') == []

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_control_primitive_flags(self, dissect_pdml, two_pass):
        """Figure 20: one Warning per set CIAP or MEB bit, on that bit."""
        p = dissect_pdml(self.FILE, two_pass=two_pass)
        flags = 'nvme-mi.control_header_flags'
        assert p.frames_with(flags) == [24, 25, 26, 28]
        assert p.values(28, 'nvme-mi.response_to') == [27]
        for frame, bits in ((24, ('ciap',)), (25, ('meb',)),
                            (26, ('ciap', 'meb')), (28, ('meb',))):
            for bit in ('ciap', 'meb'):
                item = p.fields(frame, f'nvme-mi.{bit}')[0]
                experts = item.findall(f".//field[@name='{flags}']/..")
                assert len(experts) == (bit in bits), (frame, bit)
                for expert in experts:
                    assert int(expert.find("./field[@name='_ws.expert.severity']")
                               .get('show')) == 0x600000  # Warning
        assert not any('Invalid Parameter' in m for m in p.experts(28))

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_labels(self, dissect_pdml, two_pass):
        p = dissect_pdml(self.FILE, two_pass=two_pass)
        assert p.label(1, 'nvme-mi.ror') == 'Request (not applicable to AEMs)'
        assert p.label(2, 'nvme-mi.ror') == 'Request (not applicable to AEMs)'
        assert p.label(3, 'nvme-mi.ror') == 'Request'
        assert p.values(3, 'nvme-mi.csi') == [1]
        assert p.values(13, 'nvme-mi.mi.chsp.maxrent') == [0]
        assert [n.split(': ', 1)[1] for n in p.shownames(16, 'nvme-mi.mi.vpd.rti')] == [
            'DC Output (0x01)', 'Reserved (NVMe) (0x0e)', 'Reserved (0x20)', 'OEM (0xc0)']
        assert p.shownames(18, 'nvme-mi.pel.bit')[0].endswith('Bit Location (BITLOC): 3')
        assert p.shownames(18, 'nvme-mi.pel.byte') == ['Byte Location (BYTLOC): 4']
        assert p.shows(19, 'nvme-mi.mi.aeo.hdr_unknown') == ['aa', 'bb']


class TestNvmeMiCsiCandidate:
    """A response CSI that names an empty slot while the other slot holds an
    unanswered same-type request is a possible mismatch (NVMe-MI 2.2
    Figure 20): noted from a first-pass snapshot, never paired."""

    FILE = 'nvme-mi-csi-candidate.pcapng'
    CAND = 'nvme-mi.response_csi_candidate'
    UNLINKED = (' && !nvme-mi.response_to && !nvme-mi.response_time'
                ' && !nvme-mi.response_csi_mismatch')

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_lifecycle(self, assert_frames_match, two_pass):
        c = self.CAND
        cases = [
            (2, f'{c} && nvme-mi.mi.orphan_response && !nvme-mi.mi.opcode' + self.UNLINKED),
            (3, (f'nvme-mi.response_to == 1 && !{c} && !nvme-mi.response_csi_mismatch'
                ' && !nvme-mi.mi.orphan_response')),
            (4, '!nvme-mi.req_superseded'),
            (5, f'nvme-mi.response_to == 4 && !{c}'),
            (7, f'{c} && nvme-mi.admin.orphan_response' + self.UNLINKED),
            (8, f'nvme-mi.response_to == 6 && !{c} && !nvme-mi.admin.orphan_response'),
            (10, f'{c}' + self.UNLINKED),
            (11, f'nvme-mi.response_to == 9 && !{c}'),
            (13, f'!{c} && nvme-mi.admin.orphan_response'),
            (14, f'!{c} && nvme-mi.mi.orphan_response'),
            (16, f'!{c} && nvme-mi.mi.orphan_response'),
            (19, f'!{c} && nvme-mi.mi.orphan_response'),
            (21, f'!{c} && nvme-mi.mic_bad && nvme-mi.mi.orphan_response'),
            (22, f'nvme-mi.response_to == 20 && !{c}'),
        ]
        if two_pass:
            cases.append((1, 'nvme-mi.response_in == 3'))
        else:
            cases.append((1, '!nvme-mi.response_in'))
        assert_frames_match(self.FILE, cases, two_pass=two_pass)

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_census_and_message(self, dissect_pdml, two_pass):
        p = dissect_pdml(self.FILE, two_pass=two_pass)
        assert p.frames_with(self.CAND) == [2, 7, 10]
        for frame, req in ((2, 1), (7, 6), (10, 9)):
            assert p.experts(frame)[0] == (
                'Possible response CSI mismatch: CSI 1 has no matching request;'
                ' an outstanding same-type request names CSI 0 in frame'
                f' {req} (a missing request or reused tag is also possible)')
            # On the CSI item.
            assert p.fields(frame, 'nvme-mi.csi')[0].find(
                f".//field[@name='{self.CAND}']") is not None


class TestNvmeMiDecodeCorrectness:
    """PCC CRT bit order (Base 2.4 Fig 360), SMART / Health INFW (Fig 213)
    and Telemetry TCDA wording (Figs 221/223)."""

    FILE = 'nvme-mi-decode-correctness.pcapng'
    S = 'nvme.cmd.get_logpage.smart.'

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_decode(self, assert_frames_match, two_pass):
        s = self.S
        assert_frames_match(self.FILE, [
            (2, ('nvme.cmd.identify.pcc.crt == 0x01'
                ' && nvme.cmd.identify.pcc.crt.vqrs == 1'
                ' && nvme.cmd.identify.pcc.crt.virs == 0')),
            (4, ('nvme.cmd.identify.pcc.crt == 0x02'
                ' && nvme.cmd.identify.pcc.crt.vqrs == 0'
                ' && nvme.cmd.identify.pcc.crt.virs == 1')),
            (6, (f'{s}infw == 0x01 && {s}infw.vlthw == 1 && {s}infw.rsvd == 0'
                f' && {s}rsvd0[0] == 0x5a')),
            (8, f'{s}infw == 0xff && {s}infw.vlthw == 1 && {s}infw.rsvd == 0x7f'),
            (10, f'{s}infw == 0x00 && {s}infw.vlthw == 0'),
            (12, 'nvme.cmd.get_logpage.telemetry.da == 1'),
            (14, 'nvme.cmd.get_logpage.telemetry.da == 0'),
        ], two_pass=two_pass)

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_extents_labels_and_no_experts(self, dissect_pdml, two_pass):
        p = dissect_pdml(self.FILE, two_pass=two_pass)
        for frame in range(1, 15):
            assert p.experts(frame) == [], frame
        for frame in (6, 8, 10):
            infw = p.extents(frame, self.S + 'infw')
            rsvd = p.extents(frame, self.S + 'rsvd0')
            assert len(infw) == 1 and len(rsvd) == 1
            assert infw[0][1] == 1
            assert rsvd[0] == (infw[0][0] + 1, 24)
        assert p.label(6, self.S + 'infw.vlthw') == 'True'
        assert 'Voltage Log Threshold Warning (VLTHW)' in \
            p.shownames(6, self.S + 'infw.vlthw')[0]
        assert 'Informative Warning (INFW)' in p.shownames(6, self.S + 'infw')[0]
        assert p.label(12, 'nvme.cmd.get_logpage.telemetry.da') == (
            'Updated since last read with RAE=0'
            ' (<=2.3: saved internal state available) (0x01)')
        assert p.label(14, 'nvme.cmd.get_logpage.telemetry.da') == (
            'Not updated since last read with RAE=0'
            ' (<=2.3: header only, no saved state) (0x00)')


class TestNvmeMiAdminTransfer:
    """Admin DLEN against the data the command dwords define (MI 2.2
    Figure 139, Base 2.4 Figure 92), Response Data on opcodes that return
    none, the CID (Figure 141) and Error Response surplus (Figures 30-34)."""

    FILE = 'nvme-mi-admin-transfer.pcapng'
    DLEN = 'nvme-mi.admin.invalid_dlen'

    @staticmethod
    def exact(dlen, required, what):
        return (f'Data Length {dlen} does not equal the {required} bytes of'
                f' NVMe Request Data the {what} requires')

    @staticmethod
    def some(what):
        return f'Data Length is zero; the {what} defines a data transfer'

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_request_dlen_rules(self, dissect_pdml, two_pass):
        p = dissect_pdml(self.FILE, two_pass=two_pass)
        expected = {
            1: self.exact(8, 16, 'Firmware Image Download NUMD'),
            5: self.exact(8, 4096, 'Namespace Attachment Controller List'),
            9: self.exact(0, 4096, 'Namespace Management Create data structure'),
            11: ('Data Length 4 is nonzero; the Namespace Management Delete or'
                 ' Restore transfers no data'),
            15: self.some('Manage Exported NVM Subsystem Receive SEL'),
            19: self.some('Manage Exported NVM Subsystem Send SEL'),
            23: self.some('Manage Exported NVM Subsystem Send SEL'),
            25: self.some('Manage Exported Namespace SEL'),
            27: self.some('Manage Exported Port SEL'),
            29: self.exact(8, 16, 'Security Send Transfer Length'),
            33: self.some('Security Receive Allocation Length'),
            37: self.some('Get LBA Status MNDW'),
            39: self.exact(0, 8, 'Set Features FID'),
            41: self.some('Get Features FID and SEL'),
            47: self.some('Get Features FID and SEL'),
        }
        # F56 is the Excess Data response, below; F73+ test Features.
        assert [f for f in p.frames_with(self.DLEN) if f < 73] == \
            sorted(set(expected) | {56})
        for frame, message in expected.items():
            assert p.experts(frame) == [message], frame
            # On the visible Data Length item.
            dlen = p.fields(frame, 'nvme-mi.admin.dlen')[0]
            assert dlen.get('hide') is None
            assert dlen.find(f".//field[@name='{self.DLEN}']") is not None
        # Undecidable or no-data dwords: reserved SELs, ESUBIDV set, TL/AL
        # 0h, Get Features SEL 011b.
        for frame in (3, 7, 13, 17, 21, 31, 35, 43):
            assert p.experts(frame) == [], frame
        # Set Features HMB transfers no data; MI prohibits the Set (Figure 148).
        assert p.experts(45) == [
            ('Set Features of this Feature is prohibited on NVMe-MI Management'
            " Endpoints (NVMe-MI 'Management Endpoint - Feature Support')")]
        assert p.experts(53) == [
            ("Reserved or unlisted Admin opcode (NVMe Base 'Opcodes for Admin Commands';"
            " NVMe-MI 'List of NVMe Admin Commands Supported using the Out-of-Band"
            " Mechanism')")]
        for frame in range(2, 49, 2):
            assert p.experts(frame) == [], frame

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_features_transfer(self, dissect_pdml, two_pass):
        # Features DLEN/DOFST against the FID, SEL and dwords (MI 2.2
        # Figure 139, Base 2.4 Figure 466, NVM CS 1.3 Figure 92).
        p = dissect_pdml(self.FILE, two_pass=two_pass)
        get, setf = 'Get Features FID and SEL', 'Set Features FID'
        none = 'Data Length 4 is nonzero; the {} transfers no data'
        outside = 'Data Offset {} is outside the {}-byte ' + get + ' completion data'
        exceeds = ('Data Offset {} plus Data Length {} exceeds the {}-byte '
                   + get + ' completion data')
        flagged = {
            73: self.exact(4, 8, setf),
            75: outside.format(8, 8),
            79: ('Data Offset 4 is nonzero for an Admin command that does not'
                 ' transfer Response Data'),
            85: none.format(get),
            87: ('Data Offset 4 is nonzero; the Get Features FID and SEL returns'
                 ' no Response Data'),
            99: outside.format(16, 16),
            107: none.format(setf),
            113: none.format(setf),
            115: self.exact(8, 4096, setf),
            121: outside.format(4096, 4096),
            123: self.exact(512, 1024, setf),
            129: exceeds.format(1020, 8, 1024),
            135: self.exact(0, 4096, setf),
            137: exceeds.format(4092, 8, 4096),
            139: none.format(setf),
            143: none.format(get),
            83: ('Data Length 8 is nonzero; the Get Features FID and SEL'
                 ' transfers no data'),
        }
        for frame, message in flagged.items():
            assert p.experts(frame) == [message], frame
        # Select 011b returns capabilities in CQE DW0 and no Response Data
        # (Base 2.4 Figure 201), whatever the FID.
        sel3_dofst = ('Data Offset 4 is nonzero; the Get Features FID and SEL'
                      ' returns no Response Data')
        for frame, dlen in ((157, 8), (159, 16)):
            assert p.experts(frame) == [
                sel3_dofst,
                (f'Data Length {dlen} is nonzero; the Get Features FID and SEL'
                ' transfers no data')], frame
        new_dlen = {73, 83, 85, 107, 113, 115, 123, 129, 135, 137, 139, 143,
                    157, 159, 163, 169, 177, 185, 191, 197, 203, 210}
        assert [f for f in p.frames_with(self.DLEN) if f >= 73] == sorted(new_dlen)
        assert [f for f in p.frames_with('nvme-mi.admin.invalid_dofst')
                if f >= 73] == [75, 79, 87, 99, 121, 157, 159, 165, 167, 179,
                                187, 193, 199, 209]
        # Valid windows, unknown selections and CHPS 0 stay silent.
        for frame in (77, 78, 81, 82, 89, 90, 91, 93, 95, 97, 98, 101, 102,
                      103, 105, 109, 111, 117, 119, 125, 127, 131, 133):
            assert p.experts(frame) == [], frame
        assert p.sizes(78, 'nvme-mi.admin.data') == [4]
        assert p.frames_with('nvme.features.field_invalid') == []
        # Stray Select 011b Response Data stays raw MI data.
        for frame, size in ((84, 8), (158, 8), (160, 16)):
            assert p.experts(frame) == [
                (f'NVMe Response Data is {size} bytes for Get Features with'
                ' Select 011b, which returns capabilities in CQE DW0 and no'
                ' Response Data')], frame
            data = p.fields(frame, 'nvme-mi.admin.data')[0]
            assert data.get('hide') is None and int(data.get('size')) == size
            assert p.fields(frame, 'nvme.data') == []
            assert p.fields(frame, 'nvme.get_features.tst') == []
            assert p.fields(frame, 'nvme.features.hostid') == []
        # Capabilities in DW0 with no window are silent.
        assert p.experts(161) == [] and p.experts(162) == []
        assert p.values(162, 'nvme.cqe.dword0.get_features.caps.svbl') == [1]
        assert p.experts(141) == [
            ("Get Features Select value is reserved (NVMe Base 'Get Features - Command Dword 10');"
            ' completion Dword 0 and data are shown raw')]
        assert p.experts(142) == []
        assert [f for f in p.frames_with('nvme-mi.admin.short_response')
                if f >= 73] == []

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_vendor_data_transfer_direction(self, dissect_pdml, two_pass):
        # Vendor specific commands follow opcode bits 1:0 (Base 2.4 Figure
        # 92); their sizes and options stay unknown.
        p = dissect_pdml(self.FILE, two_pass=two_pass)
        no_resp = ('Data Offset 4 is nonzero for an Admin command that does'
                   ' not transfer Response Data')
        assert p.experts(163) == [
            ('Data Length 4 is nonzero for an Admin command defined to'
            ' transfer no data')]
        dlen = p.fields(163, 'nvme-mi.admin.dlen')[0]
        assert dlen.get('hide') is None
        assert dlen.find(f".//field[@name='{self.DLEN}']") is not None
        for frame in (165, 167):
            assert p.experts(frame) == [no_resp], frame
            doff = p.fields(frame, 'nvme-mi.admin.doff')[0]
            assert doff.find(
                ".//field[@name='nvme-mi.admin.invalid_dofst']") is not None
        assert p.fields(167, 'nvme-mi.admin.unexpected_request_data') == []
        # DTD 01b without Request Data keeps the carried-length check.
        assert p.experts(169) == [
            'Data Length 4 must equal the 0-byte NVMe Request Data field']
        # Response-bearing directions keep DOFST and raw Response Data.
        for frame in (164, 166, 168, 170, 171, 172, 173, 174, 175):
            assert p.experts(frame) == [], frame
        for frame in (172, 174):
            data = p.fields(frame, 'nvme-mi.admin.data')[0]
            assert data.get('hide') is None and int(data.get('size')) == 4
        assert p.experts(176) == [
            ('NVMe Response Data is 4 bytes for an opcode whose data transfer'
            ' bits 1:0 (00b) return no data')]

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_maximum_completion_data(self, dissect_pdml, two_pass):
        # MNDW (NVM CS 1.3 Figure 137) and the SECP 00h-03h AL (SIIS 1.20
        # Table 24) bound the window from above (MI 2.2 Figure 139).
        p = dissect_pdml(self.FILE, two_pass=two_pass)
        lba = 'maximum Get LBA Status completion data'
        al = 'Security Receive Allocation Length'
        assert p.experts(177) == [
            f'Data Offset 8 plus Data Length 8 exceeds the 12-byte {lba}']
        assert p.experts(179) == [f'Data Offset 12 is outside the 12-byte {lba}']
        for first in (185, 191, 197):
            assert p.experts(first) == [
                f'Data Offset 8 plus Data Length 8 exceeds the 12-byte {al}'], first
            assert p.experts(first + 2) == [
                f'Data Offset 12 is outside the 12-byte {al}'], first
        for frame in (203, 210):
            assert p.experts(frame) == [
                f'Data Offset 8 plus Data Length 8 exceeds the 12-byte {al}'], frame
        assert p.experts(209) == [f'Data Offset 12 is outside the 12-byte {al}']
        # An end equal to the maximum, a 64-bit end, SECP EEh, AL 0 and a
        # partial read are silent.
        for frame in (181, 182, 183, 184, 189, 190, 195, 196, 201, 202, 205,
                      207, 212, 213):
            assert p.experts(frame) == [], frame
        # The response keeps its single Security window warning.
        window = 'Security data window [8, 16) exceeds AL 12; payload left raw'
        for frame in (186, 192, 198, 204, 206):
            assert p.experts(frame) == [window], frame
        assert p.experts(211) == ['Command completed with an error status', window]

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_rae_set(self, dissect_pdml, two_pass):
        # RAE 1 keeps the wire bit and gets only the policy text, no expert
        # info (MI 2.2 Figure 137).
        p = dissect_pdml(self.FILE, two_pass=two_pass)
        assert p.shows(214, 'nvme.cmd.get_logpage.dword10.rae') == ['True']
        assert p.shows(214, 'nvme-mi.admin.rae_handling') == [RAE_TEXT]
        assert p.experts(214) == []
        assert p.experts(215) == []

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_prohibited_selectors(self, dissect_pdml, two_pass):
        # MI 2.2 Figures 144 and 148, flagged on the opcode.
        p = dissect_pdml(self.FILE, two_pass=two_pass)
        assert p.experts(145) == [
            ('Log page is prohibited on NVMe-MI Management Endpoints'
            " (NVMe-MI 'Management Endpoint - Log Page Support')")]
        opc = p.fields(145, 'nvme-mi.admin.opcode')[0]
        assert opc.find(".//field[@name='nvme-mi.admin.prohibited_lid']") is not None
        # 19h is prohibited only on Enclosures; Get of an MI-prohibited Set
        # FID is allowed.
        for frame in range(146, 151):
            assert p.experts(frame) == [], frame

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_meb_inline_data(self, dissect_pdml, two_pass):
        # MEB does not make Request Data valid for a Get (MI 2.2 4.2.3).
        p = dissect_pdml(self.FILE, two_pass=two_pass)
        assert p.experts(151) == [
            ('Command is not defined to transfer NVMe Request Data'
            " (NVMe-MI 'NVMe Admin Command Request Description')")]
        assert p.experts(152) == []

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_window_inside_a_field_stays_raw(self, dissect_pdml, two_pass):
        # A window inside DUR (MI 2.2 Figures 142/143) decodes no field, so
        # the raw Response Data stays visible.
        p = dissect_pdml(self.FILE, two_pass=two_pass)
        raw = p.fields(154, 'nvme-mi.admin.data')[0]
        assert raw.get('hide') is None and int(raw.get('size')) == 8
        assert p.fields(154, 'nvme.cmd.get_logpage.smart.dur') == []
        assert p.fields(156, 'nvme-mi.admin.data')[0].get('hide') == 'yes'
        assert p.fields(156, 'nvme.cmd.get_logpage.smart.dur') != []
        for frame in (153, 154, 155, 156):
            assert p.experts(frame) == [], frame

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_response_data_and_cid(self, dissect_pdml, two_pass):
        p = dissect_pdml(self.FILE, two_pass=two_pass)
        unexpected = 'nvme-mi.admin.unexpected_response_data'
        assert p.frames_with(unexpected) == [50, 52, 84, 158, 160, 176]
        for frame, size, bits in ((50, 8, '00b'), (52, 4, '00b'),
                                  (176, 4, '00b')):
            assert p.experts(frame) == [
                (f'NVMe Response Data is {size} bytes for an opcode whose data'
                f' transfer bits 1:0 ({bits}) return no data')]
            data = p.fields(frame, 'nvme-mi.admin.data')[0]
            assert data.get('hide') is None and int(data.get('size')) == size
            assert data.find(f".//field[@name='{unexpected}']") is not None
        # A Reserved opcode's transfer direction is unknown.
        assert p.shows(54, 'nvme-mi.admin.data') == ['00:00:00:00']
        assert p.experts(54) == []
        # Excess and short Response Data flag a visible item.
        excess = p.fields(56, 'nvme-mi.admin.data_excess')[0]
        assert excess.get('hide') is None
        assert (int(excess.get('pos')), int(excess.get('size'))) == (44, 4)
        assert excess.find(f".//field[@name='{self.DLEN}']") is not None
        assert p.experts(56) == [
            ("NVMe Response Data is 8 bytes, more than the 4 bytes the request's"
            ' Data Length selected')]
        assert p.fields(58, 'nvme-mi.admin.data')[0].get('hide') == 'yes'
        short = [f for f in p[58].iter('field') if f.get('show') == 'Data'
                 and f.find(".//field[@name='nvme-mi.admin.short_response']")
                 is not None]
        assert len(short) == 1 and short[0].get('hide') is None
        # The CID is cleared to 0h over NVMe-MI.
        assert p.values(60, 'nvme-mi.admin.cqe_dw3.cid') == [5]
        assert p.experts(60) == [
            ('Command Identifier is not 0h; it shall be cleared to 0h'
            " (NVMe-MI 'NVMe Admin Command Response Description')")]
        cid = p.fields(60, 'nvme-mi.admin.cqe_dw3.cid')[0]
        assert cid.find(".//field[@name='nvme-mi.admin.cid_nonzero']") is not None
        assert p.values(72, 'nvme-mi.admin.cqe_dw3.cid') == [0]
        assert p.experts(72) == []
        assert p.frames_with('nvme-mi.admin.cid_nonzero') == [60]

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_error_response_surplus(self, dissect_pdml, two_pass):
        p = dissect_pdml(self.FILE, two_pass=two_pass)
        surplus = p.fields(62, 'nvme-mi.admin.surplus')[0]
        assert (int(surplus.get('pos')), int(surplus.get('size'))) == (28, 12)
        assert p.experts(62) == ['12 bytes follow the 4-byte Invalid Parameter Response']
        assert surplus.find(".//field[@name='nvme-mi.admin.error_surplus']") is not None
        # Vendor Specific and Reserved Status fix no layout: raw, no surplus
        # expert; only the Reserved Status is flagged (Figure 29).
        assert p.experts(64) == []
        assert p.experts(66) == [
            "Response Message Status is a Reserved value (NVMe-MI 'Response Message Status Values')"]
        for frame in (64, 66):
            assert p.fields(frame, 'nvme-mi.admin.surplus') == []
            assert p.sizes(frame, 'nvme-mi.admin.data') == [12]
        assert p.frames_with('nvme-mi.admin.error_surplus') == [62]


class TestNvmeMiMiStructures:
    """Read NVMe-MI Data Structure response bodies whose shape is under test."""

    FILE = 'nvme-mi-mi-commands.pcapng'
    SECTION = 1
    CTRLINFO = ('nvme-mi.mi.ctrlinfo.portid', 'nvme-mi.mi.ctrlinfo.prii',
                'nvme-mi.mi.ctrlinfo.riv', 'nvme-mi.mi.ctrlinfo.pri',
                'nvme-mi.mi.ctrlinfo.pcivid', 'nvme-mi.mi.ctrlinfo.pcidid',
                'nvme-mi.mi.ctrlinfo.pcisvid', 'nvme-mi.mi.ctrlinfo.pcisdid',
                'nvme-mi.mi.ctrlinfo.pciesn', 'nvme-mi.mi.ctrlinfo.pri.bus',
                'nvme-mi.mi.ctrlinfo.pri.dev', 'nvme-mi.mi.ctrlinfo.pri.fn',
                'nvme-mi.mi.ctrlinfo.pri.arifn', 'nvme-mi.mi.list_surplus', '_ws.expert')

    def test_decode(self, assert_frames_match):
        surplus = 'nvme-mi.mi.list_surplus == de:ad:be:ef:55:aa'
        assert_frames_match(self.FILE, at(self.SPAN, [
            # The declared element still decodes ahead of the surplus.
            (4, ('nvme-mi.mi.ctrllist.numids == 1 && nvme-mi.mi.ctrllist.ctrlid == 0x0001'
                 ' && ' + surplus)),
            (10, ('nvme-mi.mi.cmdlist.numcmd == 1 && nvme-mi.mi.cmdlist.opc == 0x01'
                  ' && nvme-mi.mi.cmdlist.nmimt == 1 && ' + surplus)),
            # Figure 120 has no ARI indication, so by default PRI 7:0 is
            # Device/Function -- meaningless for F14's ARI Function 7Fh.
            (12, ('nvme-mi.mi.ctrlinfo.pri == 0x0a1d && nvme-mi.mi.ctrlinfo.pri.bus == 0x0a'
                  ' && nvme-mi.mi.ctrlinfo.pri.dev == 0x03 && nvme-mi.mi.ctrlinfo.pri.fn == 0x05'
                  ' && nvme-mi.mi.ctrlinfo.riv == 1')),
            (14, ('nvme-mi.mi.ctrlinfo.pri == 0x0b7f && nvme-mi.mi.ctrlinfo.pri.bus == 0x0b'
                  ' && nvme-mi.mi.ctrlinfo.pri.dev == 0x0f && nvme-mi.mi.ctrlinfo.pri.fn == 0x07')),
            (58, ('nvme-mi.mi.ctrlinfo.pri == 0x0a1d && nvme-mi.mi.ctrlinfo.pri.dev == 0x03'
                  ' && nvme-mi.mi.ctrlinfo.pri.fn == 0x05 && nvme-mi.mi.response_data_length')),
        ]))

    def test_pairing_and_censuses(self, fields_table, dissect_pdml):
        t = section(fields_table(self.FILE, (
            'nvme-mi.type', 'nvme-mi.response_to', 'nvme-mi.req_superseded', 'nvme-mi.mic.status',
            '_ws.malformed.expert', '_ws.expert', 'nvme-mi.mi.response_data_length',
            'nvme-mi.mi.truncated', 'nvme-mi.mi.vpd.undecoded',
            'nvme-mi.mi.list_surplus', 'nvme-mi.mi.ctrllist.numids')), self.SPAN)
        assert column(t, 'nvme-mi.type') == {n: '0x00000001' for n in range(1, 75)}
        assert column(t, 'nvme-mi.response_to') == {n + 1: str(n) for n in range(1, 74, 2)}
        assert column(t, 'nvme-mi.req_superseded') == {}
        assert [n for n, v in column(t, 'nvme-mi.mic.status').items() if v == '1'] == [
            n for n in range(1, 75) if n != 65]
        assert column(t, '_ws.malformed.expert') == {}
        # Each declared/fixed-length mismatch is diagnosed once, as is
        # missing Response Data (F48, F64).  Empty CHDS and VPD and a selected
        # VPD window are legal.
        length_frames = [18, 20, 22, 34, 36, 38, 44, 46, 48, 52, 54, 58, 60, 62, 64, 68, 70,
                         72, 74]
        assert list(column(t, 'nvme-mi.mi.response_data_length')) == length_frames
        assert column(t, 'nvme-mi.mi.truncated') == {}
        # Unplaced VPD windows remain filterable and explain their raw display.
        assert list(column(t, 'nvme-mi.mi.vpd.undecoded')) == [50, 66]
        # Surplus list data is shown; nothing is flagged.
        assert list(column(t, 'nvme-mi.mi.list_surplus')) == [4, 10]
        assert [n for n in column(t, '_ws.expert') if n <= 14] == []
        assert [n for n, v in column(t, 'nvme-mi.mi.ctrllist.numids').items() if v == '0'] == [6]

        p = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        messages = {n: p.experts(n) for n in p.packets if p.experts(n)}
        for frame in (50, 66):
            vpd_data, = p.fields(frame, 'nvme-mi.mi.vpd.data')
            assert 'bytes shown raw' in vpd_data.get('showname', '').lower(), frame
            assert not any('VPD' in message for message in messages.get(frame, [])), frame
        for frame in length_frames:
            assert len(messages[frame]) == 1, (frame, messages[frame])
        # CHDS order, Starting Controller ID, RENT above MAXRENT and
        # undefined fields are shown as sent.
        for frame in (16, 24, 26, 28, 30, 32, 40, 42, 56):
            assert not messages.get(frame), (frame, messages.get(frame))
        # MAXRENT FFh is shown as sent, and flagged (Figure 94: at most 255).
        assert p.field(25, 'nvme-mi.mi.chsp.maxrent')['show'] == '255'
        assert messages[25] == [
            ('MAXRENT FFh asks for 256 entries but the maximum is 255; the Responder'
            ' returns an Invalid Parameter Error Response (NVMe-MI'
            " 'Controller Health Status Poll - NVMe Management Dword 0')")]
        assert 'has 7 bytes' in messages[44][0] and 'requires exactly 8 bytes' in messages[44][0]
        assert 'has 9 bytes' in messages[46][0] and 'requires exactly 8 bytes' in messages[46][0]
        assert not {n: m for n, m in messages.items() if n <= 14}

    def test_bounded_fields_and_tails(self, dissect_pdml):
        """A partial CHDS stays raw, PTSP stops at byte 32, and declared or
        structural surplus stays outside the decoded structure."""
        p = pdml_section(dissect_pdml(self.FILE, two_pass=True), self.SPAN)
        for frame, ids in {16: [1, 2], 18: [1], 20: [1], 22: [1], 24: [2, 1], 28: [1, 2]}.items():
            assert p.values(frame, 'nvme-mi.mi.chds.ctlid') == ids, frame
        assert p.field(22, 'nvme-mi.mi.data')['value'] == 'aa'
        assert p.fields(44, 'nvme-mi.mi.nshds.nss') == []
        # Whole field-bearing prefixes decode even without the reserved tail.
        assert [p.values(34, 'nvme-mi.mi.subsys.mjr')[0], p.values(36, 'nvme-mi.mi.subsys.mjr')[0],
                p.values(58, 'nvme-mi.mi.ctrlinfo.portid')[0]] == [2, 2, 1]
        # The MI layer starts with the 4-byte response header.
        for frame, size, data, selected in (
                (20, 16, None, 16), (38, 6, 'deadbeef55aa', 32), (46, 1, 'aa', 8),
                (52, 2, '5566', 4), (60, 6, 'deadbeef55aa', 32), (62, 6, 'deadbeef55aa', 4)):
            surplus, = p.fields(frame, 'nvme-mi.mi.response_surplus')
            assert int(surplus.get('size')) == size, frame
            if data is not None:
                assert surplus.get('value') == data, frame
            assert int(surplus.get('pos')) == (
                int(p.field(frame, 'nvme-mi.mi.status')['pos']) + 4 + selected), frame
        for frame in (38, 40):
            raw, = p.fields(frame, 'nvme-mi.mi.data')
            assert (int(raw.get('pos')), int(raw.get('size'))) == (
                int(p.field(frame, 'nvme-mi.mi.port.prttyp')['pos']) + 8, 24)
        assert p.fields(62, 'nvme-mi.mi.list_surplus') == []
        for frame, size in ((50, '4'), (52, '4'), (54, '2'), (66, '4')):
            assert [f.get('size') for f in p.fields(frame, 'nvme-mi.mi.vpd.data')] == [size]

    def test_surplus_items_cover_exactly_the_surplus(self, dissect_pdml):
        """One tail item from the end of the last declared element to RDL."""
        p = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        assert [n for n in range(1, 15) for _ in p.fields(n, 'nvme-mi.mi.list_surplus')] == [4, 10]
        for frame, count_name, last_name, last_size in (
                (4, 'nvme-mi.mi.ctrllist.numids', 'nvme-mi.mi.ctrllist.ctrlid', 2),
                (10, 'nvme-mi.mi.cmdlist.numcmd', 'nvme-mi.mi.cmdlist.opc', 1)):
            count = p.field(frame, count_name)
            surplus = p.field(frame, 'nvme-mi.mi.list_surplus')
            assert count['size'] == '2' and surplus['size'] == '6', frame
            assert int(surplus['pos']) == int(p.field(frame, last_name)['pos']) + last_size
            assert int(surplus['pos']) + 6 == int(count['pos']) + 10, frame

    def test_port_prefixes_remain_visible_and_bounded(self, dissect_pdml):
        """MI 2.2 Figures 117-119: decode whole prefixes, never a partial PTSP."""
        p = pdml_section(dissect_pdml(self.FILE, dfilter=to_capture(self.SPAN, 'frame.number in {68,70,72,74}')), self.SPAN)
        assert sorted(p.packets) == [68, 70, 72, 74]
        for frame, length in ((68, 9), (70, 14), (72, 12), (74, 13)):
            packet = p[frame]
            assert p.fields(frame, 'nvme-mi.mi.port.mmtus')
            assert bool(p.fields(frame, 'nvme-mi.mi.port.pcie.pn')) == (frame == 70)
            assert bool(p.fields(frame, 'nvme-mi.mi.port.nvmebm')) == (frame == 74)
            covered = set()
            for field in packet.iter('field'):
                if not field.get('name', '').startswith('nvme-mi.mi.') or field.get('hide') == 'yes':
                    continue
                pos, size = int(field.get('pos', 0)), int(field.get('size', 0))
                if pos >= 28 and size:
                    assert pos + size <= 28 + length, (frame, field.attrib)
                    covered.update(range(pos, pos + size))
            assert covered == set(range(28, 28 + length)), frame
            experts = packet.findall(".//field[@name='_ws.expert']")
            assert len(experts) == 1
            assert experts[0].find("./field[@name='nvme-mi.mi.response_data_length']") is not None

    def test_ari_preference(self, fields_table):
        """With nvme-mi.ctrlinfo_ari, PRI 7:0 is one Function Number (Figure 120)."""
        default = section(fields_table(self.FILE, self.CTRLINFO), self.SPAN)
        ari = section(fields_table(self.FILE, self.CTRLINFO, prefs={'nvme-mi.ctrlinfo_ari': 'TRUE'}), self.SPAN)
        assert column(default, 'nvme-mi.mi.ctrlinfo.pri.arifn') == {}
        assert list(column(default, 'nvme-mi.mi.ctrlinfo.pri.dev')) == [12, 14, 58]
        assert list(column(default, 'nvme-mi.mi.ctrlinfo.pri.fn')) == [12, 14, 58]
        assert {n: [ari[n][f] for f in ('nvme-mi.mi.ctrlinfo.pri', 'nvme-mi.mi.ctrlinfo.pri.bus',
                                        'nvme-mi.mi.ctrlinfo.pri.arifn')]
                for n in column(ari, 'nvme-mi.mi.ctrlinfo.pri')} == {
            12: ['0x0a1d', '0x000a', '0x001d'], 14: ['0x0b7f', '0x000b', '0x007f'],
            58: ['0x0a1d', '0x000a', '0x001d']}
        assert column(ari, 'nvme-mi.mi.ctrlinfo.pri.dev') == {}
        assert column(ari, 'nvme-mi.mi.ctrlinfo.pri.fn') == {}
        unchanged = self.CTRLINFO[:10] + ('nvme-mi.mi.list_surplus', '_ws.expert')
        assert ({n: [r[f] for f in unchanged] for n, r in default.items()}
                == {n: [r[f] for f in unchanged] for n, r in ari.items()})


class TestNvmeMiNullTreeParity:
    """Response semantics must not depend on whether a tree is built."""

    TCG_FILE = 'nvme-mi-security.pcapng'
    TCG_SPAN = (59, 70)   # build_tcg_malformed_pcapng's section
    # Every expert here comes from a response (opcode recovery); unfinished
    # atoms are fragments, not malformed.
    TCG_DISTRIBUTION = ((2, 1), (10, 4))
    #: (capture, section): the TCG-malformed and error-paths sections, and
    #: three whole captures (None).
    NVME_MI_FILES = (('nvme-mi-security.pcapng', (59, 70)),
                     ('nvme-mi-mi-commands.pcapng', (419, 458)),
                     ('nvme-mi-transactions.pcapng', (259, 287)),
                     ('nvme-mi-control.pcapng', None), ('nvme-mi-mi-commands.pcapng', (1, 74)))

    def test_baselines_behind_the_parity(self, dissect_pdml):
        """The tree side of the tap comparison, pinned per recovery site."""
        tcg = pdml_section(dissect_pdml(self.TCG_FILE), self.TCG_SPAN)
        assert {n: len(tcg.experts(n)) for n in tcg.packets if tcg.experts(n)} == dict(
            self.TCG_DISTRIBUTION)
        types = dissect_pdml('nvme-mi-types.pcapng')
        assert types.experts(24) == types.experts(25) == []
        mismatch = pdml_section(dissect_pdml('nvme-mi-types.pcapng'), (119, 124))
        assert [n for n in mismatch.packets if any(
            'without a usable matching request' in m for m in mismatch.experts(n))] == [2, 4]

    @pytest.mark.parametrize(('capture', 'span'), NVME_MI_FILES)
    def test_recovery_and_passes(self, fields_table, capture, span):
        """Opcode recovery and the orphan expert partition responses, in both passes."""
        fields = ('nvme-mi.ror', 'nvme-mi.type', 'nvme-mi.control.truncated', '_ws.expert.message',
                  'nvme-mi.admin.opcode', 'nvme-mi.admin.orphan_response', 'nvme-mi.mi.opcode',
                  'nvme-mi.mi.orphan_response', 'nvme-mi.control.opcode',
                  'nvme-mi.control.orphan_response')
        t = fields_table(capture, fields)
        t = section(t, span) if span else t
        for nmimt, opcode, orphan in ((2, 'nvme-mi.admin.opcode', 'nvme-mi.admin.orphan_response'),
                                      (1, 'nvme-mi.mi.opcode', 'nvme-mi.mi.orphan_response'),
                                      (0, 'nvme-mi.control.opcode', 'nvme-mi.control.orphan_response')):
            responses = [r for r in t.values() if r['nvme-mi.ror'] == 'True'
                         and r['nvme-mi.type'] and int(r['nvme-mi.type'], 0) == nmimt
                         and not (nmimt == 0 and r['nvme-mi.control.truncated'])]
            assert all(bool(r[opcode]) != bool(r[orphan]) for r in responses), (capture, opcode)
        two = fields_table(capture, fields, two_pass=True)
        two = section(two, span) if span else two
        assert column(t, '_ws.expert.message') == column(two, '_ws.expert.message')

    def test_admission_experts_are_mode_independent(self, dissect_pdml):
        """Admission refusals are framing-layer decisions, raised once each."""
        p = pdml_section(dissect_pdml('nvme-mi-transactions.pcapng'), (1, 178))
        messages = [m for n in p.packets for m in p.experts(n)]
        assert sum('no Status byte' in m for m in messages) == 1
        assert sum('does not echo the request tag' in m for m in messages) == 3


class TestNvmeLogpageWindows:
    """Windowed log pages whose records carry their own length."""

    FILE = 'nvme-mi-admin-logpage.pcapng'
    SECTION = 5

    def test_decode(self, assert_frames_match):
        # NLRD is BASE_DEC_HEX, so it is compared by value.
        assert_frames_match(self.FILE, at(self.SPAN, [
            (8, 'nvme.cmd.get_logpage.lba_status.nel.ne.nlrd == 2'),
            (10, 'nvme.cmd.get_logpage.lba_status.nel.ne.nlrd == 2'),
            # Base 2.3 Figure 220: no Host-Initiated Data Generation Number.
            (23, 'nvme.cmd.get_logpage.dword10.id == 0x08'),
            (24, ('nvme.cmd.get_logpage.telemetry.li == 0x08'
                  ' && nvme.cmd.get_logpage.telemetry.scope == 2'
                  ' && nvme.cmd.get_logpage.telemetry.da == 0'
                  ' && nvme.cmd.get_logpage.telemetry.dgn == 0x5a'
                  ' && !nvme.cmd.get_logpage.telemetry.hdgn')),
        ]))

    def test_field_values(self, fields_table):
        t = section(fields_table(self.FILE, (
            'nvme-mi', '_ws.malformed', '_ws.expert.message', 'nvme.window_decode_skipped',
            'nvme.cmd.get_logpage.ana.chcnt', 'nvme.cmd.get_logpage.ana.ngd',
            'nvme.cmd.get_logpage.ana.grp.id', 'nvme.cmd.get_logpage.ana.grp.nns',
            'nvme.cmd.get_logpage.ana.grp.nsid',
            'nvme.cmd.get_logpage.lba_status.lslplen', 'nvme.cmd.get_logpage.lba_status.nlslne',
            'nvme.cmd.get_logpage.lba_status.nel.ne.neid',
            'nvme.cmd.get_logpage.lba_status.nel.ne.ratype',
            'nvme.cmd.get_logpage.lba_status.nel.ne.rd.rslba',
            'nvme.cmd.get_logpage.window_misaligned',
            'nvme.cmd.get_logpage.identify.dlpf', 'nvme.cmd.get_logpage.identify.dlpf.extend',
            'nvme.cmd.get_logpage.identify.dlpf.portlcl',
            'nvme.cmd.get_logpage.identify.dlpf.allsub',
            'nvme.cmd.get_logpage.identify.dlpf.rsvd', 'nvme.cmd.get_logpage.identify.tdlpl',
            'nvme.cmd.get_logpage.identify.numrec', 'nvme.cmd.get_logpage.identify.rcrd',
            'nvme.cmd.get_logpage.identify.rcrd.trtype',
            'nvme.cmd.get_logpage.identify.rcrd.portid',
            'nvme.cmd.get_logpage.identify.rcrd.cntlid',
            'nvme.cmd.get_logpage.identify.rcrd.tel',
            'nvme.cmd.get_logpage.identify.rcrd.numexat',
            'nvme.cmd.get_logpage.identify.rcrd.exat.type',
            'nvme.cmd.get_logpage.identify.rcrd.exat.len')), self.SPAN)

        def row(frame, *names):
            return [t[frame][n] for n in names]

        assert list(column(t, 'nvme-mi')) == list(range(1, 25))
        # Every transfer here is legal; some just cannot be placed.
        assert column(t, '_ws.malformed') == {}
        # ANA: the full page and the Descriptor 0 boundary decode both
        # descriptors; mid-descriptor bytes (A5h fill) are not read as one.
        ana = ('nvme.cmd.get_logpage.ana.grp.id', 'nvme.cmd.get_logpage.ana.grp.nns',
               'nvme.cmd.get_logpage.ana.grp.nsid')
        assert row(2, 'nvme.cmd.get_logpage.ana.chcnt', 'nvme.cmd.get_logpage.ana.ngd') == [
            '72623859790382856', '2']
        for frame in (2, 4):
            assert row(frame, *ana) == ['0x00000011,0x00000022', '1,1', '0x00000101,0x00000202']
        assert row(6, *ana) == ['', '', '']
        # Only F4 walks descriptors without the header's count.
        assert note_frames(t, SKIP_ANA_COUNT) == [4]
        assert expert_frames(t, SKIP_ANA_COUNT) == []
        # LBA Status: DOFST 32 is a Range Descriptor whose RSLBA would read as
        # NEID 2Ah; DOFST 36 is dword-aligned, so legal (Figure 203), not
        # misaligned.
        lba = ('nvme.cmd.get_logpage.lba_status.nel.ne.neid',
               'nvme.cmd.get_logpage.lba_status.nel.ne.ratype',
               'nvme.cmd.get_logpage.lba_status.nel.ne.rd.rslba')
        assert row(8, 'nvme.cmd.get_logpage.lba_status.lslplen',
                   'nvme.cmd.get_logpage.lba_status.nlslne') == ['64', '1']
        for frame in (8, 10):
            assert row(frame, *lba) == ['0x0000002a', '0x10',
                                        '0x000000000000002a,0x0123456789abcdef']
        for frame in (12, 14):
            assert row(frame, *lba) == ['', '', '']
        assert column(t, 'nvme.cmd.get_logpage.window_misaligned') == {}
        # Exactly the interior windows say why they are not decoded.
        assert note_frames(t, SKIP_RAW) == [6, 12, 14, 22]
        assert expert_frames(t, SKIP_RAW) == []
        # Discovery header: DLPF (byte 18) and TDLPL (23:20) are fields, and
        # read zero rather than absent on a legacy page.
        assert row(16, 'nvme.cmd.get_logpage.identify.dlpf',
                   'nvme.cmd.get_logpage.identify.dlpf.extend',
                   'nvme.cmd.get_logpage.identify.dlpf.portlcl',
                   'nvme.cmd.get_logpage.identify.dlpf.allsub',
                   'nvme.cmd.get_logpage.identify.dlpf.rsvd',
                   'nvme.cmd.get_logpage.identify.tdlpl') == [
            '0x07', 'True', 'True', 'True', '0x00', '3328']
        assert row(18, 'nvme.cmd.get_logpage.identify.dlpf',
                   'nvme.cmd.get_logpage.identify.dlpf.extend',
                   'nvme.cmd.get_logpage.identify.tdlpl') == ['0x00', 'False', '0']
        # Extended entries are TEL apart (Figure 312), not 1,024; the
        # attributes walk by EXATLEN (Figure 533).
        assert row(16, 'nvme.cmd.get_logpage.identify.numrec',
                   'nvme.cmd.get_logpage.identify.rcrd.trtype',
                   'nvme.cmd.get_logpage.identify.rcrd.portid',
                   'nvme.cmd.get_logpage.identify.rcrd.cntlid',
                   'nvme.cmd.get_logpage.identify.rcrd.tel',
                   'nvme.cmd.get_logpage.identify.rcrd.numexat',
                   'nvme.cmd.get_logpage.identify.rcrd.exat.type',
                   'nvme.cmd.get_logpage.identify.rcrd.exat.len') == [
            '2', '0x03,0x01', '0x1000,0x1001', '0x2000,0x2001', '1152,1152', '2,2',
            '0x0001,0x0002,0x0003,0xff01', '16,96,20,80']
        # Legacy entries keep the 1,024 stride and have no TEL (Figure 310).
        assert row(18, 'nvme.cmd.get_logpage.identify.rcrd.trtype',
                   'nvme.cmd.get_logpage.identify.rcrd.portid',
                   'nvme.cmd.get_logpage.identify.rcrd.tel') == [
            '0x03,0x01', '0x3000,0x3001', '']
        # DOFST 2048 is Entry 1's fixed position; DOFST 1536 is mid-entry.
        assert row(20, 'nvme.cmd.get_logpage.identify.rcrd.trtype',
                   'nvme.cmd.get_logpage.identify.rcrd.portid') == ['0x01', '0x3001']
        assert row(22, 'nvme.cmd.get_logpage.identify.rcrd',
                   'nvme.cmd.get_logpage.identify.rcrd.trtype') == ['', '']

    def test_extents_and_labels(self, dissect_pdml):
        p = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        # Telemetry: 361 Reserved bytes, then the scope byte at 381.
        reserved = p.field(24, 'nvme.cmd.get_logpage.telemetry.rsvd2')
        assert reserved['size'] == '361'
        assert int(p.field(24, 'nvme.cmd.get_logpage.telemetry.scope')['pos']) == (
            int(reserved['pos']) + 361)
        # The Discovery header's Reserved run is 1023:24 once DLPF/TDLPL are out.
        assert p.field(16, 'nvme.cmd.get_logpage.identify.rsvd')['size'] == '1000'
        # Entry items are sibling TEL-sized (or 1,024-byte legacy) records.
        for frame, size in ((16, 1152), (18, 1024)):
            records = p.fields(frame, 'nvme.cmd.get_logpage.identify.rcrd')
            assert [r.get('size') for r in records] == [str(size)] * 2
            assert int(records[1].get('pos')) - int(records[0].get('pos')) == size
            assert len(set(field_depths(p[frame], 'nvme.cmd.get_logpage.identify.rcrd'))) == 1
        # FF01h is named from the FF00h-FFFFh Vendor Specific range.
        labels = [f.get('showname')
                  for f in p.fields(16, 'nvme.cmd.get_logpage.identify.rcrd.exat.type')]
        assert len(labels) == 4
        for label, name in zip(labels, ('Host Identifier', 'Admin label ASCII',
                                        'Admin label UTF-8', 'Vendor Specific')):
            assert name in label, label


class TestNvmeMiAdminWindow:
    """The NVMe-MI Admin window's own contracts."""

    FILE = 'nvme-mi-admin-logpage.pcapng'
    SECTION = 3

    def test_decode(self, assert_frames_match):
        # The whole entries carry the partial windows' bytes as a prefix.
        assert_frames_match(self.FILE, at(self.SPAN, [
            (10, ('nvme.cmd.identify.nvmset.num == 1'
                  ' && nvme.cmd.identify.nvmset.id == 0x0101'
                  ' && nvme.cmd.identify.nvmset.endgid == 0x0202')),
            (12, ('nvme.cmd.identify.scl.num == 1'
                  ' && nvme.cmd.identify.scl.scid == 0x0111'
                  ' && nvme.cmd.identify.scl.pcid == 0x0222'
                  ' && nvme.cmd.identify.scl.nvi == 0x0555')),
        ]))

    def test_field_values(self, fields_table):
        t = section(fields_table(self.FILE, (
            'nvme-mi', '_ws.malformed', '_ws.expert.message', '_ws.expert.severity',
            'nvme.cmd.get_logpage.lba_status.lslplen', 'nvme.cmd.get_logpage.lba_status.nlslne',
            'nvme.cmd.get_logpage.lba_status.estulb', 'nvme.cmd.get_logpage.lba_status.lsgc',
            'nvme-mi.admin.data_excess', 'nvme-mi.admin.invalid_dlen',
            'nvme-mi.admin.short_response',
            'nvme.cmd.identify.ctrl.mn', 'nvme.cmd.identify.ctrl.sn',
            'nvme.cmd.identify.nvmset.num', 'nvme.cmd.identify.nvmset.id',
            'nvme.cmd.identify.nvmset.endgid', 'nvme.cmd.identify.scl.num',
            'nvme.cmd.identify.scl.scid', 'nvme.cmd.identify.scl.pcid',
            'nvme.cmd.identify.scl.nvi',
            'nvme.set_features.lbart.type', 'nvme.set_features.lbart.slba',
            'nvme.set_features.lbart.nlb', 'nvme.set_features.lbart.apst',
            'nvme.cmd.get_logpage.smart.cw', 'nvme.cmd.get_logpage.smart.ct',
            'nvme.cmd.identify.ctrl.vid', 'nvme.cmd.identify.ctrl.ssvid',
            'nvme.data.wrong_direction',
            'nvme.cqe.dword0', 'nvme.cqe.dword0.set_features.ncqa',
            'nvme.cqe.dword0.set_features.nq.nsqa', 'nvme.cqe.dword0.get_features.pm.ps',
            'nvme.cqe.dword0.get_features.pm.wh', 'nvme.cmd.get_logpage.numd',
            'nvme-mi.admin.cqe_dw3', 'nvme-mi.admin.cqe_dw3.cid',
            'nvme.cmd.set_features.dword11.erec.tler', 'nvme.cmd.set_features.dword11.erec.dulbe',
            'nvme.cmd.set_features.dword11.erec.rsvd',
            'nvme.cmd.set_features.dword11.rsrvn.rsvd0',
            'nvme.cmd.set_features.dword11.rsrvn.regpre',
            'nvme.cmd.set_features.dword11.rsrvn.resrel',
            'nvme.cmd.set_features.dword11.rsrvn.resrpe',
            'nvme.cmd.set_features.dword11.rsrvn.rsvd1',
            'nvme.cmd.identify.ctrl.psds', 'nvme.cmd.identify.ctrl.psds.psd.mp',
            'nvme.cmd.identify.ctrl.psds.psd.enlat', 'nvme.cmd.identify.ctrl.psds.psd.exlat',
            'nvme.cmd.identify.ctrl.psds.psd.mbws',
            'nvme.cmd.identify.ctrl.nvmeof.ioccsz', 'nvme.cmd.identify.ctrl.nvmeof.iorcsz',
            'nvme.cmd.identify.ctrl.nvmeof.msdbd', 'nvme.cmd.identify.ctrl.nvmeof.ccrl',
            'nvme.cmd.identify.ctrl.nvmeof.rsvd', 'nvme.cmd.identify.ctrl.vs')), self.SPAN)

        def row(frame, *names):
            return [t[frame][n] for n in names]

        assert list(column(t, 'nvme-mi')) == list(range(1, 61))
        # The partial Identify entries used to throw; nothing here may.
        assert column(t, '_ws.malformed') == {}
        # DLEN 8 selects LSLPLEN and NLSLNE only (NVM CS 1.2 Figure 109); the
        # surplus is flagged and kept as its own item.  F4 is the full window.
        lba = ('nvme.cmd.get_logpage.lba_status.lslplen',
               'nvme.cmd.get_logpage.lba_status.nlslne',
               'nvme.cmd.get_logpage.lba_status.estulb',
               'nvme.cmd.get_logpage.lba_status.lsgc',
               'nvme-mi.admin.data_excess', 'nvme-mi.admin.invalid_dlen')
        assert row(2, *lba)[:4] == ['64', '1', '', '']
        assert t[2]['nvme-mi.admin.invalid_dlen'] != ''
        assert row(4, *lba) == ['64', '1', '153', '0x0077', '', '']
        assert list(column(t, 'nvme-mi.admin.data_excess')) == [2]
        # F60: DOFST 24 / DLEN 40 answered with 16 bytes.  MN (63:24) is cut
        # and SN (23:4) is before the window.
        assert row(60, '_ws.expert.message', '_ws.expert.severity',
                   'nvme.cmd.identify.ctrl.mn', 'nvme.cmd.identify.ctrl.sn') == [
            ("NVMe Response Data is 16 bytes, fewer than the 40 bytes the"
             " request's Data Length selected"),
            '4194304', '', '']   # PI_NOTE
        assert list(column(t, 'nvme-mi.admin.short_response')) == [60]
        # Partial entries keep the fields inside the bytes present.
        assert row(6, 'nvme.cmd.identify.nvmset.num', 'nvme.cmd.identify.nvmset.id',
                   'nvme.cmd.identify.nvmset.endgid') == ['1', '0x0101', '0x0202']
        assert row(8, 'nvme.cmd.identify.scl.num', 'nvme.cmd.identify.scl.scid',
                   'nvme.cmd.identify.scl.pcid', 'nvme.cmd.identify.scl.nvi') == [
            '1', '0x0111', '0x0222', '1365']
        # DOFST 4 into 64-byte LBA Range Type entries: entries 1 and 2 whole.
        assert row(14, 'nvme.set_features.lbart.type', 'nvme.set_features.lbart.slba',
                   'nvme.set_features.lbart.nlb') == [
            '0x03,0x04', '0x0000000000002000,0x0000000000003000',
            '511,767']
        assert row(16, 'nvme.set_features.lbart.type', 'nvme.set_features.lbart.slba') == [
            '0x02,0x03,0x04', '0x0000000000001000,0x0000000000002000,0x0000000000003000']
        assert t[18]['nvme.set_features.lbart.apst'] == '0x0011223344556677,0x8899aabbccddeeff'
        # Get Log Page and Identify data is controller-to-host only; Set
        # Features request data (F23) is legitimate.
        assert row(19, 'nvme.cmd.get_logpage.smart.cw', 'nvme.cmd.get_logpage.smart.ct') == [
            '', '']
        assert row(21, 'nvme.cmd.identify.ctrl.vid', 'nvme.cmd.identify.ctrl.ssvid') == ['', '']
        assert row(23, 'nvme.set_features.lbart.type', 'nvme.set_features.lbart.slba') == [
            '0x02', '0x0000000000001000']
        assert list(column(t, 'nvme.data.wrong_direction')) == [19, 21]
        # SCT 1h / SC 0h (F26) and SC 6h (F30) fail: Dword 0 stays raw.  The
        # successful twins decode (NCQA/NSQA export the 0's based value).
        nq = ('nvme.cqe.dword0', 'nvme.cqe.dword0.set_features.ncqa',
              'nvme.cqe.dword0.set_features.nq.nsqa')
        pm = ('nvme.cqe.dword0', 'nvme.cqe.dword0.get_features.pm.ps',
              'nvme.cqe.dword0.get_features.pm.wh')
        assert row(26, *nq) == ['0x000f000f', '', '']
        assert row(28, *nq)[1:] == ['15', '15']
        assert row(30, *pm) == ['0x0000001f', '', '']
        assert row(32, *pm)[1:] == ['0x0000001f', '0x00000000']
        # The raw NUMD is the wire value; only its annotation could wrap.
        assert [t[n]['nvme.cmd.get_logpage.numd'] for n in (33, 35, 37)] == [
            '4294967295', '0', '4294967294']
        # The CQE Command Id is shown as sent.
        assert t[40]['nvme-mi.admin.cqe_dw3'] != ''
        assert t[40]['nvme-mi.admin.cqe_dw3.cid'] == '0x00001234'
        assert t[42]['nvme-mi.admin.cqe_dw3.cid'] == '0x00000000'
        # Reserved runs reach bit 31 (NVM CS 1.2 Figure 96, Base 2.3 Figure 468).
        assert row(43, 'nvme.cmd.set_features.dword11.erec.tler',
                   'nvme.cmd.set_features.dword11.erec.dulbe',
                   'nvme.cmd.set_features.dword11.erec.rsvd') == [
            '0x00001234', 'True', '0x00007fff']
        assert row(45, 'nvme.cmd.set_features.dword11.rsrvn.rsvd0',
                   'nvme.cmd.set_features.dword11.rsrvn.regpre',
                   'nvme.cmd.set_features.dword11.rsrvn.resrel',
                   'nvme.cmd.set_features.dword11.rsrvn.resrpe',
                   'nvme.cmd.set_features.dword11.rsrvn.rsvd1') == [
            '0x00000001', 'True', 'True', 'True', '0x0fffffff']
        # Identify Controller tail windows: a descriptor renders when whole.
        assert row(48, 'nvme.cmd.identify.ctrl.psds.psd.mp',
                   'nvme.cmd.identify.ctrl.psds.psd.enlat',
                   'nvme.cmd.identify.ctrl.psds.psd.exlat',
                   'nvme.cmd.identify.ctrl.psds.psd.mbws') == ['4097', '101', '201', '0x03']
        assert t[50]['nvme.cmd.identify.ctrl.psds.psd.mp'] == '4096'
        assert t[52]['nvme.cmd.identify.ctrl.psds.psd.mp'] == ','.join(
            str(4096 + i) for i in range(16))
        assert t[58]['nvme.cmd.identify.ctrl.psds.psd.mp'] == '4096,4097'
        assert list(column(t, 'nvme.cmd.identify.ctrl.psds.psd.mp')) == [48, 50, 52, 58]
        # F54 ends at 2048: the whole Fabric Specific block, no table.
        assert row(54, 'nvme.cmd.identify.ctrl.nvmeof.ioccsz',
                   'nvme.cmd.identify.ctrl.nvmeof.iorcsz',
                   'nvme.cmd.identify.ctrl.nvmeof.msdbd',
                   'nvme.cmd.identify.ctrl.nvmeof.ccrl',
                   'nvme.cmd.identify.ctrl.nvmeof.rsvd', 'nvme.cmd.identify.ctrl.psds') == [
            '4', '1', '16', '4', '00' * 240, '']
        # F58 holds only the block's Reserved tail, so no block field.
        assert row(58, 'nvme.cmd.identify.ctrl.nvmeof.rsvd',
                   'nvme.cmd.identify.ctrl.nvmeof.ccrl') == ['', '']
        assert t[56]['nvme.cmd.identify.ctrl.vs'] == '08090a0b0c0d0e0f1011121314151617'

    def test_extents_and_labels(self, dissect_pdml):
        p = pdml_section(dissect_pdml(self.FILE), self.SPAN)

        def extent(frame, name):
            f = p.field(frame, name)
            return f['pos'], f['size']

        def items(frame, name, *attrs):
            return [tuple(f.get(a) for a in attrs) for f in p.fields(frame, name)]

        assert p.field(2, 'nvme-mi.admin.data_excess')['size'] == '8'
        # LBA Range Type records: two whole 64-byte siblings named by their own
        # index; Type 4h is "Page or swap file" (NVM CS 1.2 Figure 95).
        assert items(14, 'nvme.set_features.lbart', 'size') == [('64',), ('64',)]
        records = p.fields(14, 'nvme.set_features.lbart')
        assert int(records[1].get('pos')) - int(records[0].get('pos')) == 64
        assert len(set(field_depths(p[14], 'nvme.set_features.lbart'))) == 1
        assert 'LBA Range Structure 1' in records[0].get('showname')
        assert 'LBA Range Structure 2' in records[1].get('showname')
        labels = [s for (s,) in items(16, 'nvme.set_features.lbart.type', 'showname')]
        assert len(labels) == 3
        for label, name in zip(labels, ('RAID', 'Cache', 'Page or swap file')):
            assert name in label, label
        assert items(18, 'nvme.set_features.lbart.apst', 'size') == [('8',), ('8',)]
        # NUMD is 0's based dwords; FFFFFFFFh is 16 GiB, not 0.
        for frame, size in ((33, '17179869184 bytes'), (35, '4 bytes'),
                            (37, '17179869180 bytes')):
            assert size in p.field(frame, 'nvme.cmd.get_logpage.numd')['showname']
        # Power State Descriptor table and block items fit the window.
        assert items(48, 'nvme.cmd.identify.ctrl.psds.psd', 'showname', 'pos', 'size') == [
            ('Power State 1 Descriptor (PSD1)', '40', '32')]
        assert extent(48, 'nvme.cmd.identify.ctrl.psds') == ('40', '32')
        assert items(50, 'nvme.cmd.identify.ctrl.psds.psd', 'showname') == [
            ('Power State 0 Descriptor (PSD0)',)]
        assert extent(50, 'nvme.cmd.identify.ctrl.psds') == ('40', '48')
        assert extent(52, 'nvme.cmd.identify.ctrl.psds') == ('40', '512')
        assert extent(54, 'nvme.cmd.identify.ctrl.nvmeof') == ('296', '256')
        assert extent(58, 'nvme.cmd.identify.ctrl.nvmeof') == ('40', '48')
        assert extent(58, 'nvme.cmd.identify.ctrl.psds') == ('88', '80')
        assert items(58, 'nvme.cmd.identify.ctrl.psds.psd', 'showname', 'pos') == [
            ('Power State 0 Descriptor (PSD0)', '88'),
            ('Power State 1 Descriptor (PSD1)', '120')]
        vs = p.field(56, 'nvme.cmd.identify.ctrl.vs')
        assert (vs['pos'], vs['size']) == ('40', '16')
        assert vs['showname'].endswith('(offset 8)'), vs['showname']


class TestNvmeMiStructureLayouts:
    """Controller lists, AE Occurrence layouts, VPD records and bounded strings."""

    FILE = 'nvme-mi-mi-commands.pcapng'
    SECTION = 4

    def test_controller_lists(self, dissect_pdml):
        pdml = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        p = pdml
        name = 'nvme.controller_list.count_invalid'
        assert {f: len(pdml.fields(packet, name)) for f, packet in p.packets.items()
                if pdml.fields(packet, name)} == {8: 1, 10: 1, 18: 1}
        assert pdml.values(p[2], 'nvme-mi.mi.ctrllist.ctrlid') == [1, 3]
        assert pdml.values(p[8], 'nvme-mi.mi.ctrllist.ctrlid') == list(range(1, 2049))
        assert pdml.values(p[18], 'nvme.cmd.identify.ctrl_list.id') == list(range(1, 2048))
        # More identifiers than a list holds: the list runs short.
        assert pdml.fields(p[10], 'nvme-mi.mi.truncated')
        assert pdml.fields(p[10], 'nvme-mi.mi.data')[-1].get('value') == 'a5'
        assert pdml.values(p[12], 'nvme-mi.mi.ctrllist.numids') == [0]
        assert pdml.fields(p[14], 'nvme-mi.mi.list_surplus')[0].get('value') == 'a55a'
        assert pdml.fields(p[24], 'nvme.data')[-1].get('value').endswith('a55a')
        # Descending, below-floor and nonzero-tail lists decode as sent.
        for frame in (4, 6, 16, 20, 22, 24, 26, 28, 30, 32):
            assert not pdml.fields(p[frame], '_ws.expert.message')
        for frame in (28, 30):
            assert not pdml.fields(p[frame], 'nvme.cmd.identify.ctrl_list.num')
            assert not pdml.fields(p[frame], 'nvme.cmd.identify.ctrl_list.id')
            assert pdml.fields(p[frame], 'nvme.data')[-1].get('value') == '0100a55a'

    @pytest.mark.parametrize('ae,scope,checks', [
        (0, 1, {'rv': 1}), (1, 1, {'cfsv': 1}),
        (2, 2, {'stv': 1, 'ssv': 2}), (3, 1, {'crime': 1, 'cev': 1}),
        (6, 2, {'ctv': 37}), (7, 2, {'puv': 50}), (8, 2, {'asv': 99}),
        (9, 2, {'cwv': 128}), (11, 4, {'plav': 1}),
        (12, 2, {'sfmv': 1}), (13, 0, {'snfmv': 1}),
        (14, 1, {'pmt': 12, 'pwrs': 2, 'pwrv': 0x1234, 'pwr_rsvd': 0}),
        (15, 1, {'pwril': 2, 'pwriv': 100, 'vsent': 3, 'vtht': 1, 'volv': 3300}),
    ])
    def test_ae_layout(self, dissect_pdml, ae, scope, checks):
        pdml = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        occurrences = pdml.fields(pdml[33], 'nvme-mi.mi.aeo.entry')
        entry, = [e for e in occurrences
                  if pdml.values(e, 'nvme-mi.mi.aeo.aeoi') == [ae]]
        assert pdml.values(entry, 'nvme-mi.mi.aeo.aess') == [scope]
        for suffix, value in checks.items():
            assert pdml.values(entry, 'nvme-mi.mi.aeosi.' + suffix) == [value]
        assert not pdml.fields(entry, '_ws.expert.message')

    def test_ae_raw_controls(self, dissect_pdml):
        pdml = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        for entry in pdml.fields(pdml[34], 'nvme-mi.mi.aeo.entry'):
            assert pdml.fields(entry, 'nvme-mi.mi.aeo.aeosi')[0].get('value') == 'a5'
            assert not any(n.get('name', '').startswith('nvme-mi.mi.aeosi.')
                           for n in entry.iter('field'))
        assert len(pdml.fields(pdml[34], 'nvme-mi.mi.response_data_length')) == 3
        assert len(pdml.fields(pdml[35], 'nvme-mi.mi.response_data_length')) == 1
        assert not pdml.fields(pdml[35], 'nvme-mi.mi.aeosi.pwrv')

    def test_vpd_records_and_nested_descriptors(self, dissect_pdml):
        pdml = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        p = pdml[37]
        for name, expected in (
                ('ipmiver', [1]), ('mrioff', [1]), ('rti', [11, 12, 238, 13]),
                ('version', [0, 1, 0]), ('pciepn', [7]), ('typ', [2, 4, 3, 5, 7, 238]),
                ('maxpwr', [25]), ('pointer', [2, 2]), ('merim', [5]),
                ('merwmto', [10]), ('mut', [15]), ('mtl', [10])):
            assert pdml.values(p, 'nvme-mi.mi.vpd.' + name) == expected
        assert pdml.fields(p, 'nvme-mi.mi.vpd.tnvmcap')[0].get('value') == (
            123456789).to_bytes(13, 'little').hex()
        assert pdml.fields(p, 'nvme-mi.mi.vpd.lstr')[0].get('show') == 'rack-€'
        assert sum(f.get('value') == 'e282'
                   for f in pdml.fields(p, 'nvme-mi.mi.vpd.raw')) == 2
        assert not pdml.fields(p, '_ws.expert.message')
        assert not pdml.fields(pdml[39], 'nvme-mi.mi.vpd.ipmiver')
        assert not pdml.fields(pdml[39], 'nvme-mi.mi.vpd.rti')
        assert len(pdml.fields(pdml[39], 'nvme-mi.mi.vpd.undecoded')) == 1

    def test_vpd_bounds_and_checksums(self, dissect_pdml):
        pdml = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        for name, frames in (('bad_checksum', [41, 43, 45]),
                             ('invalid_length', [47, 49, 51])):
            actual = {frame: len(pdml.fields(packet, 'nvme-mi.mi.vpd.' + name))
                      for frame, packet in pdml.packets.items()
                      if pdml.fields(packet, 'nvme-mi.mi.vpd.' + name)}
            assert actual == {frame: 1 for frame in frames}
        for frame in (57, 59, 61, 63):
            assert not pdml.fields(pdml[frame], 'nvme-mi.mi.vpd.lstr')
        assert pdml[61].find(".//proto[@name='_ws.short']") is not None
        assert not pdml.fields(pdml[61], 'nvme-mi.mi.truncated')
        assert not pdml.fields(pdml[59], 'nvme-mi.mi.truncated')
        assert pdml.fields(pdml[85], 'nvme-mi.mi.vpd.undecoded')
        assert not pdml.fields(pdml[85], 'nvme-mi.mi.vpd.ff')

    def test_bounded_strings_and_nqn(self, dissect_pdml):
        pdml = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        p = pdml
        assert pdml.fields(p[65], 'nvme.set_features.hmd.med.eval')[0].get('show') == ' ~€'
        for frame in (69, 71):
            assert not pdml.fields(p[frame], 'nvme.set_features.hmd.med.eval')
            assert pdml.fields(p[frame], 'nvme.data')
        nqn = 'nvme.cmd.identify.ctrl.subnqn'
        prefix = 'nqn.2026-01.com.example:'
        assert pdml.fields(p[73], nqn)[0].get('show') == prefix + '€😀'
        assert pdml.fields(p[75], nqn)[0].get('value').startswith(
            (prefix.encode() + b'\xe2\x82\0').hex())
        assert pdml.fields(p[77], nqn)[0].get('show') == prefix + 'ok'
        assert pdml.fields(p[77], 'nvme.data')[-1].get('value').startswith('ffc21f7f')
        assert not pdml.fields(p[81], nqn)
        assert len(pdml.fields(p[87], nqn)) == 1
        assert pdml.fields(p[83], 'nvme.cmd.get_logpage.identify.rcrd.subnqn')[0].get('show') == prefix + '€'
        assert pdml.fields(p[55], 'nvme-mi.mi.vpd.lstr')[0].get('show') == 'ok'
        assert pdml.fields(p[55], 'nvme-mi.mi.vpd.raw')[-1].get('value') == 'ffc21f7f'
        assert not pdml.fields(p[55], '_ws.expert.message')
        for frame, name, raw in (
                (97, 'nvme-mi.mi.vpd.lstr', b'rack-\x7f\0'),
                (99, 'nvme.set_features.hmd.med.eval', b'a\x1fb'),
                (101, nqn, (prefix.encode() + b'\x1f\x7f\0').ljust(256, b'\0'))):
            item, = pdml.fields(p[frame], name)
            assert item.get('value') == raw.hex()
            assert item.get('show')

    def test_partial_nqn_raw(self, dissect_pdml):
        pdml = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        for frame in (89, 91, 93, 95):
            packet = pdml[frame]
            assert not pdml.fields(packet, 'nvme.cmd.identify.ctrl.subnqn')
            assert not pdml.fields(packet, 'nvme.cmd.get_logpage.identify.rcrd.subnqn')
            raw, = [node for name in ('nvme.window.partial', 'nvme.data')
                    for node in pdml.fields(packet, name) if node.get('size') == '4']
            assert raw.get('value') == '1f7fe282'
            assert raw.get('hide') != 'yes'
            assert not pdml.fields(packet, '_ws.expert.message')
        assert pdml.fields(pdml[89], 'nvme.cmd.identify.ctrl.rsvd9')[0].get('size') == '180'
        assert pdml.fields(pdml[91], 'nvme.cmd.identify.ctrl.rsvd5')[0].get('size') == '768'

    def test_selected_window_order_independence(self, dissect_pdml):
        pdml = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        selected = pdml_section(dissect_pdml(
            self.FILE, two_pass=True,
            dfilter=to_capture(self.SPAN, 'frame.number in {26,28,30,32,37,39,81,89,91,93,95}')), self.SPAN)
        names = ('nvme.cmd.identify.ctrl_list.num', 'nvme.cmd.identify.ctrl_list.id',
                 'nvme-mi.mi.vpd.ipmiver', 'nvme-mi.mi.vpd.rti',
                 'nvme-mi.mi.vpd.lstr', 'nvme.cmd.identify.ctrl.subnqn',
                 'nvme.cmd.get_logpage.identify.rcrd.subnqn', 'nvme.data',
                 '_ws.expert.message')
        assert sorted(selected.packets) == [26, 28, 30, 32, 37, 39, 81, 89, 91, 93, 95]
        for frame, packet in selected.packets.items():
            for name in names:
                assert [(n.get('show'), n.get('value')) for n in pdml.fields(packet, name)] == [
                    (n.get('show'), n.get('value')) for n in pdml.fields(pdml[frame], name)]
        assert Counter(n.get('show') for n in pdml.fields(selected[26],
            'nvme.cmd.identify.ctrl_list.id')) == Counter(n.get('show') for n in
            pdml.fields(selected[32], 'nvme.cmd.identify.ctrl_list.id'))


class TestNvmeAdminFieldLayouts:
    """Log page, Admin command, Identify and Feature field layouts:
    nvme-mi-admin-logpage.pcapng F231-F349 (m6_final_vectors)."""

    FILE = 'nvme-mi-admin-logpage.pcapng'
    SECTION = 4

    def test_log_request_layouts(self, dissect_pdml):
        pdml = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        p = pdml
        prefix = 'nvme.cmd.get_logpage.lsp.'
        for frame, name, expected in (
                (1, 'cthid', 1), (1, 'mcda', 4), (2, 'pel_act', 3),
                (3, 'scope', 3), (3, 'contents', 2),
                (4, 'extdlpe', 1), (4, 'pleo', 1), (4, 'allsube', 1),
                (5, 'rgo', 1), (6, 'reserved', 0x7f)):
            assert pdml.values(p[frame], prefix + name) == [expected]
        assert not pdml.fields(p[6], prefix + 'rmc')
        lsi = pdml.fields(p[7], 'nvme.cmd.get_logpage.dword11.lsi')[0]
        assert int(lsi.get('show'), 0) == 0x1234
        assert 'LSI' in lsi.get('showname')
        assert 'Domain Identifier' in lsi.get('showname')
        assert 'Target Controller' in pdml.fields(p[8], 'nvme.cmd.get_logpage.dword11.lsi')[0].get('showname')
        # LOG-3: Base 2.4 Figures 220, 232 and 274.
        for frame, name, text in (
                (1, 'mcda', 'Data Area 1 through Data Area 4 (4)'),
                (2, 'pel_act', 'Establish Context and Read 512 Bytes of Header (0x3)'),
                (3, 'scope', 'NVMe-MI Command Set opcodes (0x3)'),
                (3, 'contents', 'Currently prohibited (out-of-band Management Endpoint) (0x2)')):
            assert pdml.label(p[frame], prefix + name) == text
        # LOG-5: LSI is reserved for LID 14h when ELPF is 0 (Base 2.4 Figure 275).
        whole = dissect_pdml(self.FILE)
        assert whole.values(23, 'nvme.cmd.get_logpage.lsp.elpf') == [0]
        assert whole.label(23, 'nvme.cmd.get_logpage.dword11.lsi').endswith(', Reserved')

    def test_capabilities_and_index_origins(self, dissect_pdml):
        pdml = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        p = pdml
        for name in ('mcdas', 'ecrh', 'extdlpes', 'pleos', 'allsubes', 'allhostes'):
            assert pdml.values(p[10], 'nvme.cmd.get_logpage.supported.' + name) == [1]
        assert pdml.values(p[12], 'nvme.cmd.get_logpage.ana.grp.id') == [0x11223344]
        assert pdml.values(p[16], 'nvme.cmd.get_logpage.reach.id') == [0x10203040]
        assert pdml.values(p[16], 'nvme.cmd.get_logpage.reach.rac') == [2]
        assert pdml.values(p[16], 'nvme.cmd.get_logpage.reach.member') == [0x33445566]
        nqn = 'nqn.2026-01.com.example:m6'
        assert pdml.fields(p[18], 'nvme.cmd.get_logpage.identify.rcrd.subnqn')[0].get('show') == nqn
        assert pdml.fields(p[20], 'nvme.cmd.get_logpage.hostdisc.hostnqn')[0].get('show') == nqn
        assert pdml.values(p[20], 'nvme.cmd.get_logpage.hostdisc.tel') == [1056]
        for frame in (14, 22):
            assert pdml.shows(p[frame], 'nvme.window_decode_skipped') == [SKIP_RAW]
            assert not any(SKIP_RAW in n.get('show')
                           for n in pdml.fields(p[frame], '_ws.expert.message'))
            assert pdml.fields(p[frame], 'nvme.data')[-1].get('value') == 'a55a1234'
            assert not pdml.fields(p[frame], 'nvme.cmd.get_logpage.ana.grp.id')

    def test_discovery_index_zero_boundaries(self, dissect_pdml):
        pdml = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        p = pdml
        record = 'nvme.cmd.get_logpage.identify.rcrd'
        assert not pdml.fields(p[109], record)
        assert not pdml.fields(p[109], record + '.trtype')
        assert not pdml.fields(p[109], record + '.tel')
        assert pdml.fields(p[109], 'nvme.data')[-1].get('value') == '20040000'
        assert pdml.shows(p[109], 'nvme.window_decode_skipped') == [SKIP_RAW]
        assert not any(SKIP_RAW in n.get('show')
                       for n in pdml.fields(p[109], '_ws.expert.message'))

        # The same page with its header and TELs proves both entry boundaries.
        entries = pdml.fields(p[111], record)
        origin = int(pdml.fields(p[111], 'nvme-mi.admin.data')[0].get('pos'))
        assert [(int(f.get('pos')) - origin, int(f.get('size'))) for f in entries] == [
            (1024, 1056), (2080, 1056)]
        assert pdml.values(p[111], record + '.trtype') == [3, 1]
        assert pdml.values(p[111], record + '.portid') == [0x1111, 0x2222]
        assert pdml.values(p[111], record + '.tel') == [1056, 1056]
        assert not pdml.fields(p[111], 'nvme.window_decode_skipped')

        # Without the header, the request's EXTDLPE (Figure 309) still says
        # Entry 0 may be extended, so its TEL is read and gives its end.
        entry, = pdml.fields(p[113], record)
        assert entry.get('size') == '1028'
        assert pdml.values(p[113], record + '.trtype') == [3]
        assert pdml.values(p[113], record + '.tel') == [1056]
        assert not pdml.fields(p[113], 'nvme.window_decode_skipped')

    def test_admin_field_families(self, dissect_pdml):
        pdml = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        p = pdml
        for frame, name, expected, size in (
                (23, 'ns_mgmt.csi', 2, 4),
                (24, 'virt_mgmt.cntlid', 0x1234, 4),
                (24, 'virt_mgmt.rt', 1, 4),
                (24, 'virt_mgmt.nr', 0x5678, 4),
                (25, 'cap_mgmt.capacity', 0x1122334455667788, 8),
                (26, 'export.ra', 1, 4),
                (27, 'get_lba_status.slba', 0x1122334455667788, 8),
                (27, 'get_lba_status.atype', 0x10, 4),
                (28, 'sanitize_ns.act', 4, 4),
                (28, 'sanitize_ns.emvs', 1, 4)):
            item, = pdml.fields(p[frame], 'nvme.cmd.' + name)
            assert pdml.values(p[frame], 'nvme.cmd.' + name) == [expected]
            assert int(item.get('size')) == size
        assert not pdml.fields(p[29], 'nvme.cmd.export.ra')
        assert not pdml.fields(p[29], 'nvme.cmd.export.subsys_sel')

    def test_identify_fixed_fields_and_raw_controls(self, dissect_pdml):
        pdml = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        p = pdml
        for frame, name, expected in (
                (31, 'nvm_ns.lbstm', 0x0102030405060708),
                (31, 'nvm_ns.sts', 0x12),
                (31, 'nvm_ns.pif', 3),
                (31, 'nvm_ns.qpif', 1),
                (33, 'nvm_ctrl.dmrsl', 0x12345678),
                (33, 'nvm_ctrl.dmsl', 0x0102030405060708),
                (39, 'domain.id', 0x1234),
                (45, 'underlying.nsid', 0x12345678),
                (45, 'underlying.idx', 0),
                (47, 'underlying.pidup', 0x5678)):
            assert pdml.values(p[frame], 'nvme.cmd.identify.' + name) == [expected]
        assert not pdml.fields(p[33], 'nvme.cmd.identify.nvm_ctrl.vsl')
        assert pdml.values(p[37], 'nvme.cmd.identify.nslist.nsid') == [1, 3]
        assert pdml.values(p[41], 'nvme.cmd.identify.eg.id') == [1, 4, 0x1234]
        assert pdml.values(p[43], 'nvme.cmd.identify.iocsc') == [5, 0]
        assert pdml.values(p[49], 'nvme.cmd.identify.state.version') == [1, 2]
        assert pdml.fields(p[49], 'nvme.cmd.identify.state.uuid')[0].get('value') == bytes(range(16)).hex()
        assert pdml.fields(p[39], 'nvme.cmd.identify.domain.tdc')[0].get('value') == (
            0x010203040506070809).to_bytes(16, 'little').hex()
        assert not pdml.fields(p[35], 'nvme.cmd.identify.nvm_ctrl.vsl')
        assert pdml.fields(p[35], 'nvme.data')[-1].get('value') == 'a55a1234' * 4
        assert not pdml.fields(p[51], 'nvme.cmd.identify.state.uuid')
        assert pdml.fields(p[51], 'nvme.data')[-1].get('value') == 'a55a1234'

    def test_identify_cns09_windows(self, dissect_pdml):
        pdml = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        p = pdml
        prefix = 'nvme.cmd.identify.ns.'
        origin = int(pdml.fields(p[115], 'nvme.data')[-1].get('pos'))
        for name, expected, offset in (
                ('nsfeat', 0, 0), ('nlbaf', 3, 1), ('flbas', 0, 2), ('mc', 3, 3)):
            item, = pdml.fields(p[115], prefix + name)
            assert pdml.values(p[115], prefix + name) == [expected]
            assert int(item.get('pos')) - origin == offset
            assert item.get('size') == '1'
        for frame in (115, 117, 119):
            for name in ('nsze', 'ncap', 'nuse'):
                assert not pdml.fields(p[frame], prefix + name)
        for frame in (115, 117):
            for name in ('lbafs', 'lbaf'):
                assert not pdml.fields(p[frame], prefix + name)
        # A trailing half of NUSE remains raw; a complete LBAF slot decodes
        # with its index even without NLBAF/NULBAF in the window.
        assert pdml.fields(p[117], 'nvme.data')[-1].get('value') == '00000000'
        assert pdml.values(p[119], prefix + 'lbaf') == [0x00091000]
        assert 'LBAF0: LBADS 9, MS 4096' in pdml.shownames(p[119], prefix + 'lbaf')[0]
        for frame in (117, 119):
            assert not pdml.fields(p[frame], prefix + 'nlbaf')
            assert not pdml.fields(p[frame], prefix + 'mc')

    def test_feature_command_and_completion_families(self, dissect_pdml):
        pdml = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        p = pdml
        for frame, name, expected in (
                (54, 'metadata.gdhm', 1),
                (56, 'cdq.hp', 0x12345678),
                (56, 'cdq.tpt', 0x55667788),
                (59, 'cdq.id', 0x1234),
                (59, 'cdq.etpt', 1),
                (60, 'power.ptv', 0x1234),
                (63, 'power.pmts', 3),
                (64, 'measurement.act', 1),
                (67, 'measurement.smtr', 0x1234),
                (67, 'measurement.pmgn', 0x56),
                (67, 'measurement.pme', 1),
                (68, 'fdp.fdpcidx', 0x56),
                (71, 'fdp.fdpe', 1),
                (77, 'hmb.hsize', 0x1234),
                (77, 'hmb.hmnare', 1),
                (77, 'hmb.hmnar', 1),
                (78, 'cdp.chps', 1),
                (81, 'cdp.ppsc', 1),
                (81, 'cdp.pmdss', 1),
                (84, 'power.pls', 2),
                (87, 'power.plv', 0x1234)):
            assert pdml.values(p[frame], 'nvme.features.' + name) == [expected]
        assert not pdml.fields(p[81], 'nvme.features.cdp.chps')
        assert not pdml.fields(p[99], 'nvme.features.power.ept')
        assert not pdml.fields(p[101], 'nvme.features.power.ept')
        for frame in (57, 69, 73):
            assert not pdml.fields(p[frame], 'nvme.cqe.dword0')

    def test_feature_data_and_unknown_controls(self, dissect_pdml):
        pdml = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        p = pdml
        assert pdml.values(p[72], 'nvme.features.fdpe.type') == [1, 2]
        assert pdml.values(p[75], 'nvme.features.fdpe.type') == [1, 2]
        assert pdml.values(p[75], 'nvme.features.fdpe.enabled') == [1, 0]
        assert pdml.values(p[81], 'nvme.features.cdp.security_status') == [2]
        assert pdml.values(p[81], 'nvme.features.cdp.security_supported') == [6]
        assert pdml.fields(p[89], 'nvme.features.nsal')[0].get('show') == 'rack-€'
        assert pdml.fields(p[93], 'nvme.features.emca')[0].get('show') == 'https://bmc.example/'
        assert pdml.fields(p[95], 'nvme.features.hostid')[0].get('value') == bytes(range(16)).hex()
        assert pdml.values(p[97], 'nvme.features.perf.r4karl') == [0x12]
        for frame, absent, raw in (
                (83, 'cdp.security_status', 'a55a1234'),
                (91, 'nsal', 'e2820000'),
                (103, 'power.plv', 'a55a1234')):
            assert not pdml.fields(p[frame], 'nvme.features.' + absent)
            assert pdml.fields(p[frame], 'nvme.data')[-1].get('value') == raw

    def test_siis_revision_values(self, dissect_pdml):
        pdml = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        name = 'tcg-storage.l0.feat.siis.revision'
        for frame, raw, text in ((105, 0x20, 'SIIS v1.20 r1.00'),
                                 (107, 0x0c, 'Reserved')):
            field, = pdml.fields(pdml[frame], name)
            assert int(field.get('show'), 0) == raw
            assert field.get('size') == '1'
            assert text in field.get('showname')

    def test_selected_index_window_parity(self, dissect_pdml):
        pdml = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        frames = (18, 109, 111, 113, 115, 117, 119)
        selected = pdml_section(dissect_pdml(
            self.FILE, two_pass=True, dfilter='frame.number in {' + ', '.join(
                str(frame_in(self.SPAN, n)) for n in frames) + '}'), self.SPAN)
        assert set(selected.packets) == set(frames)
        for frame, packet in selected.packets.items():
            for name in (
                    'nvme.cmd.get_logpage.identify.rcrd',
                    'nvme.cmd.get_logpage.identify.rcrd.subnqn',
                    'nvme.cmd.get_logpage.identify.rcrd.trtype',
                    'nvme.cmd.get_logpage.identify.rcrd.tel',
                    'nvme.window_decode_skipped',
                    'nvme.cmd.identify.ns.nlbaf', 'nvme.cmd.identify.ns.mc',
                    'nvme.cmd.identify.ns.nuse', 'nvme.cmd.identify.ns.lbaf', 'nvme.data'):
                assert [(n.get('show'), n.get('value'), n.get('size')) for n in pdml.fields(packet, name)] == [
                    (n.get('show'), n.get('value'), n.get('size')) for n in pdml.fields(pdml[frame], name)]


def list_invalid(present, num, name, total, header_and_entries, data):
    """The AE / AE Occurrence list check's message."""
    return (f'{present} of {num} {name} entries present; Total Length {total},'
            f' header plus entries {header_and_entries}, list data {data} bytes')


def expert_frames(table, text):
    """Frames whose expert messages contain `text`."""
    return [n for n, row in table.items() if text in row['_ws.expert.message']]


def note_frames(table, text):
    """Frames whose window note (not an expert info) contains `text`."""
    return [n for n, row in table.items() if text in row['nvme.window_decode_skipped']]


SKIP_ANA_COUNT = 'Descriptor count not captured'
SKIP_RAW = 'Structure-specific decode skipped; the bytes are shown raw'


def field_depths(packet, name):
    """The number of enclosing <field> elements of each `name` field:
    siblings share a depth, nested repeats increase it."""
    out = []

    def walk(node, depth):
        for child in node:
            is_field = child.tag == 'field'
            if is_field and child.get('name') == name:
                out.append(depth)
            walk(child, depth + 1 if is_field else depth)
    walk(packet, 0)
    return out


#: The NVMe-MI side is build_shared_decode_pcapng's section, F482-F743.
SHARED_MI = 'nvme-mi-mi-commands.pcapng'
SHARED_MI_SPAN = (482, 743)
#: The native twins are build_shared_decode_native's section, F26-F76.
SHARED_NATIVE = 'nvme-tcp-admin.pcapng'
SHARED_NATIVE_SPAN = (26, 76)


def native_twins(dissect_pdml, two_pass):
    """The native twin frames, keyed from 1 as in build_shared_decode_native."""
    first, last = SHARED_NATIVE_SPAN
    return {n - first + 1: p for n, p in dissect_pdml(SHARED_NATIVE, two_pass=two_pass)
            .packets.items() if first <= n <= last}
#: SECP 00h lengths past the body: a window note, not an expert info.
SHARED_WINDOW_NOTES = [24, 26, 28, 36, 38, 40, 46]
SHARED_EXPERTS = {
    'nvme-mi.admin.invalid_dofst': [55, 65, 79, 255, 259],
    # F77's NUMD asks for 12 bytes; F205's Performance Characteristics Set
    # (ATTRI 00h) carries a 4096-byte attribute (NVM CS 1.3 Figures 102/103).
    # F91/F257/F261 windows pass the Feature's size; F101/F181 Sets are not
    # its size (Base 2.4 Figure 466, NVM CS 1.3 4.1.3.2). F95's Get Features
    # SEL 011b returns no Response Data (Base 2.4 Figure 201).
    'nvme-mi.admin.invalid_dlen': [53, 57, 61, 63, 71, 75, 77, 85, 91, 95,
                                   101, 181, 205, 257, 261],
    'nvme-mi.admin.unexpected_request_data': [57, 67],
    'nvme.data.wrong_direction': [67],
    'nvme-mi.admin.prohibited_opcode': [233, 235, 237],
    'nvme-mi.admin.prohibited_fid': list(range(97, 198, 4)),
    'nvme-mi.admin.prohibited_lid': [211, 213],
    'nvme-mi.admin.reserved_opcode': [239, 241, 243],
    # 16-byte stubs answering acceptable Response-Data windows and the two
    # SECP 00h length-conflict bodies that are short by design (DLEN 16 / 12
    # carrying 12 / 8). F72's Identify window exceeds 4096, so its short
    # response is suppressed along with the invalid-window diagnosis.
    'nvme-mi.admin.short_response': [24, 36, 60, 68, 70, 90, 104, 136, 148,
                                     160, 176, 184, 210, 212, 214, 216, 218,
                                     230, 232],
}
#: Every Get Log Page request: the ten common cases, the log windows and
#: LIDs 1Dh-20h/C0h.
SHARED_GLP_REQUESTS = [1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 59, 61, 63, 65, 67,
                       209, 211, 213, 215, 217]


class TestNvmeMiPresentation:
    """Field registration, labels, protocol extents and special EIDs."""

    FILE = 'nvme-mi-admin-logpage.pcapng'
    SECTION = 7

    def test_mi_range_values(self, range_strings):
        """MI 2.2 Figures 77, 86, 117 and 118: complete contextual ranges."""
        sfreq = [(1, 1, '100 kHz'), (2, 2, '400 kHz'), (3, 3, '1 MHz'),
                 (4, 15, 'Reserved')]
        widths = [
            (1, 1, 'PCIe x1'), (2, 2, 'PCIe x2'), (3, 3, 'Reserved'),
            (4, 4, 'PCIe x4'), (5, 7, 'Reserved'), (8, 8, 'PCIe x8'),
            (9, 11, 'Reserved'), (12, 12, 'PCIe x12'), (13, 15, 'Reserved'),
            (16, 16, 'PCIe x16'), (17, 31, 'Reserved'), (32, 32, 'PCIe x32'),
            (33, 255, 'Reserved'),
        ]
        expected = {
            'config.sfreq': [(0, 0, 'Reserved')] + sfreq,
            'config.sfreq_cur': [(0, 0, 'Obsolete')] + sfreq,
            'port.prttyp': [(0, 0, 'Inactive'), (1, 1, 'PCIe'),
                            (2, 2, '2-Wire'), (3, 255, 'Reserved')],
            'port.pcie.mps': [
                (0, 0, '128 bytes'), (1, 1, '256 bytes'), (2, 2, '512 bytes'),
                (3, 3, '1 KiB'), (4, 4, '2 KiB'), (5, 5, '4 KiB'),
                (6, 255, 'Reserved'),
            ],
            'port.pcie.cls': [
                (0, 0, 'Link not active'), (1, 1, '2.5 GT/s'),
                (2, 2, '5.0 GT/s'), (3, 3, '8.0 GT/s'), (4, 4, '16.0 GT/s'),
                (5, 5, '32.0 GT/s'), (6, 6, '64.0 GT/s'),
                (7, 255, 'Reserved'),
            ],
            'port.pcie.mlw': [(0, 0, 'Reserved')] + widths,
            'port.pcie.nlw': [(0, 0, 'Link not active')] + widths,
        }
        for suffix, ranges in expected.items():
            name = f'nvme-mi.mi.{suffix}'
            assert range_strings.get(name) == ranges, name

    def test_protocol_extents_and_header_subtrees(self, dissect_pdml):
        pdml = pdml_section(dissect_pdml(self.FILE, two_pass=True), self.SPAN)
        for frame in (4, 6, 11):
            packet = pdml[frame]
            mctp = packet.findall(".//proto[@name='mctp']")
            assert len(mctp) == 1
            assert int(mctp[0].get('size')) == int(pdml_field(packet, 'frame.cap_len').get('show')) - 16
            name = 'mctpc' if frame == 11 else 'nvme-mi'
            protocols = packet.findall(f".//proto[@name='{name}']")
            assert len(protocols) == 1
            header_name = 'MCTP Control Protocol header' if frame == 11 else 'NVMe-MI header'
            headers = protocols[0].findall(f".//field[@show='{header_name}']")
            assert len(headers) == 1
            assert int(headers[0].get('size')) == (2 if frame == 11 else 4)

    def test_field_values(self, fields_table):
        t = section(fields_table(self.FILE, (
            'nvme.cmd.get_logpage.sanitize.sprog',
            'nvme-mi.response_to', 'nvme-mi.response_time', 'mctp.dst', 'mctp.src', '_ws.expert',
            '_ws.col.Info')), self.SPAN)
        # The Sanitize Status pages say Never Started, so SPROG is FFFFh
        # (Base 2.3 Figure 302).
        assert {n: v for n, v in column(t, 'nvme.cmd.get_logpage.sanitize.sprog').items()} == {
            4: '0xffff', 6: '0xffff'}
        # Response time runs from request EOM to response SOM.
        assert [(t[n]['nvme-mi.response_to'], t[n]['nvme-mi.response_time']) for n in (4, 6)] == [
            ('2', '1.000000000'), ('5', '1.000000000')]
        # Special EIDs stay numeric and draw no expert.
        assert [n for n, r in t.items() if (r['mctp.dst'], r['mctp.src']) == ('0', '7')] == [12]
        assert [n for n in column(t, '_ws.expert') if n in (11, 12, 13)] == []
        assert 'Reserved command 0x15' in t[11]['_ws.col.Info']

    def test_representative_labels(self, dissect_pdml):
        pdml = pdml_section(dissect_pdml(self.FILE, two_pass=True), self.SPAN)
        assert 'Directive Specific' in pdml_field(pdml[10], 'nvme.cqe.status.sc').get('showname')
        assert pdml_field(pdml[11], 'mctpc.command').get('showname') == 'Command: Reserved (0x15)'
        assert 'Reserved' in pdml_field(pdml[14], 'nvme-mi.mi.rds.dtyp').get('showname')
        assert pdml_field(pdml[15], 'nvme-mi.mi.status').get('showname') == 'Status: Reserved (0x09)'
        payload = pdml_field(pdml[7], 'tcg-storage.data')
        assert payload.get('showname') == 'Discarded/Ignored payload'
        assert payload.get('value') == '01020304'

    def test_special_eids_remain_numeric(self, dissect_pdml):
        pdml = pdml_section(dissect_pdml(self.FILE, two_pass=True), self.SPAN)
        assert pdml_field(pdml[12], 'mctp.dst').get('showname') == 'Destination: Null Destination EID (0)'
        assert pdml_field(pdml[12], 'mctp.src').get('showname') == 'Source: Reserved (7)'
        assert pdml_field(pdml[13], 'mctp.dst').get('showname') == 'Destination: Broadcast EID (255)'
        assert pdml_field(pdml[13], 'mctp.src').get('showname') == 'Source: 8'


class TestNvmeMiAdminSharedDecode:
    """Admin policy, windows and SECP 00h lengths, against NVMe/TCP twins."""

    def test_exact_census(self, dissect_pdml):
        tree = pdml_section(dissect_pdml(SHARED_MI), SHARED_MI_SPAN).packets
        assert len(tree) == 262
        counts = Counter(frame for frames in SHARED_EXPERTS.values() for frame in frames)
        for frame, packet in tree.items():
            found = packet.findall(".//field[@name='_ws.expert.message']")
            assert len(found) == counts[frame], (frame, [f.attrib for f in found])
        for name, frames in SHARED_EXPERTS.items():
            actual = [frame for frame, packet in tree.items()
                      if packet.find(f".//field[@name='{name}']") is not None]
            assert actual == frames, name
        assert [frame for frame, packet in tree.items()
                if packet.find(".//field[@name='nvme.window_decode_skipped']") is not None
                ] == SHARED_WINDOW_NOTES
        assert [frame for frame, packet in tree.items()
                if packet.find(".//field[@name='nvme-mi.mic_unverified']") is not None] == [32, 44]
        selected = pdml_section(dissect_pdml(SHARED_MI, dfilter=to_capture(
            SHARED_MI_SPAN, 'frame.number in {4, 19, 24, 32, 53, 79, 97, 199, 211,'
                            ' 239, 245, 249, 252, 254, 255, 257, 259, 261}')), SHARED_MI_SPAN).packets
        assert sorted(selected) == [4, 19, 24, 32, 53, 79, 97, 199, 211, 239, 245, 249, 252,
                                    254, 255, 257, 259, 261]
        for frame, packet in selected.items():
            assert [n.get('show') for n in packet.findall(
                ".//field[@name='_ws.expert.message']")] == [
                    n.get('show') for n in tree[frame].findall(
                        ".//field[@name='_ws.expert.message']")]

    def test_get_features_reserved_runs(self, assert_frames_match):
        """Error Recovery and Reservation Notification Mask completions show Reserved."""
        assert_frames_match(SHARED_MI, at(SHARED_MI_SPAN, [
            (108, 'nvme.cqe.dword0.get_features.erec.rsvd == 0'),
            (188, 'nvme.cqe.dword0.get_features.rsrvn.rsvd1 == 0'),
        ]))

    def test_telemetry_da_ranges(self, range_strings):
        assert range_strings['nvme.cmd.get_logpage.telemetry.da'] == [
            (0, 0, 'Not updated since last read with RAE=0 (<=2.3: header only, no saved state)'),
            (1, 1, 'Updated since last read with RAE=0 (<=2.3: saved internal state available)'),
            (2, 255, 'Reserved'),
        ]

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_raw_values_extents_generated_and_native_twins(self, dissect_pdml, two_pass):
        mi = pdml_section(dissect_pdml(SHARED_MI, two_pass=two_pass), SHARED_MI_SPAN).packets
        native = native_twins(dissect_pdml, two_pass)
        assert len(native) == 51
        for frame, name, value, offset, length in (
                (4, 'nvme.cmd.get_logpage.selftest.rsvd', 0xa55a, 2, 2),
                (6, 'nvme.cmd.get_logpage.selftest.res.vdi.rsvd', 10, 6, 1),
                (10, 'nvme.cmd.get_logpage.egroup.cw.rsvd1', 11, 0, 1),
                (12, 'nvme.cmd.get_logpage.telemetry.da', 0, 2, 1),
                (14, 'nvme.cmd.get_logpage.telemetry.da', 1, 2, 1),
                (16, 'nvme.cmd.get_logpage.telemetry.da', 2, 2, 1),
                (18, 'nvme.cmd.get_logpage.telemetry.da', 255, 2, 1)):
            a, b = pdml_field(mi[frame], name), pdml_field(native[frame+1], name)
            assert int(a.get('show'), 0) == value
            assert (int(a.get('pos')), int(a.get('size'))) == (40+offset, length)
            assert (int(b.get('pos')), int(b.get('size'))) == (78+offset, length)
            assert a.get('showname') == b.get('showname')
        for frame in range(1, 21, 2):
            wire = pdml_field(mi[frame], 'nvme.cmd.get_logpage.dword10.rae')
            assert wire.get('show') == ('True' if frame == 19 else 'False')

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_policy_twins_and_expert_anchors(self, dissect_pdml, two_pass):
        tree = pdml_section(dissect_pdml(SHARED_MI, two_pass=two_pass), SHARED_MI_SPAN).packets
        # The 26 Set-only prohibited FIDs: each Set is flagged on its opcode
        # (F101/F181 also carry invalid_dlen); their Gets decode silently.
        for frame in range(97, 198, 4):
            opc = pdml_field(tree[frame], 'nvme-mi.admin.opcode')
            assert opc.find(".//field[@name='nvme-mi.admin.prohibited_fid']") is not None, frame
        for frame in range(99, 198, 4):
            assert not tree[frame].findall(".//field[@name='_ws.expert.message']"), frame
        # Optional Storage / prohibited Enclosure is not a blanket prohibition.
        for frame in [201, 203, 207] + list(range(219, 232, 2)) + [245, 247]:
            assert not tree[frame].findall(".//field[@name='_ws.expert.message']"), frame
        for frame, name, position, extent in (
                (75, 'nvme-mi.admin.dlen', 52, 4),
                (233, 'nvme-mi.admin.opcode', 24, 1),
                (239, 'nvme-mi.admin.opcode', 24, 1)):
            node = pdml_field(tree[frame], name)
            assert (int(node.get('pos')), int(node.get('size'))) == (position, extent)
            assert len(node.findall(".//field[@name='_ws.expert.message']")) == 1
        assert pdml_field(tree[233], '_ws.expert.message').get('show') == (
            'Admin opcode is prohibited for both NVMe Storage Devices and'
            " NVMe Enclosures (NVMe-MI 'List of NVMe Admin Commands Supported"
            " using the Out-of-Band Mechanism')")
        assert pdml_field(tree[239], '_ws.expert.message').get('show') == (
            "Reserved or unlisted Admin opcode (NVMe Base 'Opcodes for Admin Commands';"
            " NVMe-MI 'List of NVMe Admin Commands Supported using the Out-of-Band"
            " Mechanism')")
        assert pdml_field(tree[75], '_ws.expert.message').get('show') == (
            'Data Length 8 must equal the 4-byte NVMe Request Data field')
        for frame in (75, 233, 239):
            assert int(pdml_field(tree[frame], '_ws.expert.severity').get('show'), 0) == 0x600000
            assert int(pdml_field(tree[frame], '_ws.expert.group').get('show'), 0) == 0x9000000
        for frame in (211, 213):
            assert pdml_field(pdml_field(tree[frame], 'nvme-mi.admin.opcode'),
                         '_ws.expert.message').get('show') == (
                'Log page is prohibited on NVMe-MI Management Endpoints'
                " (NVMe-MI 'Management Endpoint - Log Page Support')"), frame
        # Response-window offsets never relocate Request Data.
        assert pdml_field(tree[87], 'nvme.set_features.tst.ms') is not None
        assert not tree[67].findall(".//field[@name='nvme.cmd.get_logpage.smart']")

    def test_feature_personality_and_fixed_buffer_contracts(self, dissect_pdml):
        tree = pdml_section(dissect_pdml(SHARED_MI, two_pass=True), SHARED_MI_SPAN).packets
        # PERID00 has no data; PERID01 has Response Data. Preserve the wire
        # selectors, windows and response correlation, including bad windows.
        for frame, fid, perid, offset, length in (
                (249, 0x22, 0, 0, 0), (251, 0x22, 1, 0, 8),
                (253, 0x1f, 0, 252, 4), (255, 0x1f, 0, 256, 4),
                (257, 0x13, 0, 508, 8), (259, 0x16, 0, 512, 4),
                (261, 0x21, 0, 508, 8)):
            request, response = tree[frame], tree[frame+1]
            for name, value in (
                    ('nvme.cmd.get_features.dword10.fid', fid),
                    ('nvme.cmd.get_features.dword10.sel', 0),
                    ('nvme.cmd.dword13', perid),
                    ('nvme-mi.admin.doff', offset),
                    ('nvme-mi.admin.dlen', length)):
                assert int(pdml_field(request, name).get('show'), 0) == value
            assert int(pdml_field(response, 'nvme-mi.response_to').get('show')) == frame_in(
                SHARED_MI_SPAN, frame)
            assert int(pdml_field(response, 'nvme-mi.admin.opcode').get('show'), 0) == 10
            assert int(pdml_field(request, 'nvme-mi.response_in').get('show')) == frame_in(
                SHARED_MI_SPAN, frame + 1)
        # Windows are checked against each Feature's size.
        for frame in (249, 250, 251, 252, 253, 254, 256, 258, 260, 262):
            assert not tree[frame].findall(".//field[@name='_ws.expert.message']"), frame
        get = 'Get Features FID and SEL completion data'
        for frame, message in (
                (255, f'Data Offset 256 is outside the 256-byte {get}'),
                (257, f'Data Offset 508 plus Data Length 8 exceeds the 512-byte {get}'),
                (259, f'Data Offset 512 is outside the 512-byte {get}'),
                (261, f'Data Offset 508 plus Data Length 8 exceeds the 512-byte {get}')):
            assert [n.get('show') for n in tree[frame].findall(
                ".//field[@name='_ws.expert.message']")] == [message], frame
        for frame, size in ((252, 8), (254, 4)):
            data = pdml_field(tree[frame], 'nvme.data')
            assert (int(data.get('pos')), int(data.get('size'))) == (40, size)
            assert data.get('value') == '00' * size
            assert data.get('hide') != 'yes'
        # The decoder recognizes PERID01's two dwords; the partial label stays raw.
        assert pdml_field(tree[252], 'nvme.features.cdp.security_status') is not None
        assert pdml_field(tree[252], 'nvme.features.cdp.security_supported') is not None

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_security_lengths_residue_capture_and_native_parity(self, dissect_pdml, two_pass):
        mi = pdml_section(dissect_pdml(SHARED_MI, two_pass=two_pass), SHARED_MI_SPAN).packets
        native = native_twins(dissect_pdml, two_pass)
        skipped = [f+1 for f in SHARED_WINDOW_NOTES]
        for name, expected in (('nvme.security.invalid_length', []),
                               ('nvme.window_decode_skipped', skipped)):
            assert [frame for frame, p in native.items()
                    if p.find(f".//field[@name='{name}']") is not None] == expected
        # A declared length past the body: the bytes present are decoded and
        # the length carries one note.
        for frame, length_field, header in (
                (24, 'list_len', 8), (36, 'cert_len', 4),
                (26, 'list_len', 8), (28, 'list_len', 8),
                (38, 'cert_len', 4), (40, 'cert_len', 4)):
            node = pdml_field(mi[frame], 'nvme.security.info.' + length_field)
            assert node.get('show') == '8'  # never silently rewritten as 4
            assert (int(node.get('pos')), int(node.get('size'))) == (40+header-2, 2)
            assert len(node.findall(".//field[@name='nvme.window_decode_skipped']")) == 1
            assert not node.findall(".//field[@name='_ws.expert.message']")
            assert not mi[frame].findall(".//field[@name='nvme.cmd.security.data']")
            if length_field == 'list_len':
                assert len(mi[frame].findall(
                    ".//field[@name='nvme.security.info.protocol']")) == 4
            else:
                assert pdml_field(mi[frame], 'nvme.security.info.cert_data').get(
                    'value') == '000102ee'
        for frame, offset in ((30, 10), (42, 6)):
            node = pdml_field(mi[frame], 'nvme.security.info.residue')
            assert (int(node.get('pos')), int(node.get('size'))) == (40+offset, 2)
            assert node.get('value') == '02ee'
            assert not node.findall(".//field[@name='_ws.expert.message']")
        for frame in (32, 44):
            assert int(pdml_field(mi[frame], 'frame.cap_len').get('show')) < int(
                pdml_field(mi[frame], 'frame.len').get('show'))
            assert mi[frame].find(".//proto[@name='_ws.short']") is not None
        for tree in (mi, native):
            assert not any(p.findall(".//proto[@name='tcg-storage']") for p in tree.values())
        for frame in (22, 34):
            assert not mi[frame].findall(".//field[@name='_ws.expert.message']")
        leaves = {'nvme.security.info.list_len', 'nvme.security.info.protocol',
                  'nvme.security.info.cert_len', 'nvme.security.info.cert_data',
                  'nvme.security.info.residue', 'nvme.cmd.security.data'}
        for frame in range(22, 51, 2):
            a = [(n.get('name'), n.get('show'), n.get('size'), n.get('value'))
                 for n in mi[frame].iter('field') if n.get('name') in leaves]
            b = [(n.get('name'), n.get('show'), n.get('size'), n.get('value'))
                 for n in native[frame+1].iter('field') if n.get('name') in leaves]
            assert a == b, frame
        for frame in (24, 36):
            # One Note, on the MI layer's Data item -- 12 / 8 bytes carried
            # against the DLEN 16 / 12 selected; the SECP 00h length's
            # window note is not an expert info.
            experts = {c.get('name'): n
                       for n in mi[frame].iter('field') if n.get('name') == '_ws.expert'
                       for c in n if not c.get('name').startswith('_ws.expert.')}
            assert set(experts) == {'nvme-mi.admin.short_response'}
            for node in experts.values():
                assert int(pdml_field(node, '_ws.expert.severity').get('show'), 0) == 0x400000
        for frame in (26, 28, 38, 40, 46):
            assert not mi[frame].findall(".//field[@name='_ws.expert']")
        # Selection after the first pass must preserve lengths and diagnostics.
        selected = pdml_section(dissect_pdml(SHARED_MI, two_pass=two_pass, dfilter=to_capture(
            SHARED_MI_SPAN, 'frame.number == 24')), SHARED_MI_SPAN).packets
        assert ET.tostring(pdml_field(selected[24], 'nvme.security.info')) == ET.tostring(
            pdml_field(mi[24], 'nvme.security.info'))

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_window_note_text_not_expert(self, dissect_pdml, field_registry, two_pass):
        # A conformant window the decoder does not walk is not an anomaly:
        # the note is shown under the item it explains, never as an expert.
        assert field_registry['nvme.window_decode_skipped'][3] == 'FT_STRING'
        mi = pdml_section(dissect_pdml(SHARED_MI, two_pass=two_pass), SHARED_MI_SPAN).packets
        for frame in SHARED_WINDOW_NOTES:
            assert [n.get('show') for n in mi[frame].findall(
                ".//field[@name='nvme.window_decode_skipped']")] == [SKIP_RAW], frame
        for frame, packet in mi.items():
            assert not [m.get('show') for m in packet.findall(
                ".//field[@name='_ws.expert.message']")
                if SKIP_RAW in m.get('show')], frame

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_rae_handling_text_not_expert(self, dissect_pdml, two_pass):
        # The ME ignores RAE whatever its value (NVMe-MI 2.2 Figure 137
        # note 2): endpoint policy, shown as text on every Get Log Page
        # request and never as an expert info.
        mi = pdml_section(dissect_pdml(SHARED_MI, two_pass=two_pass), SHARED_MI_SPAN).packets
        rae = 'nvme.cmd.get_logpage.dword10.rae'
        glp = {frame: pdml_field(packet, rae).get('show') for frame, packet in mi.items()
               if packet.find(f".//field[@name='{rae}']") is not None}
        assert set(glp.values()) == {'False', 'True'}
        shown = [frame for frame, packet in mi.items()
                 if packet.find(".//field[@name='nvme-mi.admin.rae_handling']") is not None]
        assert shown == sorted(glp) == SHARED_GLP_REQUESTS
        for frame in shown:
            node = pdml_field(mi[frame], 'nvme-mi.admin.rae_handling')
            # Anchored on CDW10, which holds the RAE bit.
            bit = int(pdml_field(mi[frame], rae).get('pos'))
            assert int(node.get('size')) == 4
            assert int(node.get('pos')) <= bit < int(node.get('pos')) + 4
            assert mi[frame].find(".//field[@name='nvme-mi.admin.rae_policy']") is None
            assert not [m.get('show') for m in mi[frame].findall(
                ".//field[@name='_ws.expert.message']") if 'RAE' in m.get('show')], frame
        # F1 (SMART / Health Information) is otherwise clean.
        assert not mi[1].findall(".//field[@name='_ws.expert']")
        for packet in native_twins(dissect_pdml, two_pass).values():
            assert packet.find(".//field[@name='nvme-mi.admin.rae_handling']") is None


#: reserved_vectors' section of nvme-mi-types.pcapng.
RESERVED_FILE, RESERVED_SPAN = 'nvme-mi-types.pcapng', (620, 669)


class TestNvmeMiReserved:
    """Nonzero Reserved runs in MI bodies are shown shifted by their mask, without an expert."""

    RUNS = (
        (12, 'nvme-mi.mi.subsys.nnsc_reserved', '0x40'),
        (16, 'nvme-mi.mi.port.prtcap_reserved', '0x01'),
        (18, 'nvme-mi.mi.port.pcie.slsv_reserved', '0x01'),
        (20, 'nvme-mi.mi.port.twprt_reserved', '0x01'),
        (22, 'nvme-mi.mi.port.nvmebm_reserved', '0x01'),
        (24, 'nvme-mi.mi.ctrlinfo.prii_reserved', '0x01'),
        (26, 'nvme-mi.mi.nshds.reserved', '0x0100'),
        (30, 'nvme-mi.mi.chds.csts_reserved', '0x0001'),
        (32, 'nvme-mi.mi.chds.reserved', '0001000000'),   # byte 12 of 15:11
        (34, 'nvme-mi.mi.aes.reserved', '0x0000,0x0001'),
        (35, 'nvme-mi.mi.ae.reserved', '0x0002'),
    )

    def test_reserved_runs(self, fields_table):
        t = section(fields_table(RESERVED_FILE, (
            '_ws.expert', '_ws.malformed.expert', 'nvme-mi.mi.reserved', 'nvme-mi.mi.nmresp',
            'nvme-mi.mi.nmresp_reserved', 'nvme-mi.mi.port.pcie.slsv.gts2p5',
            'nvme-mi.mi.port.pcie.slsv.gts5', 'nvme-mi.mi.port.pcie.slsv.gts8',
            'nvme-mi.mi.port.pcie.slsv.gts16', 'nvme-mi.mi.port.pcie.slsv.gts32',
            'nvme-mi.mi.port.pcie.slsv.gts64', *(f for _, f, _ in self.RUNS))), RESERVED_SPAN)
        assert column(t, '_ws.expert') == {}
        assert column(t, '_ws.malformed.expert') == {}
        for frame, name, value in self.RUNS:
            assert t[frame][name] == value, (frame, name)
        # Figure 67: request bytes 07:05 are published.
        assert [t[1]['nvme-mi.mi.reserved'], t[3]['nvme-mi.mi.reserved']] == ['0x000000', '0x005a00']
        # 5.9 and 5.1.2 reserve NMRESP; 5.2.2 does not.
        assert (t[6]['nvme-mi.mi.nmresp_reserved'], t[8]['nvme-mi.mi.nmresp_reserved']) == (
            '0x000100', '0x000001')
        assert (t[10]['nvme-mi.mi.nmresp'], t[10]['nvme-mi.mi.nmresp_reserved']) == ('0x000001', '')
        # Figure 118 byte 09 is a vector: 0Fh supports 2.5 to 16.0 GT/s.
        assert [t[14][f] for f in (
            'nvme-mi.mi.port.pcie.slsv.gts2p5', 'nvme-mi.mi.port.pcie.slsv.gts5',
            'nvme-mi.mi.port.pcie.slsv.gts8', 'nvme-mi.mi.port.pcie.slsv.gts16',
            'nvme-mi.mi.port.pcie.slsv.gts32', 'nvme-mi.mi.port.pcie.slsv.gts64',
            'nvme-mi.mi.port.pcie.slsv_reserved')] == [
            'True', 'True', 'True', 'True', 'False', 'False', '0x00']


@pytest.fixture(scope='module')
def cross_vectors():
    return runpy.run_path(str(Path(__file__).resolve().parents[1]
                             / 'tools/gen-nvme-mi-test-capture.py'))


class TestNvmeMiCrossLayer:
    VERSION = 'mctp-version-state.pcapng'
    TCG = 'nvme-mi-tcg-cross-layer.pcapng'

    def test_version_dropped_before_assembly(self, assert_frames_match, tshark_fields):
        cases = [
            (2, 'mctp.version.unsupported && !nvme-mi && !mctp.assembly.restarted'),
            (3, ('mctp.reassembled.length == 72 && mctp.fragment == 1 && mctp.fragment == 3'
                ' && mctp.fragment.count == 2 && nvme-mi.admin.opcode == 6'
                ' && nvme-mi.mic.status == 1 && !_ws.expert')),
            (4, 'nvme-mi.response_to == 3 && nvme-mi.admin.opcode == 6 && !_ws.expert'),
            (5, 'mctp.version.unsupported && !nvme-mi'),
            (6, 'mctp.assembly.orphan && !mctp.reassembled.length && !nvme-mi'),
        ]
        for two_pass in (False, True):
            assert_frames_match(self.VERSION, cases, two_pass=two_pass)
            assert tshark_fields(self.VERSION, '_ws.expert', two_pass=two_pass).split() == \
                ['2', '5', '6']

    def test_replay_and_reserved_tokens_are_observation_only(
            self, cross_vectors, assert_frames_match, tshark_fields):
        _, frames = cross_vectors['cross_layer_tcg_vectors']()
        secure = 'tcg-storage.packet.secure_data && !tcg-storage.tok.uid && !_ws.expert'
        plain = 'count(tcg-storage.tok.uid) == 2 && !tcg-storage.packet.secure_data && !_ws.expert'
        # A trusted Success resets the ComID even without a captured request.
        cases = [
            (2, ('tcg-storage.comid_mgmt.stack_reset_result == 0'
                 ' && !_ws.expert')),
            (15, ('nvme-mi.replay_of == 2 && nvme-mi.replay_request == 13'
                 ' && nvme-mi.response_to == 1 && nvme-mi.mic.status == 1'
                 ' && tcg-storage.comid_mgmt.stack_reset_result == 0 && !_ws.expert')),
        ]
        warnings = []
        for name in ('same-subpacket', 'cross-subpacket'):
            invalid = frames[name + '-invalid'][0]
            recovery = frames[name + '-next-packet'][0]
            warnings += [invalid, recovery]
            cases += [
                (invalid, ('tcg-storage.tok.reserved_token && count(tcg-storage.tok.uid) == 4'
                          ' && tcg-storage.tok.uid == 0xff04'
                          ' && count(tcg-storage.tok.host_status) == 2')),
                (frames[name + '-victim-plain'][1], plain),
                (frames[name + '-prior-secure'][1], secure),
                (recovery, ('tcg-storage.tok.reserved_token && count(tcg-storage.packet.seq) == 2'
                           ' && tcg-storage.tok.uid == 0xff04')),
                (frames[name + '-recovery-secure'][1], secure),
            ]
        for two_pass in (False, True):
            assert_frames_match(self.TCG, cases, two_pass=two_pass)
            assert list(map(int, tshark_fields(
                self.TCG, '_ws.expert', two_pass=two_pass).split())) == warnings
            assert tshark_fields(self.TCG, 'nvme-mi.mic.status == 1',
                                 two_pass=two_pass).split() == [str(n) for n in range(1, 68)]


class TestNvmeMiTcgFailedSend:
    """A Security Send completed with an error (an NVMe-MI error Response, or
    a CQE status other than success) transferred no data (SIIS 1.20 Table 25)
    and the TPer did not act on it (inferred: Core 2.01 3.3.10.2.1 item 3
    describes the state after an IF-SEND completed without error): its call
    gets no response, and the retry and the next call pair with their own.  So does
    one that an Abort answers with CPAS 01b (aborted before it affected the
    NVM Subsystem, NVMe-MI 'Control Primitives').  So does one whose error
    arrives only in a Replay, the original response never having been seen.
    An Abort answer without a verified MIC undoes nothing."""

    FILE = 'nvme-mi-tcg-failed-send.pcapng'

    def test_pairing(self, cross_vectors, assert_frames_match):
        _, frames = cross_vectors['tcg_failed_send_vectors']()
        scenarios = sorted({name for name, _ in frames if name != 'properties'})
        assert scenarios == ['noseq-abort-nomic-retry', 'noseq-abort-retry',
                             'noseq-cqe-err-no-retry', 'noseq-cqe-err-retry',
                             'noseq-mi-err-retry', 'noseq-replay-retry',
                             'seq-abort-retry', 'seq-cqe-err-retry',
                             'seq-mi-err-retry', 'seq-replay-retry']
        back, forward = [], []
        for name in scenarios:
            failed = frames[(name, 'fail')][0]
            if name == 'noseq-abort-nomic-retry':
                # The Abort answer carries no MIC, so it undoes nothing: the
                # first result still pairs with the aborted call.
                forward.append((failed, 'tcg-storage.response_in == '
                                        f'{frames[(name, "result-a")][1]}'))
                continue
            forward.append((failed, '!tcg-storage.response_in'))
            for call, answer, method in (('retry', 'result-a', 'Get'), ('set', 'result-b', 'Set')):
                if (name, call) not in frames:
                    continue
                request, response = frames[(name, call)][0], frames[(name, answer)][1]
                forward.append((request, (f'tcg-storage.response_in == {response}'
                                          ' && !tcg-storage.data')))
                back.append((response, (f'tcg-storage.request_in == {request}'
                                        f' && tcg-storage.response_to == "Anybody.{method}"')))
        assert_frames_match(self.FILE, back)
        assert_frames_match(self.FILE, back + forward, two_pass=True)


class TestNvmeTcpTcgFailedSend:
    """The same over NVMe/TCP: an Admin Security Send answered by a CapsuleResp
    with an error status (SIIS 1.20 Table 25).  A failure undoes only its own
    Send when two end in one TCP segment."""

    FILE = 'nvme-tcp-tcg-failed-send.pcapng'

    def test_pairing(self, cross_vectors, assert_frames_match):
        _, frames = cross_vectors['tcg_failed_send_tcp_vectors']()
        failed, retry = frames['fail'][0], frames['retry'][0]
        data = frames['result'][0] + 1      # the Receive's C2HData PDU
        back = [(data, f'tcg-storage.request_in == {retry}'
                       ' && tcg-storage.response_to == "Anybody.Get"')]
        forward = [(failed, '!tcg-storage.response_in'),
                   (retry, f'tcg-storage.response_in == {data}')]
        # Two Sends end in one segment and the first fails: the second's
        # call still pairs with its response.
        back.append((frames['result2'][0] + 1,
                     f'tcg-storage.request_in == {frames["pair"][0]}'
                     ' && tcg-storage.response_to == "Anybody.Set"'))
        assert_frames_match(self.FILE, back)
        assert_frames_match(self.FILE, back + forward, two_pass=True)


class TestNvmeMiAdminCompletions:
    """Admin completion Dword 0, Identify flags and superseded Control Primitives."""

    FILE = 'nvme-mi-admin-identify.pcapng'
    SECTION = 4

    NS_FLAGS = (
        ('nvme.cmd.identify.ns.nsfeat.thinp', 'True'), ('nvme.cmd.identify.ns.nsfeat.nsabp', 'True'),
        ('nvme.cmd.identify.ns.nsfeat.dae', 'True'), ('nvme.cmd.identify.ns.nsfeat.uidreuse', 'True'),
        ('nvme.cmd.identify.ns.nsfeat.optperf', '0x01'), ('nvme.cmd.identify.ns.nsfeat.mam', 'False'),
        ('nvme.cmd.identify.ns.nsfeat.optrperf', 'True'), ('nvme.cmd.identify.ns.flbas.fidxl', '3'),
        ('nvme.cmd.identify.ns.flbas.mtelba', 'True'), ('nvme.cmd.identify.ns.flbas.fidxu', '2'),
        ('nvme.cmd.identify.ns.flbas.rsvd', '0x00'), ('nvme.cmd.identify.ns.mc.mtelbas', 'True'),
        ('nvme.cmd.identify.ns.mc.mtsbs', 'True'), ('nvme.cmd.identify.ns.mc.rsvd', '0x00'),
        ('nvme.cmd.identify.ns.dpc.pit1s', 'True'), ('nvme.cmd.identify.ns.dpc.pit2s', 'True'),
        ('nvme.cmd.identify.ns.dpc.pit3s', 'True'), ('nvme.cmd.identify.ns.dpc.piifb', 'True'),
        ('nvme.cmd.identify.ns.dpc.piilb', 'True'), ('nvme.cmd.identify.ns.dpc.rsvd', '0x00'),
        ('nvme.cmd.identify.ns.dps.pit', '0x01'), ('nvme.cmd.identify.ns.dps.pip', 'True'),
        ('nvme.cmd.identify.ns.dps.rsvd', '0x00'), ('nvme.cmd.identify.ns.nmic.shrns', 'True'),
        ('nvme.cmd.identify.ns.nmic.disns', 'False'), ('nvme.cmd.identify.ns.nmic.rsvd', '0x00'),
        ('nvme.cmd.identify.ns.rescap.ptpls', 'True'), ('nvme.cmd.identify.ns.rescap.wes', 'True'),
        ('nvme.cmd.identify.ns.rescap.eas', 'True'), ('nvme.cmd.identify.ns.rescap.weros', 'True'),
        ('nvme.cmd.identify.ns.rescap.earos', 'True'), ('nvme.cmd.identify.ns.rescap.wears', 'True'),
        ('nvme.cmd.identify.ns.rescap.eaars', 'True'), ('nvme.cmd.identify.ns.rescap.ieks', 'True'),
        ('nvme.cmd.identify.ns.fpi.rfnvm', '25'), ('nvme.cmd.identify.ns.fpi.fpis', 'True'),
        ('nvme.cmd.identify.ns.nsattr.cwp', 'True'), ('nvme.cmd.identify.ns.nsattr.rsvd', '0x00'),
    )

    def test_decode(self, assert_frames_match):
        assert_frames_match(self.FILE, at(self.SPAN, [
            # The parents keep their values and filter names.
            (10, ('nvme.cmd.identify.ns.nsfeat == 0x9f && nvme.cmd.identify.ns.flbas == 0x53'
                  ' && nvme.cmd.identify.ns.dps == 0x09 && nvme.cmd.identify.ns.nsattr == 0x01')),
            (15, 'nvme-mi.control.mes.bpopl == 0'),
            # An answer after the slot was emptied still pairs by TAG, late.
            (24, ('nvme-mi.response_to == 21 && nvme-mi.late_control_response'
                  ' && !nvme-mi.control.tag_mismatch')),
        ]), two_pass=True)

    def test_field_values(self, fields_table):
        t = section(fields_table(self.FILE, (
            '_ws.malformed.expert', '_ws.col.info', 'nvme-mi.admin.opcode', 'nvme.cqe.dword0',
            'nvme.cqe.dword0.fw_commit', 'nvme.cqe.dword0.fw_commit.mefwo',
            'nvme.cqe.dword0.fw_commit.asqfwo', 'nvme.cqe.dword0.fw_commit.rsvd',
            'nvme.features.measurement.smtr', 'nvme.features.measurement.pmgn',
            'nvme.features.measurement.pme', 'nvme.cmd.identify.ns.nsfeat',
            'nvme.cmd.identify.ns.flbas', 'nvme.cmd.identify.ns.dpc',
            'nvme.cmd.identify.ns.rescap', *(f for f, _ in self.NS_FLAGS))), self.SPAN)

        def rows(where, *names):
            return {n: [r[f] for f in names] for n, r in t.items() if r[where]}

        assert column(t, '_ws.malformed.expert') == {}
        assert rows('nvme.cqe.dword0.fw_commit', 'nvme.cqe.dword0.fw_commit.mefwo',
                    'nvme.cqe.dword0.fw_commit.asqfwo', 'nvme.cqe.dword0.fw_commit.rsvd') == {
            2: ['True', 'False', '0x00000000'], 4: ['False', 'True', '0x00000000']}
        assert rows('nvme.features.measurement.smtr', 'nvme.features.measurement.smtr',
                    'nvme.features.measurement.pmgn', 'nvme.features.measurement.pme') == {
            6: ['18', '52', 'True']}
        assert [n for n, r in t.items() if r['nvme.cqe.dword0'] and r['nvme-mi.admin.opcode']
                and int(r['nvme-mi.admin.opcode'], 0) == 0x09] == [8]
        assert {f: t[10][f] for f, _ in self.NS_FLAGS} == dict(self.NS_FLAGS)
        # F20's window is bytes 35:28: DPC to FPI, nothing before byte 28.
        assert [t[20][f] for f in (
            'nvme.cmd.identify.ns.nsfeat', 'nvme.cmd.identify.ns.flbas', 'nvme.cmd.identify.ns.dpc',
            'nvme.cmd.identify.ns.dps.pit', 'nvme.cmd.identify.ns.nmic.shrns',
            'nvme.cmd.identify.ns.rescap', 'nvme.cmd.identify.ns.fpi.rfnvm')] == [
            '', '', '0x1f', '0x01', 'True', '0xff', '25']
        assert t[11]['_ws.col.info'].endswith('(Identify) Namespace (Allocated NSID)')

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_superseded_control_primitives(self, fields_table, two_pass):
        t = section(fields_table(self.FILE, ('nvme-mi.control', 'nvme-mi.response_to', 'nvme-mi.response_in',
                                     'nvme-mi.late_control_response',
                                     'nvme-mi.control.tag_mismatch'), two_pass=two_pass), self.SPAN)
        links = {13: ('', '15'), 14: ('', '16'), 15: ('13', ''), 16: ('14', ''), 17: ('', ''),
                 18: ('', ''), 21: ('', '24'), 22: ('', '23'), 23: ('22', ''), 24: ('21', '')}
        if not two_pass:
            # Response In needs the later response.
            links = {n: (to, '') for n, (to, _) in links.items()}
        assert {n: (r['nvme-mi.response_to'], r['nvme-mi.response_in'])
                for n, r in t.items() if r['nvme-mi.control']} == links
        assert list(column(t, 'nvme-mi.late_control_response')) == [15, 24]
        assert list(column(t, 'nvme-mi.control.tag_mismatch')) == [18]


class TestNvmeMiAdminSelectors:
    """MI-allowed Admin commands (NVMe-MI 2.2 Figure 137): selector-dependent
    fields, CQE Dword 0 and Command Specific Status Codes per command
    (NVMe Base 2.4 Figure 104, NVM Command Set 1.3 Figure 19)."""

    FILE = 'nvme-mi-admin-identify.pcapng'
    SECTION = 5

    FIELDS = (
        'nvme.cmd.ns_mgmt.sel', 'nvme.cmd.ns_mgmt.csi', 'nvme.cmd.ns_attach.sel',
        'nvme.cmd.virt_mgmt.act', 'nvme.cmd.virt_mgmt.rt', 'nvme.cmd.cap_mgmt.oper',
        'nvme.cmd.cap_mgmt.capacity', 'nvme.cmd.get_lba_status.mndw',
        'nvme.cmd.get_lba_status.atype', 'nvme.cmd.self_test.dstp', 'nvme.cmd.export.recv_sel',
        'nvme.cmd.export.ra', 'nvme.cmd.dword10', 'nvme.cmd.dword11', 'nvme.cmd.dword12',
        'nvme.cmd.dword13', 'nvme.cmd.dword15', 'nvme.cqe.dword0', 'nvme.cqe.dword0.ns_mgmt.nsid',
        'nvme.cqe.dword0.cap_mgmt.celid', 'nvme.cqe.dword0.virt_mgmt.nrm',
        'nvme.cqe.status.sc', 'nvme.cqe.status.sc.undefined_for_cmd')

    @pytest.fixture
    def table(self, fields_table):
        return section(fields_table(self.FILE, ('_ws.malformed.expert', *self.FIELDS)), self.SPAN)

    def test_decode(self, assert_frames_match):
        assert_frames_match(self.FILE, at(self.SPAN, [
            (1, 'nvme.cmd.ns_mgmt.sel == 0 && nvme.cmd.ns_mgmt.csi == 2 && !nvme.cmd.dword11'),
            (2, 'nvme.cqe.dword0.ns_mgmt.nsid == 5 && !nvme.cqe.dword0'),
            (3, ('nvme.cmd.ns_mgmt.sel == 1 && !nvme.cmd.ns_mgmt.csi'
                ' && nvme.cmd.dword11 == 0x02000000')),
            (4, 'nvme.cqe.dword0 == 5 && !nvme.cqe.dword0.ns_mgmt.nsid'),
            (11, ('nvme.cmd.virt_mgmt.act == 8 && nvme.cmd.virt_mgmt.rt == 1'
                 ' && nvme.cmd.virt_mgmt.cntlid == 0x1234 && nvme.cmd.virt_mgmt.nr == 0x5678'
                 ' && !nvme.cmd.dword10 && !nvme.cmd.dword11 && nvme.cmd.dword12 == 0')),
            (12, 'nvme.cqe.dword0.virt_mgmt.nrm == 16'),
            (14, 'nvme.cqe.dword0 == 0x10 && !nvme.cqe.dword0.virt_mgmt'),
            (17, ('nvme.cmd.cap_mgmt.oper == 3 && nvme.cmd.cap_mgmt.elid == 7'
                 ' && nvme.cmd.cap_mgmt.capacity == 0x1122334455667788'
                 ' && !nvme.cmd.dword11 && !nvme.cmd.dword12')),
            (18, 'nvme.cqe.dword0.cap_mgmt.celid == 9'),
            (19, '!nvme.cmd.cap_mgmt.capacity && nvme.cmd.dword11 == 0x55667788'),
            (20, 'nvme.cqe.dword0 == 9 && !nvme.cqe.dword0.cap_mgmt'),
            # A failed Create returns no Created Element Identifier.
            (24, 'nvme.cqe.dword0 == 9 && !nvme.cqe.dword0.cap_mgmt'),
            (25, ('nvme.cmd.get_lba_status.slba == 0x1122334455667788'
                 ' && nvme.cmd.get_lba_status.mndw == 0 && nvme.cmd.get_lba_status.atype == 2'
                 ' && nvme.cmd.get_lba_status.rl == 16 && !nvme.cmd.dword10'
                 ' && !nvme.cmd.dword13 && nvme.cmd.dword14 == 0')),
            (29, 'nvme.cmd.self_test.dstp == 0xdeadbeef && !nvme.cmd.dword15'),
            (31, '!nvme.cmd.self_test.dstp && nvme.cmd.dword15 == 0x11'),
            (33, 'nvme.cmd.export.recv_sel == 0 && nvme.cmd.export.ra == 1'),
            (35, 'nvme.cmd.export.recv_sel == 1 && !nvme.cmd.export.ra'),
            (37, 'nvme.cmd.export.recv_sel == 0xc5 && !nvme.cmd.export.ra'),
        ]), two_pass=True)

    def test_selector_names(self, dissect_pdml):
        names = {
            1: ('nvme.cmd.ns_mgmt.sel', 'Create (0x0)'),
            3: ('nvme.cmd.ns_mgmt.sel', 'Delete (0x1)'),
            5: ('nvme.cmd.ns_mgmt.sel', 'Reserved (0x3)'),
            7: ('nvme.cmd.ns_attach.sel', 'Controller Detach (0x1)'),
            9: ('nvme.cmd.ns_attach.sel', 'Reserved (0x2)'),
            11: ('nvme.cmd.virt_mgmt.act', 'Secondary Controller Assign (0x8)'),
            15: ('nvme.cmd.virt_mgmt.rt', 'Reserved (0x5)'),
            17: ('nvme.cmd.cap_mgmt.oper', 'Create NVM Set (0x3)'),
            21: ('nvme.cmd.cap_mgmt.oper', 'Reserved (0x6)'),
            27: ('nvme.cmd.get_lba_status.atype', 'Reserved (0x03)'),
            33: ('nvme.cmd.export.recv_sel', 'Create Exported NVM Subsystem (0x00)'),
            37: ('nvme.cmd.export.recv_sel', 'Vendor Specific (0xc5)'),
        }
        p = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        assert {n: [s.rpartition(': ')[2] for s in p.shownames(n, field)]
                for n, (field, _) in names.items()} == {n: [text] for n, (_, text) in names.items()}
        assert p.shownames(25, 'nvme.cmd.get_lba_status.mndw') == [
            'Maximum Number of Dwords (MNDW): 0x0 (1)']

    def test_status_codes(self, table):
        assert column(table, '_ws.malformed.expert') == {}
        sc = {n: r['nvme.cqe.status.sc'] for n, r in table.items()
              if r['nvme.cqe.status.sc'] not in ('', '0x0000')}
        assert sc == {8: '0x001a', 16: '0x0021', 22: '0x0026', 24: '0x002d', 32: '0x001d',
                      40: '0x0009', 42: '0x0009', 44: '0x0082', 46: '0x0082', 48: '0x003c',
                      50: '0x003c', 52: '0x0070', 54: '0x0050', 56: '0x0009',
                      62: '0x0001', 64: '0x00ff', 66: '0x0002'}
        # 09h on Identify, 82h and 3Ch on Sanitize; never Directive Specific
        # (70h), Reserved (50h), a vendor specific opcode or Generic status.
        assert list(column(table, 'nvme.cqe.status.sc.undefined_for_cmd')) == [42, 46, 50]

    def test_status_labels(self, dissect_pdml):
        p = pdml_section(dissect_pdml(self.FILE), self.SPAN)

        def label(frame, field):
            return [s.split(' = ')[-1] for s in p.shownames(frame, field)]

        assert label(40, 'nvme.cqe.status.sc') == [
            'Status Code: 0x09 (Invalid Log Page)']
        assert label(42, 'nvme.cqe.status.sc') == [
            'Status Code: 0x09 (Undefined for Identify; Invalid Log Page for other commands)']
        assert label(44, 'nvme.cqe.status.sc') == [
            'Status Code: 0x82 (Attempted Write to Read Only Range)']
        assert label(48, 'nvme.cqe.status.sc') == [
            'Status Code: 0x3c (Request Exceeds Maximum Namespace Sanitize Operations In Progress)']
        assert label(46, 'nvme.cqe.status.sc.undefined_for_cmd') == [
            ('Command Specific Status 82h (Attempted Write to Read Only Range) is not defined'
            " for Sanitize (NVM Command Set 'Status Code - Command Specific Status Values')")]

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_vendor_specific_status(self, dissect_pdml, two_pass):
        # SCT 7h SC values are vendor defined (Base 2.4 Figure 102).
        p = pdml_section(dissect_pdml(self.FILE, two_pass=two_pass), self.SPAN)
        assert {n: (p.label(n, 'nvme.cqe.status.sc'), p.values(n, 'nvme.cqe.status.sct'))
                for n in (60, 62, 64, 66)} == {
            60: ('0x00 (Vendor Specific)', [7]), 62: ('0x01 (Vendor Specific)', [7]),
            64: ('0xff (Vendor Specific)', [7]),
            66: ('0x02 (Invalid Field in Command)', [0])}
        for n in (60, 62, 64, 66):
            assert p.experts(n) == ['Command completed with an error status'], n

    def test_security_compliance_header(self, assert_frames_match):
        # SECP 00h SPSP 0002h (SPC-5 Security Compliance Information): the
        # 4-byte big-endian length, descriptors raw; SPSP 0003h stays opaque.
        assert_frames_match('nvme-mi-security.pcapng', [
            (24, ('nvme.security.info.compliance_len == 12'
                 ' && nvme.security.info.compliance_desc == 00:01:00:00:00:00:00:04:10:11:12:13'
                 ' && !nvme.security.info.residue && !nvme.cmd.security.data && !_ws.expert')),
        ], two_pass=True)
        assert_frames_match(self.FILE, at(self.SPAN, [
            (58, 'nvme.cmd.security.data && !nvme.security.info'),
        ]), two_pass=True)

    def test_two_pass_parity(self, fields_table, table):
        assert section(fields_table(self.FILE, ('_ws.malformed.expert', *self.FIELDS),
                                    two_pass=True), self.SPAN) == table


class TestNvmeMiEdgeCases:
    """Edge cases of CP effects, pairing windows, DLEN and MI field values."""

    FILE = 'nvme-mi-types.pcapng'
    SECTION = 12

    REPLAYS: ClassVar = {5: 2, 10: 7, 15: 12, 30: 27}
    ANA = ('nvme.cmd.get_logpage.ana.grp', 'nvme.cmd.get_logpage.ana.grp.id',
           'nvme.cmd.get_logpage.ana.grp.nns', 'nvme.cmd.get_logpage.ana.grp.chcnt',
           'nvme.cmd.get_logpage.ana.grp.anas.state', 'nvme.cmd.get_logpage.ana.grp.rsvd',
           'nvme.cmd.get_logpage.ana.grp.nsid')
    VPD = ('nvme-mi.mi.vpd.pciels.gts64', 'nvme-mi.mi.vpd.pciels.gts32', 'nvme-mi.mi.vpd.rccap.rcs',
           'nvme-mi.mi.vpd.rccap.crcs', 'nvme-mi.mi.vpd.mctps.mctppcievs',
           'nvme-mi.mi.vpd.addri.twaddr', 'nvme-mi.mi.vpd.addri.arpc', 'nvme-mi.mi.vpd.twcap.rst',
           'nvme-mi.mi.vpd.twcap.m2was', 'nvme-mi.mi.vpd.twcap.i3cs', 'nvme-mi.mi.vpd.twcap.ffr',
           'nvme-mi.mi.vpd.twcap.pecs', 'nvme-mi.mi.vpd.twcap.mspd', 'nvme-mi.mi.vpd.rsvd')
    FRU = ('nvme-mi.mi.vpd.addri.twaddr', 'nvme-mi.mi.vpd.addri.arpc', 'nvme-mi.mi.vpd.twcap.rst',
           'nvme-mi.mi.vpd.twcap.i2cwa', 'nvme-mi.mi.vpd.twcap.bfcs', 'nvme-mi.mi.vpd.twcap.mspd',
           'nvme-mi.mi.vpd.mfids')
    PIA = ('nvme-mi.mi.vpd.pia.ipmiver', 'nvme-mi.mi.vpd.pia.palen', 'nvme-mi.mi.vpd.pia.lcode',
           'nvme-mi.mi.vpd.pia.mname', 'nvme-mi.mi.vpd.pia.pname', 'nvme-mi.mi.vpd.pia.ppmn',
           'nvme-mi.mi.vpd.pia.pver', 'nvme-mi.mi.vpd.pia.psn', 'nvme-mi.mi.vpd.pia.at',
           'nvme-mi.mi.vpd.pia.cpia', 'nvme-mi.mi.vpd.pia.pichk', 'nvme-mi.mi.vpd.rti')
    IDENTIFY = ('nvme.window.partial', 'nvme.data', 'nvme.cmd.identify.cs_ind_ns.anagrpid',
                'nvme.cmd.identify.cs_ind_ns.rgrpid', 'nvme.cmd.identify.cs_ind_ns.rsvd2',
                'nvme.cmd.identify.nslist.nsid', 'nvme.cmd.identify.iocsc')
    TOO_SHORT = ("NVMe-MI message is shorter than the four-byte NVMe-MI Message Header, so it"
                 " cannot be a complete NVMe-MI Message (NVMe-MI 'NVMe-MI Message Fields')")

    def table(self, fields_table, two_pass=False, prefs=None):
        return section(fields_table(self.FILE, (
            'frame.protocols', '_ws.col.info', '_ws.expert.message', '_ws.malformed',
            'nvme-mi.replay_of', 'nvme-mi.response_to', 'nvme-mi.response_in',
            'nvme-mi.duplicate_mpr', 'nvme-mi.req_superseded', 'nvme-mi.status', 'nvme-mi.pel.byte',
            'nvme-mi.pel.bit', 'nvme-mi.reserved_type', 'nvme-mi.late_control_response',
            'nvme-mi.control.orphan_response', 'nvme-mi.control.opcode', 'nvme.data.wrong_direction',
            'nvme-mi.admin.data_excess', 'nvme.cqe.dword0', 'nvme.cqe.dword0.fw_commit.asqfwo',
            'nvme.cqe.dword0.fw_commit.mefwo', 'nvme.cmd.set_features.dword11.tt.tmpsel',
            'nvme.cmd.get_features.dword11.tt.tmpsel',
            'nvme-mi.mi.aeosi.cwv', 'nvme-mi.mi.nshds.sw.taut', 'nvme-mi.mi.nshds.sw.st',
            'nvme-mi.mi.nshds.sw_reserved', 'nvme-mi.mi.vpd.raw', 'nvme-mi.mi.vpd.bad_checksum', *self.ANA, *self.VPD,
            'nvme-mi.mi.vpd.twcap.i2cwa', 'nvme-mi.mi.vpd.twcap.bfcs', 'nvme-mi.mi.vpd.mfids',
            *self.PIA, *self.IDENTIFY), two_pass=two_pass, prefs=prefs), self.SPAN)

    def test_decode(self, assert_frames_match):
        # Too short for a header: still nvme-mi, nothing invented.
        assert_frames_match(self.FILE, at(self.SPAN, [
            (n, 'nvme-mi.too_short && !nvme-mi.mctp-mt && !nvme-mi.type') for n in (54, 55)]))

    @pytest.mark.parametrize('two_pass', [False, True])
    @pytest.mark.parametrize('prefs', [None, {'nvme-mi.check_mic': 'FALSE'}],
                             ids=['default', 'check_mic_off'])
    def test_control_effects_without_a_verified_mic(self, fields_table, two_pass, prefs):
        """A CP's effect follows from its Success response, not from a verified MIC."""
        t = self.table(fields_table, two_pass, prefs)
        assert {n: int(v) for n, v in column(t, 'nvme-mi.replay_of').items()} == self.REPLAYS
        assert [t[15]['nvme-mi.response_to'], t[30]['nvme-mi.response_to']] == ['11', '26']
        assert column(t, 'nvme-mi.duplicate_mpr') == {}
        assert list(column(t, 'nvme-mi.req_superseded')) == ([] if prefs else [24])
        # A reserved-NMIMT request with IC 0 is answered and its echo's STATUS
        # decodes (4.1.2); only the request is Reserved, and no link is made.
        assert {n: [t[n][f] for f in ('nvme-mi.status', 'nvme-mi.pel.byte', 'nvme-mi.pel.bit',
                                      'nvme-mi.response_to', 'nvme-mi.response_in')]
                for n in (42, 43)} == {42: ['', '', '', '', ''], 43: ['0x04', '1', '3', '', '']}
        assert list(column(t, 'nvme-mi.reserved_type')) == [42]

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_control_pairing_and_windows(self, fields_table, two_pass):
        t = self.table(fields_table, two_pass)
        # A Replay re-decodes the same ANA window (Figures 227/228).
        for original, replay in ((2, 5), (7, 10)):
            assert [t[original][f] for f in self.ANA] == [t[replay][f] for f in self.ANA]
        for n in (2, 7):
            assert [t[n][f] for f in self.ANA[1:5]] == ['0x00000001', '2', '7', '0x01']
            assert t[n]['nvme.cmd.get_logpage.ana.grp.nsid'] == ''
        # Unable to Abort pairs with the nearest unanswered Abort, never a
        # non-Abort slot; a superseded answer may arrive after the newest.
        assert {n: (t[n]['nvme-mi.response_to'], t[n]['nvme-mi.control.opcode'])
                for n in (34, 35, 37, 38, 41, 46, 47, 50, 51, 52, 53)} == {
            34: ('32', '0x02'), 35: ('33', '0x03'), 37: ('', '0x03'), 38: ('36', '0x03'),
            41: ('40', '0x02'), 46: ('45', '0x03'), 47: ('44', '0x02'), 50: ('49', '0x03'),
            51: ('48', '0x03'), 52: ('', ''), 53: ('', '')}
        assert list(column(t, 'nvme-mi.late_control_response')) == [34, 47, 51]
        assert list(column(t, 'nvme-mi.control.orphan_response')) == [52, 53]
        if two_pass:
            assert {n: t[n]['nvme-mi.response_in'] for n in (32, 33, 36, 39, 40, 44, 45, 48, 49)} == {
                32: '34', 33: '35', 36: '38', 39: '', 40: '41', 44: '47', 45: '46', 48: '51',
                49: '50'}
        # Bytes travelling the wrong way are refused and stay visible.
        assert list(column(t, 'nvme.data.wrong_direction')) == [59, 60]
        # Set Features / Firmware Download (data transfer 01b) return no data
        # to the host (Base 2.4 Figure 92): flagged, left raw, not excess.
        assert {n: (t[n]['_ws.expert.message'], t[n]['nvme-mi.admin.data_excess'])
                for n in (62, 64, 66)} == {
            n: ((f'NVMe Response Data is {size} bytes for an opcode whose data'
                ' transfer bits 1:0 (01b) return no data'), '')
            for n, size in ((62, 8), (64, 8), (66, 20))}
        # Figure 186 Dword 0 on success (MEFWO) and abort (ASQFWO).
        assert {n: [t[n][f] for f in ('nvme.cqe.dword0', 'nvme.cqe.dword0.fw_commit.asqfwo',
                                      'nvme.cqe.dword0.fw_commit.mefwo')] for n in (76, 78)} == {
            76: ['', 'False', 'True'], 78: ['', 'True', 'False']}

    def test_field_values(self, fields_table):
        t = self.table(fields_table)

        def row(frame, *names):
            return [t[frame][f] for f in names]

        # A message shorter than the header is still shown and diagnosed.
        for n, length in ((54, 3), (55, 1)):
            assert row(n, 'frame.protocols', '_ws.col.info', '_ws.expert.message') == [
                'sll:mctp:nvme-mi', f'Bogus length {length}, minimum 4', self.TOO_SHORT]
        assert list(column(t, '_ws.malformed')) == [54, 55]
        # DLEN is checked against the Request Data carried (Figure 139), then
        # against the size the command dwords define (MI 2.2 Figure 139).
        assert [t[n]['_ws.expert.message'] for n in (56, 57, 58)] == [
            ('Data Length 16 does not equal the 8 bytes of NVMe Request Data the'
            ' Set Features FID requires'),
            ('Data Length 8 does not equal the 16 bytes of NVMe Request Data'
            ' the Firmware Image Download NUMD requires'),
            'Data Length 16 must equal the 8-byte NVMe Request Data field']
        # Security Receive moves data controller to host only (Figure 142).
        assert t[59]['_ws.expert.message'] == (
            "Command is not defined to transfer NVMe Request Data (NVMe-MI 'NVMe Admin"
            " Command Request Description'),"
            'Host-to-controller data for Security Receive, which defines data in the'
            ' controller-to-host direction only; no response-side field is decoded from it')
        # Get/Set Features name their Feature in Info (OCP NVMe-MI-13).
        assert [t[n]['_ws.col.info'] for n in (56, 61, 62, 70)] == [
            'NVMe-MI NVMe Admin command Request (Set Features) Timestamp',
            'NVMe-MI NVMe Admin command Request (Set Features) Timestamp',
            'NVMe-MI NVMe Admin command Response (Set Features)',
            'NVMe-MI NVMe Admin command Request (Get Features) Power Management']
        # Get and Set TMPSEL filter apart (Figure 470).
        for op, want in (('get', {71: 0xf, 72: 0x9}), ('set', {73: 0xf, 74: 0xe})):
            assert {n: int(v, 0) for n, v in column(
                t, f'nvme.cmd.{op}_features.dword11.tt.tmpsel').items() if 71 <= n <= 74} == want
        # CWV is the inverted Critical Warning (Figures 65/105).
        assert row(82, 'nvme-mi.mi.aeosi.cwv', 'nvme-mi.mi.nshds.sw.taut',
                   'nvme-mi.mi.nshds.sw.st') == ['0xfd', 'False', 'True']
        assert t[82]['nvme-mi.mi.nshds.sw_reserved'] == 'True'
        # MultiRecord bit vectors: the 0Ch record, then the NVM Subsystem port;
        # TWADDRI/TWCAP: the NVM Subsystem (3Ah, 51h), then the Mux (E9h, C2h).
        assert row(84, *self.VPD) == [
            'False,False', 'True,True', 'False,False', 'True,True', 'True,True', '0x1d,0x74',
            'False,True', 'False', '2', 'True', 'True', 'True', '1,2', '000000000000,00']
        # FRU Information Device: REV 1h and 0h decode, REV 2h stays raw.
        assert t[86]['nvme-mi.mi.vpd.raw'] == '00,a6e109'
        assert row(86, *self.FRU) == ['0x53,0x52', 'False,False', 'True,False', 'True,False',
                                      'True,False', '1,0', '9,8']
        # Identify windows render each byte once: a field, or raw.
        assert {n: row(n, *self.IDENTIFY) for n in (88, 90, 92, 94, 96, 98)} == {
            88: ['', '', '0x00000007', '0x00000003', '0000000000000000', '', ''],
            90: ['', '', '0x00000007', '0x00000003', '0000000000000000', '', ''],
            92: ['0000,0300', '', '', '', '', '', ''],
            94: ['', '0000000000000000', '', '', '', '0x00000001,0x00000003', ''],
            96: ['', '0000000000000000', '', '', '', '0x00000001,0x00000003', ''],
            98: ['04050607,10111213', '', '', '', '', '', '0x0f0e0d0c0b0a0908']}
        # The Product Info Area (8.2.2, IPMI FRU format, Figure 174).
        assert [t[100]['nvme-mi.mi.vpd.raw'], t[104]['nvme-mi.mi.vpd.raw']] == ['beef,00', '']
        assert row(100, *self.PIA) == ['0x01', '6', '0x19', 'ACME', 'NVMe SSD', 'MODEL-123', '01',
                                       'SN0001', '', 'XYZ', '0x98', '0x0c']
        assert row(104, *self.PIA) == ['0x01', '6', '0x19', 'ACME', 'NVMe SSD', 'MODEL-', '', '',
                                       '', '', '', '']
        assert list(column(t, 'nvme-mi.mi.vpd.bad_checksum')) == [102]
        # MRIOFF 0: bytes outside every decoded area are still shown (8.2).
        assert [t[106]['nvme-mi.mi.vpd.raw'], t[108]['nvme-mi.mi.vpd.raw']] == [
            '010119' + '00' * 5, 'aa' * 16]
        assert [row(n, '_ws.expert.message', 'nvme-mi.mi.vpd.pia.ipmiver', 'nvme-mi.mi.vpd.rti')
                for n in (106, 108)] == [['', '', '']] * 2

    def test_raw_data_hidden_only_behind_a_decode(self, dissect_pdml):
        p = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        assert {n: p.field(n, 'nvme-mi.admin.data').get('hide') == 'yes' for n in (2, 60, 61, 62)} == {
            2: True, 60: False, 61: True, 62: False}

    def test_labels(self, dissect_pdml):
        q = pdml_section(dissect_pdml(self.FILE), self.SPAN)

        def label(p, frame, name):
            return p.field(frame, name)['showname']

        # Lockdown OFI is named by its Scope (Figure 353); MI opcodes have no
        # table here.
        for p, frame, ofi in ((q, 67, '0x04 (Temperature Threshold)'), (q, 68, '0x84 (Sanitize)'),
                              (q, 69, '0x01'),
                              (dissect_pdml('nvme-mi-admin-identify.pcapng'), 37,
                               '0x09 (Set Features)')):
            assert label(p, frame, 'nvme.cmd.lockdown.dword10.ofi').endswith(
                'Opcode or Feature Identifier (OFI): ' + ofi), frame
        # TMPSEL Fh is All Sensors only for Set; 9h-Eh are Reserved (Figure 407).
        for frame, op, text in ((71, 'get', 'Reserved (0xf)'), (72, 'get', 'Reserved (0x9)'),
                                (73, 'set', 'All Temperature Sensors (0xf)'),
                                (74, 'set', 'Reserved (0xe)')):
            assert label(q, frame, f'nvme.cmd.{op}_features.dword11.tt.tmpsel').endswith(
                'Threshold Temperature Select: ' + text)
        # NUMD is 0's based over 31:00 (Figure 189).
        assert [label(q, n, 'nvme.cmd.fw_download.numd') for n in (57, 79)] == [
            'Number of Dwords (NUMD): 0x3 (4)',
            'Number of Dwords (NUMD): 0xffffffff (4294967296)']
        # SPSP is SPSP1:SPSP0 (Figures 394/398), named per protocol (396, SIIS).
        security, tcg = dissect_pdml('nvme-mi-security.pcapng'), dissect_pdml(
            'nvme-mi-tcg.pcapng')
        for p, frame, spsp, nssf in (
                (q, 80, '0x0001 (Replay Protected Memory Block)', '0x00 (RPMB Target)'),
                (q, 81, '0x0003 (Reserved)', '0x05 (Reserved)'),
                (security, 5, '0x1000 (ComID)', '0x00'), (security, 1, '0x0000', '0x00'),
                (tcg, 400, '0x1000 (Reserved)', '0x00 (Reserved)')):
            assert label(p, frame, 'nvme.cmd.security.dword10.nssf').endswith(
                'NVMe Security Specific Field (NSSF): ' + nssf), frame
            assert label(p, frame, 'nvme.cmd.security.dword10.spsp') == 'SP Specific (SPSP): ' + spsp
        # AE Occurrence Specific values in their units (Figure 65).
        for p, frame, ctv, pmt, pwrs, pwrv in (
                (q, 82, '-40 °C', 'NVM Subsystem total power (0x0)', '0.0001 W (0x1)',
                 '12345 (1.2345 W)'),
                (dissect_pdml('nvme-mi-mi-commands.pcapng'), 350, '37 °C',
                 'Vendor Specific (0xc)', '0.01 W (0x2)', '4660 (46.60 W)')):
            assert label(p, frame, 'nvme-mi.mi.aeosi.ctv') == 'Composite Temperature Value (CTV): ' + ctv
            assert label(p, frame, 'nvme-mi.mi.aeosi.pmt').endswith('Power Measurement Type (PMT): ' + pmt)
            assert label(p, frame, 'nvme-mi.mi.aeosi.pwrs').endswith('Power Scale (PWRS): ' + pwrs)
            assert label(p, frame, 'nvme-mi.mi.aeosi.pwrv').endswith(
                decimal_forms('Power Value (PWRV): ' + pwrv))
        # VPD enumerations (Figures 172/175/176/183/194) and record byte order.
        assert [label(q, 84, n) for n in ('nvme-mi.mi.vpd.bfc', 'nvme-mi.mi.vpd.ff',
                                          'nvme-mi.mi.vpd.pciemlw')] == [
            'Boot Failure Code (BFC): Corrupted Firmware Image (0x08)',
            'Form Factor (FF): PCIe, CEM add in card - Standard Height Half Length (FHHL) (0x22)',
            'PCIe Maximum Link Width (PCIEMLW): PCIe x4 (4)']
        assert label(q, 84, 'nvme-mi.mi.vpd.twcap.m2was').endswith(
            'MCTP over 2-Wire In Aux Power Support (M2WAS): The 2-Wire port supports MCTP during'
            ' the Auxiliary Only power state (2)')
        positions = [int(f.get('pos')) for f in q.fields(84, 'nvme-mi.mi.vpd.record')[0]]
        assert positions == sorted(positions)
        assert label(q, 86, 'nvme-mi.mi.vpd.mfids') == (
            'Maximum FRU Information Device Size (MFIDS): 9 (512 bytes)')
        assert label(q, 100, 'nvme-mi.mi.vpd.pia.tl').startswith('Manufacturer Name Type/Length: 0xc4')
        # TWPME's current name, under the old filter name (Figure 328 byte 255).
        identify = dissect_pdml('nvme-mi-admin-identify.pcapng')
        assert label(identify, 2, 'nvme.cmd.identify.ctrl.mi.mec.smbusme').endswith(
            '2-Wire Port Management Endpoint (TWPME): False')
        # LBA Format RP 25:24 is named (NVM CS 1.2 Figure 116).
        assert [f.get('showname') for f in identify.fields(4, 'nvme.cmd.identify.ns.lbaf')[:4]] == [
            'LBA Format: 0x00090000 (LBAF0: LBADS 9, MS 0, RP Best performance)',
            'LBA Format: 0x010a0001 (LBAF1: LBADS 10, MS 1, RP Better performance)',
            'LBA Format: 0x020b0002 (LBAF2: LBADS 11, MS 2, RP Good performance)',
            'LBA Format: 0x030c0003 (LBAF3: LBADS 12, MS 3, RP Degraded performance)']

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_nshds_sw_summary(self, dissect_pdml, two_pass):
        """SW is inverted (MI 2.2 Figure 105): the parent names no bits."""
        p = pdml_section(dissect_pdml(self.FILE, two_pass=two_pass), self.SPAN)
        children = ('nvme-mi.mi.nshds.sw.ips', 'nvme-mi.mi.nshds.sw.pmre',
                    'nvme-mi.mi.nshds.sw.vmbf', 'nvme-mi.mi.nshds.sw.ro',
                    'nvme-mi.mi.nshds.sw.rd', 'nvme-mi.mi.nshds.sw.taut',
                    'nvme-mi.mi.nshds.sw.st')
        for frame, sw in ((110, 0xff), (112, 0x80), (114, 0xfd)):
            assert p.shownames(frame, 'nvme-mi.mi.nshds.sw') == [f'SMART Warnings (SW): 0x{sw:02x}']
            assert p.values(frame, 'nvme-mi.mi.nshds.sw') == [sw]
            assert p.values(frame, 'nvme-mi.mi.nshds.sw_reserved') == [1]
            labels = [p.label(frame, name) for name in children]
            assert labels == ['Normal' if sw & (0x40 >> i) else 'Warning'
                              for i in range(7)], frame
            assert p.experts(frame) == []

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_health_status_reserved_bits(self, dissect_pdml, two_pass):
        """NSS bit 0 and HSF bits 15:14 and 3 are shown, without an expert
        (MI 2.2 Figures 97/105)."""
        p = pdml_section(dissect_pdml(self.FILE, two_pass=two_pass), self.SPAN)
        defined = ('nvme-mi.mi.hsf.tcida', 'nvme-mi.mi.hsf.cwarn', 'nvme-mi.mi.hsf.spare',
                   'nvme-mi.mi.hsf.pdlu', 'nvme-mi.mi.hsf.ctemp', 'nvme-mi.mi.hsf.csts',
                   'nvme-mi.mi.hsf.fa', 'nvme-mi.mi.hsf.nac', 'nvme-mi.mi.hsf.ceco',
                   'nvme-mi.mi.hsf.nssro', 'nvme-mi.mi.hsf.shst', 'nvme-mi.mi.hsf.cfs',
                   'nvme-mi.mi.hsf.rdy')

        def flags(value):
            masks = (0x2000, 0x1000, 0x0800, 0x0400, 0x0200, 0x0100, 0x0080, 0x0040,
                     0x0020, 0x0010, 0x0004, 0x0002, 0x0001)
            return [int(bool(value & m)) for m in masks]

        for frame, nss, rsvd in ((110, 0x38, 0), (116, 0x39, 1)):
            assert p.values(frame, 'nvme-mi.mi.nshds.nss') == [nss]
            assert p.values(frame, 'nvme-mi.mi.nshds.nss.reserved') == [rsvd]
            assert [p.values(frame, f'nvme-mi.mi.nshds.nss.{f}') for f in (
                'df', 'rnr', 'p0la', 'atf')] == [[1], [1], [1], [0]]
        for frame, ccsf, high, low in ((110, 0x0211, 0, 0), (118, 0xc211, 3, 0),
                                       (120, 0x0219, 0, 1), (122, 0xc008, 3, 1)):
            assert p.values(frame, 'nvme-mi.mi.nshds.ccs') == [ccsf], frame
            assert p.values(frame, 'nvme-mi.mi.hsf.rsvd_15_14') == [high], frame
            assert p.values(frame, 'nvme-mi.mi.hsf.rsvd_3') == [low], frame
            assert [p.values(frame, f)[0] for f in defined] == flags(ccsf), frame
        chscf = (0x1002, 0xd002, 0x100a, 0xc008)
        assert p.values(124, 'nvme-mi.mi.chds.chsc') == list(chscf)
        assert p.values(124, 'nvme-mi.mi.hsf.rsvd_15_14') == [0, 3, 0, 3]
        assert p.values(124, 'nvme-mi.mi.hsf.rsvd_3') == [0, 0, 1, 1]
        assert [p.values(124, f) for f in defined] == [list(c) for c in zip(
            *(flags(v) for v in chscf))]
        for frame in (110, 116, 118, 120, 122, 124):
            assert p.experts(frame) == [], frame

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_pcie_port_pinfo(self, dissect_pdml, two_pass):
        """PINFO bits 7:1 are Reserved and bit 0 is CPPC (MI 2.2 Figure 176)."""
        p = pdml_section(dissect_pdml(self.FILE, two_pass=two_pass), self.SPAN)
        assert [p.values(84, f) for f in ('nvme-mi.mi.vpd.pinfo', 'nvme-mi.mi.vpd.pinfo.reserved',
                                          'nvme-mi.mi.vpd.cppc')] == [[0x01], [0], [1]]
        assert [p.values(126, f) for f in (
            'nvme-mi.mi.vpd.pciepn', 'nvme-mi.mi.vpd.pinfo', 'nvme-mi.mi.vpd.pinfo.reserved',
            'nvme-mi.mi.vpd.cppc', 'nvme-mi.mi.vpd.pciels', 'nvme-mi.mi.vpd.pciemlw',
            'nvme-mi.mi.vpd.mctps', 'nvme-mi.mi.vpd.rccap', 'nvme-mi.mi.vpd.portid')] == [
            [0, 1, 2, 3], [0x01, 0xff, 0xfe, 0xff], [0, 0x7f, 0x7f, 0x7f], [1, 1, 0, 1],
            [0x1f] * 4, [4] * 4, [1] * 4, [0x07] * 4, [0, 1, 2, 3]]
        records = [int(f.get('pos')) for f in p.fields(126, 'nvme-mi.mi.vpd.record')]
        for name, offset in (('nvme-mi.mi.vpd.pciepn', 6), ('nvme-mi.mi.vpd.pinfo', 7),
                             ('nvme-mi.mi.vpd.pciels', 8), ('nvme-mi.mi.vpd.portid', 12)):
            assert p.extents(126, name) == [(pos + offset, 1) for pos in records], name
        assert p.experts(126) == []


class TestNvmeMiOverMctpTransports:
    """The NVMe-MI side of the MCTP transport captures."""

    LINKS = ('nvme-mi.response_in', 'nvme-mi.response_to')

    @staticmethod
    def links(table, frames):
        return {n: (table[n]['nvme-mi.response_in'], table[n]['nvme-mi.response_to'])
                for n in frames}

    def test_transport_limits(self, fields_table, assert_frames_match):
        """F93 exceeds DSP0235 7.6's 4,224 bytes and displaces the request before it."""
        f = 'mctp-transport.pcapng'
        t = fields_table(f, ('nvme-mi.message_too_large', 'nvme-mi.req_superseded',
                             'nvme-mi.prev_no_response', '_ws.expert') + self.LINKS,
                         two_pass=True)
        t = {n: row for n, row in t.items() if 88 <= n <= 95}
        assert list(column(t, 'nvme-mi.message_too_large')) == [93]
        assert list(column(t, 'nvme-mi.req_superseded')) == [92, 93]
        for field in ('nvme-mi.prev_no_response',) + self.LINKS:
            assert column(t, field) == {}, field
        assert_frames_match(f, [
            (89, 'nvme-mi.mi.opcode == 0x01 && nvme-mi.mic.status == 1'),
            (92, 'nvme-mi.mic.status == 1'),
            (93, 'nvme-mi.mic.status == 1'),
        ])

    def test_smbus_ingress_pairing(self, fields_table, assert_frames_match):
        """A bad-PEC record remains visible but cannot mutate MCTP state."""
        f = 'mctp-smbus-ingress.pcapng'
        fields = ('mctp.smbus', 'nvme-mi.mi.opcode', '_ws.col.protocol') + self.LINKS
        default = fields_table(f, fields, two_pass=True)
        assert self.links(default, (7, 8)) == {7: ('8', ''), 8: ('', '7')}
        assert (default[2]['nvme-mi.response_to'], default[5]['nvme-mi.response_to'],
                default[18]['nvme-mi.response_to'], default[19]['nvme-mi.response_to']) == (
                    '1', '', '', '17')
        assert_frames_match(f, [
            (4, 'mctp.assembly.orphan && !nvme-mi && !mctp.reassembled.length'),
            (7, 'nvme-mi.mi.opcode == 0x01'),
        ])

    def test_smbus_body_that_cannot_finish(self, fields_table, assert_frames_match):
        """An NVM Subsystem Information response with RDL 2 (Figure 115)."""
        f = 'mctp-smbus.pcapng'
        t = fields_table(f, ('nvme-mi.mic.status', 'nvme-mi.mi.response_data_length',
                             '_ws.col.info') + self.LINKS, two_pass=True)
        t = {n: row for n, row in t.items() if 20 <= n <= 27}
        assert [n for n, row in t.items() if row['nvme-mi.mic.status'] == '1'] == [
            20, 21, 24, 26, 27]
        # F21 is an empty HSP response; F27 the short structure.
        assert list(column(t, 'nvme-mi.mi.response_data_length')) == [21, 27]
        assert self.links(t, (26, 27)) == {26: ('27', ''), 27: ('', '26')}
        assert [t[n]['_ws.col.info'] for n in (20, 21)] == [
            '[0x10->0x3a] NVMe-MI MI command Request (NVM Subsystem Health Status Poll)',
            '[0x3a->0x10] NVMe-MI MI command Response (NVM Subsystem Health Status Poll)']
        assert_frames_match(f, [
            (20, 'nvme-mi.mic.status == 1 && mctp.smbus.pec.status == 1'),
            (21, 'nvme-mi.mic.status == 1'),
            (24, 'nvme-mi.mic.status == 1 && !_ws.expert'),
            (26, ('mctp.smbus.pec.status == 1 && nvme-mi.mic.status == 1 && !_ws.expert'
                  ' && nvme-mi.mi.opcode == 0x00 && nvme-mi.mi.rds.dtyp == 0')),
            (27, ('mctp.smbus.pec.status == 1 && nvme-mi.mic.status == 1'
                  ' && nvme-mi.mi.response_data_length && _ws.malformed && !_ws.short'
                  ' && !nvme-mi.mi.truncated')),
        ])

    def test_ingress_scope_keys(self, fields_table, assert_frames_match):
        """The transaction key carries the I2C ingress scope."""
        f = 'mctp-ingress-scope.pcapng'
        t = fields_table(f, ('nvme-mi.req_superseded',) + self.LINKS, two_pass=True)
        assert column(t, 'nvme-mi.req_superseded') == {}
        assert self.links(t, (1, 2, 3, 4)) == {
            1: ('4', ''), 2: ('3', ''), 3: ('', '2'), 4: ('', '1')}
        assert_frames_match(f, [
            (3, '!nvme-mi.admin.orphan_response && nvme-mi.admin.opcode == 0x02'),
            (4, '!nvme-mi.admin.orphan_response && nvme-mi.admin.opcode == 0x06'),
            (11, 'nvme-mi.mi.opcode == 0x01'),
        ])

    def test_sll2_twins_hold_no_state(self, tshark_fields):
        assert tshark_fields('mctp-transport.pcapng',
                             'frame.number >= 104 && nvme-mi.prev_no_response').strip() == ''


class TestNvmeMiUntrustedResponses:
    """A response that cannot be trusted neither answers nor pairs anything."""

    @staticmethod
    def links(cmd_tshark, test_env, path, fields, dfilter):
        out = subprocess.check_output(
            [cmd_tshark, '-2', '-r', str(path), '-Y', dfilter, '-Tfields', '-eframe.number',
             *[f'-e{f}' for f in fields]], encoding='utf-8', env=test_env)
        return [line.split('\t') for line in out.splitlines()]

    def test_control_response_without_status_leaves_the_slot_open(
            self, cross_vectors, cmd_tshark, test_env, tmp_path):
        """A Control Primitive Response starts with STATUS (Figure 40): a
        header-and-MIC-only response is flagged and the real one still pairs."""
        make, ctl = cross_vectors['make_packet'], cross_vectors['NVME_MI_TYPE_CONTROL']
        packets = [
            make(True, ctl, 0, cross_vectors['cp_request_payload'](
                cross_vectors['CP_OPC_ABORT'], tag=3), tag=1),
            make(False, ctl, 0, b'', tag=1),
            make(False, ctl, 0, cross_vectors['cp_response_payload'](0, tag=3), tag=1)]
        path = tmp_path / 'cp-empty.pcapng'
        path.write_bytes(cross_vectors['cross_layer_pcapng'](packets))
        rows = self.links(cmd_tshark, test_env, path,
                          ('nvme-mi.response_to', 'nvme-mi.status_absent'), 'nvme-mi')
        assert [(r[0], r[1]) for r in rows] == [('1', ''), ('2', ''), ('3', '1')]
        assert rows[1][2] == '1'

    def test_bad_mic_tcg_response_does_not_take_the_pending_call(
            self, cmd_tshark, test_env, capture_file, tmp_path):
        """F2721 answers the Locking_GlobalRange.Get call in F2718; with its MIC
        damaged it is not trusted, so the call stays unanswered."""
        data = bytearray(Path(capture_file('nvme-mi-tcg.pcapng')).read_bytes())
        pos = frame = 0
        while pos < len(data):
            btype, blen = struct.unpack_from('<II', data, pos)
            if btype == 6:
                frame += 1
                if frame == 2721:
                    caplen = struct.unpack_from('<I', data, pos + 20)[0]
                    data[pos + 28 + caplen - 1] ^= 0xFF
            pos += blen
        path = tmp_path / 'tcg-bad-mic.pcapng'
        path.write_bytes(data)
        rows = {r[0]: r[1:] for r in self.links(
            cmd_tshark, test_env, path, ('tcg-storage.response_to', 'tcg-storage.response_in'),
            'frame.number >= 2718 && frame.number <= 2731')}
        assert rows.get('2721', ['', ''])[0] == ''
        assert rows.get('2718', ['', ''])[1] == ''
        # The flipped byte is what made the MIC bad.
        assert [r[0] for r in self.links(
            cmd_tshark, test_env, path, (), 'frame.number == 2721 && nvme-mi.mic_bad')] == ['2721']
        # The pairs on either side are unaffected.
        assert rows['2725'][0] != '' and rows['2731'][0] == 'This SP.Random'
