# Wireshark tests
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
"""CoAP-EAP (RFC 9820) dissector tests.

These tests require a Wireshark build tree with the CoAP-EAP dissector
integrated.  Copy this file to wireshark/test/ and the capture files
to wireshark/test/captures/ before running pytest.
"""

import subprocess


class TestCoapEapDissector:
    """Tests for the CoAP-EAP dissector (RFC 9820)."""

    # -- frame-count tests --------------------------------------------------

    def test_cbor_negotiation_capture(self, cmd_tshark, capture_file, test_env):
        """Cipher suite negotiation + EAP-PSK is decoded correctly."""
        stdout = subprocess.check_output((cmd_tshark,
            "-r", capture_file("coap-eap-cbor-negotiation.pcap"),
            "-Y", "coap_eap",
            "-Tfields", "-e", "frame.number",
        ), encoding="utf-8", env=test_env).strip()
        assert len(stdout.splitlines()) == 7

    def test_failure_capture(self, cmd_tshark, capture_file, test_env):
        """EAP-Failure flow is decoded correctly."""
        stdout = subprocess.check_output((cmd_tshark,
            "-r", capture_file("coap-eap-failure.pcap"),
            "-Y", "coap_eap",
            "-Tfields", "-e", "frame.number",
        ), encoding="utf-8", env=test_env).strip()
        assert len(stdout.splitlines()) == 8

    # -- EAP field visibility -----------------------------------------------

    def test_eap_request_visibility(self, cmd_tshark, capture_file, test_env):
        """EAP-Request/Identity is visible in CoAP-EAP frames."""
        stdout = subprocess.check_output((cmd_tshark,
            "-r", capture_file("coap-eap-cbor-negotiation.pcap"),
            "-Y", "eap.code == 1",
            "-Tfields", "-e", "eap.type",
        ), encoding="utf-8", env=test_env).strip()
        assert "1" in stdout  # Identity type

    def test_eap_response_visibility(self, cmd_tshark, capture_file, test_env):
        """EAP-Response is visible in CoAP-EAP frames."""
        stdout = subprocess.check_output((cmd_tshark,
            "-r", capture_file("coap-eap-cbor-negotiation.pcap"),
            "-Y", "eap.code == 2",
            "-Tfields", "-e", "eap.type",
        ), encoding="utf-8", env=test_env).strip()
        assert stdout != ""

    def test_eap_success_global(self, cmd_tshark, capture_file, test_env):
        """EAP-Success (code=3) is present in RADIUS relay frames."""
        stdout = subprocess.check_output((cmd_tshark,
            "-r", capture_file("coap-eap-cbor-negotiation.pcap"),
            "-Y", "eap.code == 3",
            "-Tfields", "-e", "frame.number",
        ), encoding="utf-8", env=test_env).strip()
        assert stdout != ""

    def test_eap_failure_global(self, cmd_tshark, capture_file, test_env):
        """EAP-Failure (code=4) is decoded in CoAP-EAP frames."""
        stdout = subprocess.check_output((cmd_tshark,
            "-r", capture_file("coap-eap-failure.pcap"),
            "-Y", "coap_eap && eap.code == 4",
            "-Tfields", "-e", "frame.number",
        ), encoding="utf-8", env=test_env).strip()
        assert stdout != ""

    # -- display filters / columns ------------------------------------------

    def test_protocol_column(self, cmd_tshark, capture_file, test_env):
        """Protocol column shows coap_eap for matching frames."""
        stdout = subprocess.check_output((cmd_tshark,
            "-r", capture_file("coap-eap-cbor-negotiation.pcap"),
            "-Y", "coap_eap",
            "-Tfields", "-e", "frame.protocols",
        ), encoding="utf-8", env=test_env).strip()
        for line in stdout.splitlines():
            assert "coap_eap" in line

    def test_eap_field_filter(self, cmd_tshark, capture_file, test_env):
        """Frames with an EAP payload are filterable via coap_eap.eap."""
        stdout = subprocess.check_output((cmd_tshark,
            "-r", capture_file("coap-eap-cbor-negotiation.pcap"),
            "-Y", "coap_eap.eap",
            "-Tfields", "-e", "coap_eap.eap",
        ), encoding="utf-8", env=test_env).strip()
        lines = stdout.splitlines()
        assert len(lines) >= 1
        for line in lines:
            assert line != ""

    # -- false positives ----------------------------------------------------

    def test_no_false_positives(self, cmd_tshark, capture_file, test_env):
        """RADIUS port traffic is not parsed as CoAP-EAP."""
        stdout = subprocess.check_output((cmd_tshark,
            "-r", capture_file("coap-eap-cbor-negotiation.pcap"),
            "-Y", "coap_eap && udp.port == 1812",
            "-Tfields", "-e", "frame.number",
        ), encoding="utf-8", env=test_env).strip()
        assert stdout == ""

    # -- CBOR field value tests ---------------------------------------------

    def test_cipher_suites_negotiation(self, cmd_tshark, capture_file, test_env):
        """Step 1 advertises suites 0 and 1; Step 2 selects suite 0."""
        stdout = subprocess.check_output((cmd_tshark,
            "-r", capture_file("coap-eap-cbor-negotiation.pcap"),
            "-Y", "coap_eap.cipher_suites",
            "-Tfields", "-e", "coap_eap.cipher_suites",
        ), encoding="utf-8", env=test_env).strip()
        assert "AES-CCM-16-64-128, SHA-256 (0)" in stdout
        assert "A128GCM, SHA-256 (1)" in stdout

    def test_session_lifetime_registered(self, cmd_tshark, capture_file, test_env):
        """Session-Lifetime field is registered (value is inside OSCORE)."""
        stdout = subprocess.check_output((cmd_tshark,
            "-G", "fields",
        ), encoding="utf-8", env=test_env).strip()
        assert "coap_eap.lifetime" in stdout

    def test_cbor_info_field_present(self, cmd_tshark, capture_file, test_env):
        """CoAP-EAP_Info CBOR map field is populated."""
        stdout = subprocess.check_output((cmd_tshark,
            "-r", capture_file("coap-eap-cbor-negotiation.pcap"),
            "-Y", "coap_eap.cbor_info",
            "-Tfields", "-e", "coap_eap.cbor_info",
        ), encoding="utf-8", env=test_env).strip()
        assert stdout != ""

    # -- field registration (verify tshark knows the field names) -----------

    def test_field_rid_c_registered(self, cmd_tshark, capture_file, test_env):
        """RID-C field is recognized by tshark."""
        stdout = subprocess.check_output((cmd_tshark,
            "-G", "fields",
        ), encoding="utf-8", env=test_env).strip()
        assert "coap_eap.rid_c" in stdout

    def test_field_rid_i_registered(self, cmd_tshark, capture_file, test_env):
        """RID-I field is recognized by tshark."""
        stdout = subprocess.check_output((cmd_tshark,
            "-G", "fields",
        ), encoding="utf-8", env=test_env).strip()
        assert "coap_eap.rid_i" in stdout

    def test_field_cbormap_key_registered(self, cmd_tshark, capture_file, test_env):
        """CBOR Map Key field is recognized by tshark."""
        stdout = subprocess.check_output((cmd_tshark,
            "-G", "fields",
        ), encoding="utf-8", env=test_env).strip()
        assert "coap_eap.cbormap_key" in stdout


class TestCoapEapExpertInfo:
    """Tests for CoAP-EAP expert info fields (registered, even if no frame
       triggers them in the test captures)."""

    def test_expert_payload_too_short_defined(self, cmd_tshark, capture_file, test_env):
        """Expert info coap_eap.payload_too_short is registered."""
        stdout = subprocess.check_output((cmd_tshark,
            "-G", "fields",
        ), encoding="utf-8", env=test_env).strip()
        assert "coap_eap.payload_too_short" in stdout

    def test_expert_eap_length_invalid_defined(self, cmd_tshark, capture_file, test_env):
        """Expert info coap_eap.eap_length_invalid is registered."""
        stdout = subprocess.check_output((cmd_tshark,
            "-G", "fields",
        ), encoding="utf-8", env=test_env).strip()
        assert "coap_eap.eap_length_invalid" in stdout

    def test_expert_eap_length_exceeds_defined(self, cmd_tshark, capture_file, test_env):
        """Expert info coap_eap.eap_length_exceeds is registered."""
        stdout = subprocess.check_output((cmd_tshark,
            "-G", "fields",
        ), encoding="utf-8", env=test_env).strip()
        assert "coap_eap.eap_length_exceeds" in stdout

    def test_expert_cbor_malformed_defined(self, cmd_tshark, capture_file, test_env):
        """Expert info coap_eap.cbor_malformed is registered."""
        stdout = subprocess.check_output((cmd_tshark,
            "-G", "fields",
        ), encoding="utf-8", env=test_env).strip()
        assert "coap_eap.cbor_malformed" in stdout

    def test_expert_cbor_not_map_defined(self, cmd_tshark, capture_file, test_env):
        """Expert info coap_eap.cbor_not_map is registered."""
        stdout = subprocess.check_output((cmd_tshark,
            "-G", "fields",
        ), encoding="utf-8", env=test_env).strip()
        assert "coap_eap.cbor_not_map" in stdout
