#!/bin/bash
#
# Test decryption capabilities of the Wireshark tools
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 2005 Ulf Lamping
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

# To do:
#   IEEE 802.15.4
#   ISAKMP / IKEv2
#   PKCS#12
#   SNMP
#   DCERPC NETLOGON
#   KINK
#   LDAP
#   NTLMSSP
#   SPNEGO

# common exit status values
EXIT_OK=0
EXIT_COMMAND_LINE=1
EXIT_ERROR=2

UAT_FILES="
	80211_keys
	dtlsdecrypttablefile
	esp_sa
	ssl_keys
	c1222_decryption_table
	ikev1_decryption_table
	ikev2_decryption_table
"

TEST_KEYS_DIR="$TESTS_DIR/keys/"
if [ "$WS_SYSTEM" == "Windows" ] ; then
	TEST_KEYS_DIR="`cygpath -w $TEST_KEYS_DIR`"
fi

#TS_ARGS="-Tfields -e frame.number -e frame.time_epoch -e frame.time_delta"
TS_DC_ARGS=""

DIFF_OUT=./diff-output.txt

# WPA PSK
# https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=view&target=wpa-Induction.pcap
decryption_step_80211_wpa_psk() {
	$TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS \
		-o "wlan.enable_decryption: TRUE" \
		-Tfields -e http.request.uri \
		-r "$CAPTURE_DIR/wpa-Induction.pcap.gz" \
		-Y http \
		| grep favicon.ico > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to decrypt IEEE 802.11 WPA PSK"
		return
	fi
	test_step_ok
}

# WPA EAP (EAPOL Rekey)
# Included in git sources test/captures/wpa-eap-tls.pcap.gz
decryption_step_80211_wpa_eap() {
	$TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS \
		-o "wlan.enable_decryption: TRUE" \
		-r "$CAPTURE_DIR/wpa-eap-tls.pcap.gz" \
		-Y "wlan.analysis.tk==7d9987daf5876249b6c773bf454a0da7" \
		| grep "Group Message" > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to decrypt IEEE 802.11 WPA EAP"
		return
	fi
	test_step_ok
}
# WPA decode with message1+2 only and secure bit set on message 2
# Included in git sources test/captures/wpa-test-decode.pcap.gz
decryption_step_80211_wpa_eapol_incomplete_rekeys() {
	$TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS \
		-o "wlan.enable_decryption: TRUE" \
		-r "$CAPTURE_DIR/wpa-test-decode.pcap.gz" \
		-Y "icmp.resp_to == 4263" \
		| grep "Echo"  > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Not able to follow rekey with missing eapol frames"
		return
	fi
	test_step_ok
}

# WPA decode management frames with MFP enabled (802.11w)
# Included in git sources test/captures/wpa-test-decode-mgmt.pcap.gz
decryption_step_80211_wpa_psk_mfp() {
	local out frames
	out=$($TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS \
		-o "wlan.enable_decryption: TRUE" \
		-r "$CAPTURE_DIR/wpa-test-decode-mgmt.pcap.gz" \
		-Y "wlan.fixed.reason_code == 2 || wlan.fixed.category_code == 3" \
		2>&1)
	RETURNVALUE=$?
	frames=$(echo "$out" | wc -l)
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Error during test execution: $out"
		return
	elif [ $frames -ne 3 ]; then
		test_step_failed "Not able to decode All Management frames ($frames/3)"
		return
	fi
	test_step_ok
}

# WPA decode traffic in a TDLS (Tunneled Direct-Link Setup) session (802.11z)
# Included in git sources test/captures/wpa-test-decode-tdls.pcap.gz
decryption_step_80211_wpa_tdls() {
	local out frames
	out=$($TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS \
		-o "wlan.enable_decryption: TRUE" \
		-r "$CAPTURE_DIR/wpa-test-decode-tdls.pcap.gz" \
		-Y "icmp" \
		2>&1)
	RETURNVALUE=$?
	frames=$(echo "$out" | wc -l)
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Error during test execution: $out"
		return
	elif [ $frames -ne 2 ]; then
		test_step_failed "Not able to decode all TDLS traffic ($frames/2)"
		return
	fi
	test_step_ok
}

# DTLS
# https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=view&target=snakeoil.tgz
decryption_step_dtls() {
	$TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS \
		-Tfields -e data.data \
		-r "$CAPTURE_DIR/snakeoil-dtls.pcap" -Y data \
		| grep "69:74:20:77:6f:72:6b:20:21:0a" > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to decrypt DTLS"
		return
	fi
	test_step_ok
}

# DTLS 1.2 with PSK, AES-128-CCM-8
decryption_step_dtls_psk_aes128ccm8() {
	output=$($TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS \
		-odtls.psk:ca19e028a8a372ad2d325f950fcaceed \
		-r "$CAPTURE_DIR/dtls12-aes128ccm8.pcap" -x)
	one='DTLS1.2 test usi*ng GnuTLS 3.5.8.'
	two='Works for me!.'
	if [[ "$output" != *${one}*${one}*${two}*${two}* ]]; then
		test_step_failed "Failed to decrypt DTLS 1.2 (PSK AES-128-CCM-8)"
		return
	fi
	test_step_ok
}

# IPsec ESP
# https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=12671
decryption_step_ipsec_esp() {
	$TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS \
		-o "esp.enable_encryption_decode: TRUE" \
		-Tfields -e data.data \
		-r "$CAPTURE_DIR/esp-bug-12671.pcapng.gz" -Y data \
		| grep "08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17" > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to decrypt DTLS"
		return
	fi
	test_step_ok
}

# SSL, using the server's private key
# https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=view&target=snakeoil2_070531.tgz
decryption_step_ssl() {
	$TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS -Tfields -e http.request.uri \
		-r "$CAPTURE_DIR/rsasnakeoil2.pcap" -Y http \
		| grep favicon.ico > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to decrypt SSL using the server's private key"
		return
	fi
	test_step_ok
}

# SSL, using the server's private key with p < q
# (test whether libgcrypt is correctly called)
decryption_step_ssl_rsa_pq() {
	TEST_KEYS_FILE="$TESTS_DIR/keys/rsa-p-lt-q.key"
	if [ "$WS_SYSTEM" == "Windows" ] ; then
		TEST_KEYS_FILE="`cygpath -w $TEST_KEYS_FILE`"
	fi
	$TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS -Tfields -e http.request.uri \
		-o ssl.keys_list:"0.0.0.0,443,http,$TEST_KEYS_FILE" \
		-r "$CAPTURE_DIR/rsa-p-lt-q.pcap" -Y http \
		| grep / > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to decrypt SSL using the server's RSA private key"
		return
	fi
	test_step_ok
}

# SSL, using the server's private key with password
decryption_step_ssl_with_password() {
	$TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS -Tfields -e http.request.uri \
		-r "$CAPTURE_DIR/dmgr.pcapng" -Y http \
		| grep unsecureLogon.jsp > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to decrypt SSL using the server's private key with password"
		return
	fi
	test_step_ok
}

# SSL, using the master secret
decryption_step_ssl_master_secret() {
	TEST_KEYS_FILE="$TESTS_DIR/keys/dhe1_keylog.dat"
	if [ "$WS_SYSTEM" == "Windows" ] ; then
		TEST_KEYS_FILE="`cygpath -w $TEST_KEYS_FILE`"
	fi
	$TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS -Tfields -e http.request.uri \
		-o "ssl.keylog_file: $TEST_KEYS_FILE" \
		-o "ssl.desegment_ssl_application_data: FALSE" \
		-o "http.ssl.port: 443" \
		-r "$CAPTURE_DIR/dhe1.pcapng.gz" -Y http \
		| grep test > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to decrypt SSL using the master secret"
		return
	fi
	test_step_ok
}

# TLS 1.2 with renegotiation
decryption_step_ssl_renegotiation() {
	TEST_KEYS_FILE="$TESTS_DIR/keys/rsasnakeoil2.key"
	if [ "$WS_SYSTEM" == "Windows" ] ; then
		TEST_KEYS_FILE="`cygpath -w $TEST_KEYS_FILE`"
	fi
	output=$($TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS -Tfields -e http.content_length \
		-o ssl.keys_list:"0.0.0.0,4433,http,$TEST_KEYS_FILE" \
		-r "$CAPTURE_DIR/tls-renegotiation.pcap" -Y http)
	if [[ "$output" != 0*2151* ]]; then
		test_step_failed "Failed to decrypt SSL with renegotiation"
		return
	fi
	test_step_ok
}

# TLS 1.2 with PSK, AES-128-CCM
decryption_step_tls_psk_aes128ccm() {
	$TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS -q \
		-ossl.psk:ca19e028a8a372ad2d325f950fcaceed \
		-r "$CAPTURE_DIR/tls12-aes128ccm.pcap" -z follow,ssl,ascii,0 \
		| grep -q http://www.gnu.org/software/gnutls
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to decrypt TLS 1.2 (PSK AES-128-CCM)"
		return
	fi
	test_step_ok
}

# TLS 1.2 with PSK, AES-256-GCM
decryption_step_tls_psk_aes256gcm() {
	$TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS -q \
		-ossl.psk:ca19e028a8a372ad2d325f950fcaceed \
		-r "$CAPTURE_DIR/tls12-aes256gcm.pcap" -z follow,ssl,ascii,0 \
		| grep -q http://www.gnu.org/software/gnutls
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to decrypt TLS 1.2 (PSK AES-256-GCM)"
		return
	fi
	test_step_ok
}

# TLS 1.2 with ChaCha20-Poly1305
decryption_step_tls12_chacha20poly1305() {
	if ! $HAVE_LIBGCRYPT17; then
		test_step_skipped
		return
	fi
	TEST_KEYS_FILE="$TESTS_DIR/keys/tls12-chacha20poly1305.keys"
	if [ "$WS_SYSTEM" == "Windows" ] ; then
		TEST_KEYS_FILE="`cygpath -w $TEST_KEYS_FILE`"
	fi
	ciphers='
		ECDHE-ECDSA-CHACHA20-POLY1305
		ECDHE-RSA-CHACHA20-POLY1305
		DHE-RSA-CHACHA20-POLY1305
		RSA-PSK-CHACHA20-POLY1305
		DHE-PSK-CHACHA20-POLY1305
		ECDHE-PSK-CHACHA20-POLY1305
		PSK-CHACHA20-POLY1305
	'
	local stream=0
	for cipher in $ciphers; do
		$TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS -q \
			-r "$CAPTURE_DIR/tls12-chacha20poly1305.pcap" \
			-o "ssl.keylog_file: $TEST_KEYS_FILE" \
			-z follow,ssl,ascii,$stream \
			| grep -q "$cipher"
		RETURNVALUE=$?
		if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
			test_step_failed "Failed to decrypt TLS 1.2 ($cipher)"
			return
		fi
		((stream++))
	done
	test_step_ok
}

# TLS 1.3 with ChaCha20-Poly1305
decryption_step_tls13_chacha20poly1305() {
	if ! $HAVE_LIBGCRYPT17; then
		test_step_skipped
		return
	fi
	TEST_KEYS_FILE="$TESTS_DIR/keys/tls13-20-chacha20poly1305.keys"
	if [ "$WS_SYSTEM" == "Windows" ] ; then
		TEST_KEYS_FILE="`cygpath -w $TEST_KEYS_FILE`"
	fi
	$TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS -q \
		-r "$CAPTURE_DIR/tls13-20-chacha20poly1305.pcap" \
		-o "ssl.keylog_file: $TEST_KEYS_FILE" \
		-z follow,ssl,ascii,0 \
		| grep -q TLS13-CHACHA20-POLY1305-SHA256
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to decrypt TLS 1.3 (ChaCha20-Poly1305)"
		return
	fi
	test_step_ok
}

# ZigBee
# https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=7022
decryption_step_zigbee() {
	$TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS \
		-r "$CAPTURE_DIR/sample_control4_2012-03-24.pcap" \
		-Tfields -e data.data \
		-Y zbee_aps \
		| grep "30:67:63:63:38:65:20:63:34:2e:64:6d:2e:74:76:20" > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to decrypt ZigBee"
		return
	fi
	test_step_ok
}

# ANSI C12.22
# https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=9196
decryption_step_c1222() {
	$TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS \
		-o "c1222.decrypt: TRUE" \
		-o "c1222.baseoid:2.16.124.113620.1.22.0" \
		-r "$CAPTURE_DIR/c1222_std_example8.pcap" \
		-Tfields -e c1222.data \
		| grep "00:10:4d:41:4e:55:46:41:43:54:55:52:45:52:20:53:4e:20:92" > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to decrypt C12.22 $RETURNVALUE"
		return
	fi
	test_step_ok
}

# DVB-CI
# simplified version of the sample capture in
# https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=6700
decryption_step_dvb_ci() {
	$TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS \
		 -o "dvb-ci.sek: 00000000000000000000000000000000" \
		 -o "dvb-ci.siv: 00000000000000000000000000000000" \
		-Tfields -e dvb-ci.cc.sac.padding \
		-r "$CAPTURE_DIR/dvb-ci_UV1_0000.pcap" \
		| grep "80:00:00:00:00:00:00:00:00:00:00:00" > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to decrypt DVB_CI"
		return
	fi
	test_step_ok
}

# IKEv1 (ISAKMP) with certificates
# https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=7951
decryption_step_ikev1_certs() {
	$TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS \
		-Tfields -e x509sat.printableString \
		-r "$CAPTURE_DIR/ikev1-certs.pcap" \
		| grep "OpenSwan" > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to decrypt IKEv1"
		return
	fi
	test_step_ok
}

# IKEv1 (ISAKMP) simultaneous exchanges
# https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=12610
decryption_step_ikev1_simultaneous() {
	$TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS \
		-Tfields -e isakmp.hash \
		-r "$CAPTURE_DIR/ikev1-bug-12610.pcapng.gz" \
		| grep "b5:25:21:f7:74:96:74:02:c9:f6:ce:e9:5f:d1:7e:5b" > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to decrypt simultaneous IKEv1 exchanges"
		return
	fi
	test_step_ok
}

# IKEv1 (ISAKMP) unencrypted phase 1
# https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=12620
decryption_step_ikev1_unencrypted() {
	$TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS \
		-Tfields -e isakmp.hash \
		-r "$CAPTURE_DIR/ikev1-bug-12620.pcapng.gz" \
		| grep "40:04:3b:64:0f:43:73:25:0d:5a:c3:a1:fb:63:15:3c" > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to decrypt the first packet of a post-phase1 IKEv1 exchange"
		return
	fi
	test_step_ok
}

# IKEv2 decryption test (3DES-CBC/SHA1_160)
decryption_step_ikev2_3des_sha160() {
	$TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS \
		-Tfields -e isakmp.auth.data \
		-r "$CAPTURE_DIR/ikev2-decrypt-3des-sha1_160.pcap" \
		| grep "02:f7:a0:d5:f1:fd:c8:ea:81:03:98:18:c6:5b:b9:bd:09:af:9b:89:17:31:9b:88:7f:f9:ba:30:46:c3:44:c7" > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to decrypt encrypted with 3_DES_CBC/SHA1_160 packet of IKEv2 exchange"
		return
	fi
	test_step_ok
}

# IKEv2 decryption test (AES-128-CCM-12) - with CBC-MAC verification
decryption_step_ikev2_aes128_ccm12() {
	$TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS \
		-Tfields -e isakmp.auth.data \
		-r "$CAPTURE_DIR/ikev2-decrypt-aes128ccm12.pcap" \
		| grep "c2:10:43:94:29:9e:1f:fe:79:08:ea:72:0a:d5:d1:37:17:a0:d4:54:e4:fa:0a:21:28:ea:68:94:11:f4:79:c4" > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to decrypt encrypted with AES_128_CCM_12 packet of IKEv2 exchange"
		return
	fi
	test_step_ok
}

# IKEv2 decryption test (AES-128-CCM-12 using CTR mode, without checksum)
decryption_step_ikev2_aes128_ccm12_2() {
	$TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS \
		-Tfields -e isakmp.auth.data \
		-r "$CAPTURE_DIR/ikev2-decrypt-aes128ccm12-2.pcap" \
		| grep "aa:a2:81:c8:7b:4a:19:04:6c:57:27:1d:55:74:88:ca:41:3b:57:22:8c:b9:51:f5:fa:96:40:99:2a:02:85:b9" > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to decrypt (using CTR mode) encrypted with AES_128_CCM_12  packet of IKEv2 exchange"
		return
	fi
	test_step_ok
}

# IKEv2 decryption test (AES-192-CTR/SHA2-512)
decryption_step_ikev2_aes192ctr_sha512() {
	$TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS \
		-Tfields -e isakmp.auth.data \
		-r "$CAPTURE_DIR/ikev2-decrypt-aes192ctr.pcap" \
		| grep "3e:c2:3d:cf:93:48:48:56:38:40:7c:75:45:47:ae:b3:08:52:90:08:2c:49:f5:83:fd:ba:e5:92:63:a2:0b:4a" > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to decrypt encrypted with AES-192-CTR/SHA2_512 packet of IKEv2 exchange"
		return
	fi
	test_step_ok
}

# IKEv2 decryption test (AES-256-CBC/SHA2-256)
decryption_step_ikev2_aes256cbc_sha256() {
	$TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS \
		-Tfields -e isakmp.auth.data \
		-r "$CAPTURE_DIR/ikev2-decrypt-aes256cbc.pcapng" \
		| grep "e1:a8:d5:50:06:42:01:a7:ec:02:4a:85:75:8d:06:73:c6:1c:5c:51:0a:c1:3b:cd:22:5d:63:27:f5:0d:a3:d3" > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to decrypt encrypted with AES-256-CBC/SHA2-256 packet of IKEv2 exchange"
		return
	fi
	test_step_ok
}

# IKEv2 decryption test (AES-256-CCM-16)
decryption_step_ikev2_aes256ccm16() {
	$TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS \
		-Tfields -e isakmp.auth.data \
		-r "$CAPTURE_DIR/ikev2-decrypt-aes256ccm16.pcapng" \
		| grep "fa:2e:74:bd:c0:1e:30:fb:0b:3d:dc:97:23:c9:44:90:95:96:9d:a5:1f:69:e5:60:20:9d:2c:2b:79:40:21:0a" > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to decrypt encrypted with AES-256-CCM-16 packet of IKEv2 exchange"
		return
	fi
	test_step_ok
}

# IKEv2 decryption test (AES-256-GCM-16)
decryption_step_ikev2_aes256gcm16() {
	$TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS \
		-Tfields -e isakmp.auth.data \
		-r "$CAPTURE_DIR/ikev2-decrypt-aes256gcm16.pcap" \
		| grep "9a:b7:1f:14:ab:55:3c:ad:87:3a:1a:a7:0b:99:df:15:5d:ee:77:cd:cf:36:94:b3:b7:52:7a:cb:b9:71:2d:ed" > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to decrypt encrypted with AES-256-GCM-16 packet of IKEv2 exchange"
		return
	fi
	test_step_ok
}

# IKEv2 decryption test (AES-256-GCM-8)
decryption_step_ikev2_aes256gcm8() {
	$TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS \
		-Tfields -e isakmp.auth.data \
		-r "$CAPTURE_DIR/ikev2-decrypt-aes256gcm8.pcap" \
		| grep "4a:66:d8:22:d0:af:bc:22:ad:9a:92:a2:cf:42:87:c9:20:ad:8a:c3:b0:69:a4:a7:e7:5f:e0:a5:d4:99:f9:14" > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to decrypt encrypted with AES-256-GCM-8 packet of IKEv2 exchange"
		return
	fi
	test_step_ok
}

# HTTP2 (HPACK)
decryption_step_http2() {
	if [ $HAVE_NGHTTP2 -ne 0 ]; then
		test_step_skipped
		return
	fi
	env $TS_DC_ENV $TSHARK $TS_DC_ARGS \
		-Tfields -e http2.header.value \
		-d tcp.port==3000,http2 \
		-r "$CAPTURE_DIR/packet-h2-14_headers.pcapng" \
	> ./testout.txt
	grep "nghttp2" ./testout.txt > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
	env $TS_DC_ENV $TSHARK $TS_DC_ARGS \
		-V \
		-d tcp.port==3000,http2 \
		-r "$CAPTURE_DIR/packet-h2-14_headers.pcapng" \
		> ./testout2.txt
	echo
	echo "Test output:"
	cat ./testout.txt
	echo "Verbose output:"
	cat ./testout2.txt
		test_step_failed "Failed to decode HTTP2 HPACK"
		return
	fi
	test_step_ok
}

# Kerberos
# Files are from krb-816.zip on the SampleCaptures page.
KEYTAB_FILE="$TESTS_DIR/keys/krb-816.keytab"
if [ "$WS_SYSTEM" == "Windows" ] ; then
	KEYTAB_FILE="`cygpath -w $KEYTAB_FILE`"
fi
decryption_step_kerberos() {
	if [ $HAVE_KERBEROS -ne 0 ]; then
		test_step_skipped
		return
	fi
	# keyvalue: ccda7d48219f73c3b28311c4ba7242b3
	$TESTS_DIR/run_and_catch_crashes env $TS_DC_ENV $TSHARK $TS_DC_ARGS \
		-Tfields -e kerberos.keyvalue \
		-o "kerberos.decrypt: TRUE" \
		-o "kerberos.file: $KEYTAB_FILE" \
		-r "$CAPTURE_DIR/krb-816.pcap.gz" \
		| grep "cc:da:7d:48:21:9f:73:c3:b2:83:11:c4:ba:72:42:b3" > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to decrypt encrypted with AES-256-GCM-8 packet of IKEv2 exchange"
		return
	fi
	test_step_ok
}

tshark_decryption_suite() {
	test_step_add "IEEE 802.11 WPA PSK Decryption" decryption_step_80211_wpa_psk
	test_step_add "IEEE 802.11 WPA PSK Decryption2 (EAPOL frames missing with a Win 10 client)" decryption_step_80211_wpa_eapol_incomplete_rekeys
	test_step_add "IEEE 802.11 WPA PSK Decryption of Management frames (802.11w)" decryption_step_80211_wpa_psk_mfp
	test_step_add "IEEE 802.11 WPA EAP Decryption" decryption_step_80211_wpa_eap
	test_step_add "IEEE 802.11 WPA TDLS Decryption" decryption_step_80211_wpa_tdls
	test_step_add "DTLS Decryption" decryption_step_dtls
	test_step_add "DTLS 1.2 Decryption (PSK AES-128-CCM-8)" decryption_step_dtls_psk_aes128ccm8
	test_step_add "IPsec ESP Decryption" decryption_step_ipsec_esp
	test_step_add "SSL Decryption (private key)" decryption_step_ssl
	test_step_add "SSL Decryption (RSA private key with p smaller than q)" decryption_step_ssl_rsa_pq
	test_step_add "SSL Decryption (private key with password)" decryption_step_ssl_with_password
	test_step_add "SSL Decryption (master secret)" decryption_step_ssl_master_secret
	test_step_add "SSL Decryption (renegotiation)" decryption_step_ssl_renegotiation
	test_step_add "TLS 1.2 Decryption (PSK AES-128-CCM)" decryption_step_tls_psk_aes128ccm
	test_step_add "TLS 1.2 Decryption (PSK AES-256-GCM)" decryption_step_tls_psk_aes256gcm
	test_step_add "TLS 1.2 Decryption (ChaCha20-Poly1305)" decryption_step_tls12_chacha20poly1305
	test_step_add "TLS 1.3 Decryption (ChaCha20-Poly1305)" decryption_step_tls13_chacha20poly1305
	test_step_add "ZigBee Decryption" decryption_step_zigbee
	test_step_add "ANSI C12.22 Decryption" decryption_step_c1222
	test_step_add "DVB-CI Decryption" decryption_step_dvb_ci

	test_step_add "IKEv1 Decryption (certificates)" decryption_step_ikev1_certs
	test_step_add "IKEv1 Decryption (simultaneous exchanges)" decryption_step_ikev1_simultaneous
	test_step_add "IKEv1 Decryption (unencrypted phase 1)" decryption_step_ikev1_unencrypted

	test_step_add "IKEv2 Decryption (3DES-CBC/SHA1_160)" decryption_step_ikev2_3des_sha160
	test_step_add "IKEv2 Decryption (AES-128-CCM-12)" decryption_step_ikev2_aes128_ccm12
	test_step_add "IKEv2 Decryption (AES-128-CCM-12 using CTR mode)" decryption_step_ikev2_aes128_ccm12_2
	test_step_add "IKEv2 Decryption (AES-192-CTR/SHA2-512)" decryption_step_ikev2_aes192ctr_sha512
	test_step_add "IKEv2 Decryption (AES-256-CBC/SHA2-256)" decryption_step_ikev2_aes256cbc_sha256
	test_step_add "IKEv2 Decryption (AES-256-CCM-16)" decryption_step_ikev2_aes256ccm16
	test_step_add "IKEv2 Decryption (AES-256-GCM-16)" decryption_step_ikev2_aes256gcm16
	test_step_add "IKEv2 Decryption (AES-256-GCM-8)" decryption_step_ikev2_aes256gcm8

	test_step_add "HTTP2 (HPACK)" decryption_step_http2

	test_step_add "Kerberos" decryption_step_kerberos
}

decryption_cleanup_step() {
	rm -rf "$TEST_HOME"
}

decryption_prep_step() {
	decryption_cleanup_step

	TS_DC_ENV="${HOME_ENV}=${HOME_PATH}"

	for UAT in $UAT_FILES ; do
		sed -e "s|TEST_KEYS_DIR|${TEST_KEYS_DIR//\\/\\\\x5c}|" \
			< "$TESTS_DIR/config/$UAT.tmpl" \
			> "$CONF_PATH/$UAT"
	done
}

decryption_suite() {
	test_step_set_pre decryption_prep_step
	test_step_set_post decryption_cleanup_step
	test_suite_add "TShark decryption" tshark_decryption_suite
}

#
# Editor modelines  -  https://www.wireshark.org/tools/modelines.html
#
# Local variables:
# sh-basic-offset: 8
# tab-width: 8
# indent-tabs-mode: t
# End:
#
# vi: set shiftwidth=8 tabstop=8 noexpandtab:
# :indentSize=8:tabSize=8:noTabs=false:
#

